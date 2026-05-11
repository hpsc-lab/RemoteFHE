# Serialization of OpenFHE Objects in Julia

## Problem Statement

The project aims to serialize FHE ciphertexts (and their associated context/keys) so they
can be transmitted between a client and a server.  Two obvious Julia approaches were
tried and both fail for fundamental reasons.

---

## Approach 1: Julia's built-in `Serialization` module — does NOT work

### Why it fails

Julia's documentation states explicitly:

> "Additionally, `Ptr` values are serialized as all-zero bit patterns (NULL) since they
> are not portable across different environments due to memory addressing differences."

Every CxxWrap-wrapped C++ object (`SharedPtrAllocated{T}`) is a mutable Julia struct
with a single field:

```julia
mutable struct SharedPtrAllocated{T} <: SmartPointer{T}
    cpp_object::Ptr{T}   # raw pointer to a heap-allocated std::shared_ptr<T>
end
```

`sizeof(SharedPtrAllocated{T}) == 8` (one pointer, 64-bit).

Because `cpp_object` is a `Ptr`, the serializer zeroes it out.  The deserialised object
has a null C++ pointer, so any subsequent call through it (`Decrypt`, etc.) triggers
CxxWrap's "C++ object was deleted" guard.

### Impact on `run_client` / `run_server`

The existing socket-based server/client code uses `Serialization.serialize` /
`Serialization.deserialize`.  This **does not work** — the server receives objects
with null C++ pointers and cannot perform any FHE operations on them.  The code
compiles and runs structurally, but the FHE logic is broken by design.

---

## Approach 2: OpenFHE's native `Serial::Serialize` — not (yet) exposed to Julia

OpenFHE provides a proper binary serialization layer built on the `cereal` library:

```cpp
// From openfhe/core/utils/serial.h
namespace lbcrypto::Serial {
    template<typename T>
    void Serialize(const T& obj, std::ostream& stream, const SerType::SERBINARY&);

    template<typename T>
    void Deserialize(T& obj, std::istream& stream, const SerType::SERBINARY&);

    template<typename T>
    bool SerializeToFile(const std::string& filename, const T& obj, const SerType::SERBINARY&);

    template<typename T>
    bool DeserializeFromFile(const std::string& filename, T& obj, const SerType::SERBINARY&);
}
```

These functions correctly serialize/deserialize the full polynomial data, not raw pointers.
They are used in the official [openfhe-serial-examples](https://github.com/openfheorg/openfhe-serial-examples).

### Why they cannot be called from Julia directly

All four functions are **C++ templates defined in headers only**.  Template functions
are instantiated at each C++ call site and are therefore **not exported from the
compiled shared library** (`libOPENFHEcore.so`, `libOPENFHEpke.so`, or
`libopenfhe_julia.so`).  There is no mangled symbol to target with `ccall`.

Running `nm -D libOPENFHEpke.so | c++filt | grep Serialize` returns no results beyond
`SerializedVersion()` and `SerializedObjectName()` (version/name metadata only).

### What IS exposed in the Julia OpenFHE bindings

The `openfhe_julia_jll` wrapper (`OpenFHE.jl`) exposes only:

| Symbol | Purpose |
|--------|---------|
| `CiphertextImpl__SerializedVersion()` | Returns an integer version tag |
| `CryptoObject__SerializedVersion()` | Returns an integer version tag |
| `PublicKeyImpl__SerializedVersion()` | Returns an integer version tag |
| `PrivateKeyImpl__SerializedVersion()` | Returns an integer version tag |
| `SerializedObjectName()` | Returns a type-name string |
| `GetFullContextByDeserializedContext(cc)` | Looks up the full context from the global registry given a partial/stub context |
| `Serializable` (base class) | Base type only — no `Serialize`/`Deserialize` methods |

None of these provide the ability to actually write or read FHE objects to/from a stream.

---

## Required Fix: A thin C++ wrapper

The OpenFHE headers **are** available in the JLL artifact:

```
~/.julia/artifacts/fffbb7803d9b0fc3514331ac84b0e6e913b80852/include/openfhe/
  core/utils/serial.h           ← Serial::Serialize / SerializeToFile
  pke/ciphertext-ser.h          ← cereal registration for CiphertextImpl
  pke/cryptocontext-ser.h       ← cereal registration for CryptoContextImpl
  pke/key/key-ser.h             ← cereal registration for PublicKeyImpl / PrivateKeyImpl
  pke/scheme/ckksrns/ckksrns-ser.h  ← CKKS-specific cereal registrations
```

A small C++ file must be written that:

1. Includes those headers (which instantiate the cereal templates).
2. Wraps the templated serialize/deserialize calls in `extern "C"` functions so
   Julia can reach them via `ccall`.
3. Accepts/returns raw `void*` pointers (which are the `cpp_object` values from
   `SharedPtrAllocated<T>`) and handles the `shared_ptr` indirection internally.

### Object ownership model for returned pointers

`SharedPtrAllocated<T>` stores in `cpp_object` a raw pointer to a
**heap-allocated** `std::shared_ptr<T>`.  The C++ wrapper therefore must:

- On **serialize**: cast `void* cpp_object` → `std::shared_ptr<T>*`, dereference once
  to get the `shared_ptr<T>`, and pass it to `Serial::Serialize`.
- On **deserialize**: `new std::shared_ptr<T>()`, populate it with
  `Serial::Deserialize`, and return the raw pointer.  Julia then stores this in a new
  `SharedPtrAllocated<T>` object and registers a finalizer that calls `delete` on it.

### Sketch of the Julia side

After deserialization, the raw pointer from C++ can be wrapped with:

```julia
raw_ptr = ccall((:openfhe_deserialize_ciphertext, libserial), Ptr{Cvoid}, ...)
ct_wrapped = SharedPtrAllocated{CiphertextImpl{DCRTPoly}}(
    reinterpret(Ptr{CiphertextImpl{DCRTPoly}}, raw_ptr))
finalizer(ct_wrapped) do obj
    ccall((:openfhe_free_ciphertext_sptr, libserial), Nothing, (Ptr{Cvoid},), obj.cpp_object)
end
```

This gives a properly lifetime-managed Julia wrapper around a freshly deserialized
C++ ciphertext.

### Context reconstruction after deserialization

When deserializing a **ciphertext** on the server side, the ciphertext carries an
embedded partial context stub (scheme parameters only).
`OpenFHE.GetFullContextByDeserializedContext(stub_cc)` queries OpenFHE's global
context registry and returns the matching full `CryptoContext`.

The server workflow is therefore:

1. Deserialize the full `CryptoContext` first (registers it in the global registry). If the same context is to be reused across multiple server requests, we can store the serialized context in files on the server and load the correct context whenever necessary
2. Deserialize the ciphertext (contains a partial context stub).
3. Call `GetFullContextByDeserializedContext(stub)` → full context.
4. Construct a `SecureArray` with the full context and the deserialized ciphertext(s).

---

## Files to create

| File | Purpose |
|------|---------|
| `deps/openfhe_serial.cpp` | C++ wrapper with `extern "C"` serialize/deserialize for `CryptoContext`, `Ciphertext`, `PublicKey` |
| `deps/build.jl` | Compiles `openfhe_serial.cpp` against the JLL artifact headers/libs |
| `src/serial.jl` | Julia-side wrappers: `serialize_context`, `deserialize_context`, `serialize_ciphertext`, `deserialize_ciphertext` |

The `send_object` / `receive_object` functions in `RemoteFHE.jl` should then be
replaced with these type-aware wrappers that use the C++ layer instead of
`Serialization.serialize`.
