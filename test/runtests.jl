using Test
using OpenFHE
using SecureArithmetic
using RemoteFHE

@testset "Ciphertext serialization round-trip" begin
    values = [1.0, 2.0, 3.0, 4.0]
    context = create_context(length(values))
    public_key, private_key = create_keypair(context)
    ciphertext = encrypt_vector(values, public_key, context)

    # Serialize context, private key, and ciphertext using OpenFHE's native serialization.
    # Each object is serialized independently to a binary string.
    s_cc = String(OpenFHE.SerializeToString(context.backend.crypto_context))
    s_pk = String(OpenFHE.SerializeToString(public_key.public_key))
    s_ct = String(OpenFHE.SerializeToString(ciphertext.data[1]))

    println("Serialized sizes (bytes): cc=", length(s_cc),
            " pk=", length(s_pk), " ct=", length(s_ct))

    @test length(s_cc) > 0
    @test length(s_pk) > 0
    @test length(s_ct) > 0

    # Deserialize each object from its binary string.
    new_cc_raw = OpenFHE.DeserializeCryptoContextFromString(s_cc)
    new_pk_raw = OpenFHE.DeserializePublicKeyFromString(s_pk)
    new_ct_raw = OpenFHE.DeserializeCiphertextFromString(s_ct)

    println("Deserialized ciphertext type: ", typeof(new_ct_raw))

    # Rewrap the raw OpenFHE objects into SecureArithmetic types.
    new_ctx = SecureContext(OpenFHEBackend(new_cc_raw))
    new_pk  = SecureArithmetic.PublicKey(new_ctx, new_pk_raw)
    new_ct  = SecureArithmetic.SecureArray([new_ct_raw], ciphertext.shape,
                                           ciphertext.capacity, new_ctx)

    decrypted = collect(decrypt(new_ct, private_key))

    println("Original values:  ", values)
    println("Decrypted values: ", decrypted)

    @test decrypted ≈ values atol=1e-6
end
