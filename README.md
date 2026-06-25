> [!WARNING]
> This project is in an early alpha state. It is not recommended to use this package in its current state.

# RemoteFHE

A minimal Julia project demonstrating a simple OpenFHE client/server flow.

## Overview

This project uses Julia's `Serialization` librariy to pass data SecureArithmetic objects between client and server.
The server does not decrypt client data; it operates on encrypted ciphertext and returns an encrypted result.

- `RemoteFHE` creates an OpenFHE-backed `SecureContext`.
- The client encrypts a vector with a public key and sends the ciphertext to the server.
- The server processes the encrypted payload and sends the encrypted result back.
- The client decrypts the returned ciphertext with its private key.

## Usage

1. Start the server:

```sh
julia --project=RemoteFHE examples/server.jl
```

2. In another terminal, run the client:

```sh
julia --project=RemoteFHE examples/client.jl
```

## Notes


## Authors
RemoteFHE.jl was initiated by [Tom Finke](https://github.com/Tom-Finke/) while working for Michael Schlottke-Lakemper at the HPSC Lab of the University of Augsburg, Germany (https://hpsc.math.uni-augsburg.de).


## License and contributing
RemoteFHE.jl is available under the MIT license (see [LICENSE.md](LICENSE.md)).
Contributions by the community are very welcome! For larger proposed changes, feel free
to reach out via an issue first.

