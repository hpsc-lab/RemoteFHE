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

### Environment variables
The example scripts can be configured with environment variables to enable basic auth and TLS. 
All variables are optional.  
The default is no auth and communication over plain http.

| Variable | Description |
|---|---|
| `REMOTEFHE_USERNAME` | Basic-auth username |
| `REMOTEFHE_PASSWORD` | Basic-auth password |
| `REMOTEFHE_CERT_FILE` | Path to PEM certificate (server only) |
| `REMOTEFHE_KEY_FILE` | Path to PEM private key (server only) |
| `REMOTEFHE_CLIENT_SSL` | Path to PEM private key (client only) |
| `REMOTEFHE_CA_FILE` | Path to CA certificate for verification (client) |

### TLS setup

The server requires a TLS certificate signed by a CA that the client trusts.
For local development, create your own CA and sign a server certificate:

```sh
# 1. Create a CA key and self-signed CA certificate
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout ca-key.pem -out ca.pem -days 3650 -nodes \
  -subj "/CN=RemoteFHE Dev CA"

# 2. Create a server key and certificate signing request (CSR)
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout key.pem -out server.csr -nodes \
  -subj "/CN=localhost"

# 3. Sign the server certificate with the CA
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out cert.pem -days 365 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")
```

The server uses `cert.pem` and `key.pem`. The client uses `ca.pem` to verify
the server's certificate. Distribute `ca.pem` to any machine that needs to
connect; keep `ca-key.pem` private.



### Running

1. Start the server:

```sh
export REMOTEFHE_USERNAME=user REMOTEFHE_PASSWORD=pass
export REMOTEFHE_CERT_FILE=cert.pem REMOTEFHE_KEY_FILE=key.pem
julia --project=RemoteFHE examples/server.jl
```

2. In another terminal, run the client:

```sh
export REMOTEFHE_USERNAME=user REMOTEFHE_PASSWORD=pass
export REMOTEFHE_CA_FILE=ca.pem REMOTEFHE_CLIENT_SSL=true
julia --project=RemoteFHE examples/client.jl
```

## Notes


## Authors
RemoteFHE.jl was initiated by [Tom Finke](https://github.com/Tom-Finke/) while working for Michael Schlottke-Lakemper at the HPSC Lab of the University of Augsburg, Germany (https://hpsc.math.uni-augsburg.de).


## License and contributing
RemoteFHE.jl is available under the MIT license (see [LICENSE.md](LICENSE.md)).
Contributions by the community are very welcome! For larger proposed changes, feel free
to reach out via an issue first.

