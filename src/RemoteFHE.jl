module RemoteFHE

using Serialization
using Sockets
using OpenFHE
using SecureArithmetic

export run_server, run_client


function setup_context(; batch_size::Integer = 8, mult_depth::Integer = 2, scaling_modulus::Integer = 50)
    parameters = CCParams{CryptoContextCKKSRNS}()
    SetMultiplicativeDepth(parameters, mult_depth)
    SetScalingModSize(parameters, scaling_modulus)
    SetBatchSize(parameters, batch_size)

    cc = GenCryptoContext(parameters)
    Enable(cc, PKE)
    Enable(cc, KEYSWITCH)
    Enable(cc, LEVELEDSHE)

    context = SecureContext(OpenFHEBackend(cc))
    public_key, private_key = generate_keys(context)
    init_multiplication!(context, private_key)

    (; context, public_key, private_key, cc)
end

function encrypt_vector(values::AbstractVector{<:Real}, public_key, context)
    plaintext = PlainVector(collect(values), context)
    encrypt(plaintext, public_key)
end

# sockets are an IO
# using Serialization.serialize, we can serialize directly into sockets
# See e.g. https://github.com/JuliaWeb/RemoteREPL.jl/blob/7b0f6072eb9477f12579493db518a48ec6c55f1e/src/client.jl#L145
function send_to_server(sock::IO, context, public_key, ciphertext)
    serialize(sock, context)
    serialize(sock, public_key)
    serialize(sock, ciphertext)
    flush(sock)
end

function receive_from_client(sock::IO)
    context = deserialize(sock)
    public_key = deserialize(sock)
    ciphertext = deserialize(sock)
    (; context, public_key, ciphertext)
end


function run_server(port::Integer = 25015)
    server = Sockets.listen(port)
    println("RemoteFHE server listening on port $port")

    sock = accept(server)
    try
        println("Client connected")

        (; context, public_key, ciphertext) = receive_from_client(sock)
        println("Received $(length(ciphertext)) ciphertext(s) from client")
        
        result = ciphertext + ciphertext

        serialize(sock, result)
        flush(sock)
        println("Sent $(length(result)) result ciphertext(s)")
    finally
        close(sock)
        close(server)
    end
end

function run_client(values::AbstractVector{<:Real}, host::AbstractString = "127.0.0.1", port::Integer = 25015)
    (; context, public_key, private_key) = setup_context()
    ciphertext = encrypt_vector(values, public_key, context)
    println("Encrypted values: ", values)

    sock = connect(host, port)
    try
        send_to_server(sock, context, public_key, ciphertext)

        result_encrypted = deserialize(sock)

        result_plain = decrypt(result_encrypted, private_key)
        println("Decrypted result: ", result_plain)
        return result_plain
    finally
        close(sock)
    end
end

end # module RemoteFHE
