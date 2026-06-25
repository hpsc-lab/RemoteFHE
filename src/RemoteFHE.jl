module RemoteFHE

using Serialization
using HTTP
using Base64
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

"""
    make_part(obj) -> HTTP.Multipart

Serialize `obj` into an `HTTP.Multipart` part using Julia's `Serialization` stdlib.

The content type `application/x-julia-serialized-object` follows the convention
established by Java's `application/x-java-serialized-object` for language-specific
serialized objects.
"""
function make_part(obj)
    io = IOBuffer()
    serialize(io, obj)
    seekstart(io)
    HTTP.Multipart(nothing, io, "application/x-julia-serialized-object")
end

"""
    parse_parts(parts::Vector{HTTP.Multipart}) -> Dict{String, Any}

Deserialize a vector of multipart form parts into a name-value dictionary.
Parts with content type `application/x-julia-serialized-object` are deserialized
via `Serialization.deserialize`.
"""
function parse_parts(parts::Vector{HTTP.Multipart})
    Dict(
        p.name => if p.contenttype == "application/x-julia-serialized-object"
            deserialize(p.data)
        else
            read(p.data)  # return raw data for unknown types
        end
        for p in parts
    )
end


function basic_auth_middleware(handler, username::AbstractString, password::AbstractString)
    expected = base64encode("$username:$password")
    return function(req)
        auth = HTTP.header(req, "Authorization", "")
        if startswith(auth, "Basic ") && SubString(auth, 7) == expected
            return handler(req)
        end
        HTTP.Response(401, ["WWW-Authenticate" => "Basic realm=\"RemoteFHE\""], "Unauthorized")
    end
end

function run_server(port::Integer = 8080)
    username = ENV["REMOTEFHE_USERNAME"]
    password = ENV["REMOTEFHE_PASSWORD"]

    router = HTTP.Router()

    HTTP.register!(router, "POST", "/compute") do req
        try
            parts = HTTP.parse_multipart_form(req)
            parts === nothing && return HTTP.Response(415, "expected multipart/form-data")
            fields = parse_parts(parts)
            @info "Deserialized fields from client" names=collect(keys(fields))

            context = fields["context"]
            public_key = fields["public_key"]
            ciphertext = fields["ciphertext"]

            result = ciphertext + ciphertext
            @info "Computed result"

            form = HTTP.Form(["result" => make_part(result)])
            body = read(form)
            @info "Serialized result" length=length(body)
            return HTTP.Response(200, ["Content-Type" => HTTP.content_type(form)]; body)
        catch e
            @error "Error in /compute handler" exception=(e, catch_backtrace())
            rethrow()
        end
    end

    server = HTTP.serve!(basic_auth_middleware(router, username, password), "0.0.0.0", port)
    @info "RemoteFHE server listening on port $port"
    wait(server)
end

function run_client(values::AbstractVector{<:Real}, host::AbstractString = "http://127.0.0.1:8080")
    username = ENV["REMOTEFHE_USERNAME"]
    password = ENV["REMOTEFHE_PASSWORD"]

    (; context, public_key, private_key) = setup_context()
    ciphertext = encrypt_vector(values, public_key, context)
    println("Encrypted values: ", values)

    form = HTTP.Form([
        "context" => make_part(context),
        "public_key" => make_part(public_key),
        "ciphertext" => make_part(ciphertext),
    ])
    response = HTTP.post("$host/compute", ["Content-Type" => HTTP.content_type(form)], form;
                         basicauth = (username, password))

    ct = HTTP.header(response, "Content-Type")
    resp_parts = HTTP.parse_multipart_form(ct, response.body)
    resp_fields = parse_parts(resp_parts)
    result_encrypted = resp_fields["result"]

    result_plain = decrypt(result_encrypted, private_key)
    println("Decrypted result: ", result_plain)
    return result_plain
end

end # module RemoteFHE
