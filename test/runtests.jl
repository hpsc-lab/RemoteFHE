using Test
using OpenFHE
using SecureArithmetic
using RemoteFHE

@testset verbose=true showtiming=true "RemoteFHE" begin

@testset "Ciphertext serialization round-trip" begin
    values = [1.0, 2.0, 3.0, 4.0]
    cli = RemoteFHE.setup_context()
    ciphertext = RemoteFHE.encrypt_vector(values, cli.public_key, cli.context)

    sock = IOBuffer()
    RemoteFHE.send_to_server(sock, cli.context, cli.public_key, ciphertext)
    seekstart(sock) # Other than TCP sockets, reading and writing side are the same. We need to go back to the start of the buffer for reading
    srv = RemoteFHE.receive_from_client(sock)

    @test srv.ciphertext isa SecureArray
    decrypted = decrypt(srv.ciphertext, cli.private_key)
    @test collect(decrypted) ≈ values
end


@testset "Server-side modification" begin
    values = [1.0, 2.0, 3.0, 4.0]
    values_2 = [1, 1.0, 2, 2.0]
    cli = RemoteFHE.setup_context()
    ciphertext = RemoteFHE.encrypt_vector(values, cli.public_key, cli.context)

    sock = IOBuffer()
    RemoteFHE.send_to_server(sock, cli.context, cli.public_key, ciphertext)
    seekstart(sock) # Other than TCP sockets, reading and writing side are the same. We need to go back to the start of the buffer for reading
    srv = RemoteFHE.receive_from_client(sock)
    ciphertext_2 = RemoteFHE.encrypt_vector(values_2, srv.public_key, srv.context)

    result = srv.ciphertext + ciphertext_2

    decrypted = decrypt(result, cli.private_key)
    @test collect(decrypted) ≈ [2, 3, 5, 6]
end

end # @testset "RemoteFHE"
