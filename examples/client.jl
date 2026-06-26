using RemoteFHE

host = if get(ENV, "REMOTEFHE_CLIENT_SSL", "false") !== "false"
    "https://127.0.0.1:8080"
else
    "http://127.0.0.1:8080"
end

result = RemoteFHE.run_client(
    [0.5, 1.5, 2.5, 3.5], host;
    username=get(ENV, "REMOTEFHE_USERNAME", nothing),
    password=get(ENV, "REMOTEFHE_PASSWORD", nothing),
    ca_file = get(ENV, "REMOTEFHE_CA_FILE", nothing),
)
println("Client finished. Result = ", result)