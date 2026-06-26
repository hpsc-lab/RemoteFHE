using RemoteFHE
using Logging, LoggingExtras

logger = FormatLogger("server.log"; append=false) do io, args
    println(io, "[$(args.level)] $(args.message)")
end
global_logger(logger)

RemoteFHE.run_server(
    ;
    username=get(ENV, "REMOTEFHE_USERNAME", nothing),
    password=get(ENV, "REMOTEFHE_PASSWORD", nothing),
    cert_file=get(ENV, "REMOTEFHE_CERT_FILE", nothing),
    key_file=get(ENV, "REMOTEFHE_KEY_FILE", nothing),
)
