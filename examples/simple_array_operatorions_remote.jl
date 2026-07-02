using RemoteFHE
using SecureArithmetic
using OpenFHE

host = if get(ENV, "REMOTEFHE_CLIENT_SSL", "false") !== "false"
    "https://127.0.0.1:8080"
else
    "http://127.0.0.1:8080"
end



################################################################################
println("="^80)
println("Creating OpenFHE context...")

parameters = CCParams{CryptoContextCKKSRNS}()

secret_key_distribution = UNIFORM_TERNARY
SetSecretKeyDist(parameters, secret_key_distribution)

SetSecurityLevel(parameters, HEStd_NotSet)
SetRingDim(parameters, 1 << 5)

rescale_technique = FLEXIBLEAUTO
dcrt_bits = 59
first_modulus = 60

SetScalingModSize(parameters, dcrt_bits)
SetScalingTechnique(parameters, rescale_technique)
SetFirstModSize(parameters, first_modulus)

level_budget = [4, 4]

levels_available_after_bootstrap = 10
depth = levels_available_after_bootstrap + GetBootstrapDepth(level_budget, secret_key_distribution)
SetMultiplicativeDepth(parameters, depth)

cc = GenCryptoContext(parameters)

Enable(cc, PKE)
Enable(cc, KEYSWITCH)
Enable(cc, LEVELEDSHE)
Enable(cc, ADVANCEDSHE)
Enable(cc, FHE)

ring_dimension = GetRingDimension(cc)
# This is the maximum number of slots that can be used for full packing.
num_slots = div(ring_dimension,  2)
println("CKKS scheme is using ring dimension ", ring_dimension)
println()

EvalBootstrapSetup(cc; level_budget)

context_openfhe = SecureContext(OpenFHEBackend(cc))


################################################################################
println("="^80)
println("Creating unencrypted context...")
println()

context_unencrypted = SecureContext(Unencrypted())


################################################################################
println("="^80)
println("simple_array_operations with an OpenFHE context")
RemoteFHE.simple_array_operations_remote(
    context_openfhe, host;
    username=get(ENV, "REMOTEFHE_USERNAME", nothing),
    password=get(ENV, "REMOTEFHE_PASSWORD", nothing),
    ca_file = get(ENV, "REMOTEFHE_CA_FILE", nothing),
)


################################################################################
println("="^80)
println("simple_array_operations with an Unencrypted context")
RemoteFHE.simple_array_operations_remote(
    context_unencrypted, host;
    username=get(ENV, "REMOTEFHE_USERNAME", nothing),
    password=get(ENV, "REMOTEFHE_PASSWORD", nothing),
    ca_file = get(ENV, "REMOTEFHE_CA_FILE", nothing),
)
