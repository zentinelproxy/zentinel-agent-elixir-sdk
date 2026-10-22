# The integration tests run the SDK's agents behind a real zentinel binary
# through the shared conformance harness; they need ZENTINEL_BIN and
# ZENTINEL_CONFORMANCE_HARNESS (see test/integration/conformance_test.exs).
exclude =
  if System.get_env("ZENTINEL_BIN") && System.get_env("ZENTINEL_CONFORMANCE_HARNESS"),
    do: [],
    else: [:zentinel]

ExUnit.start(exclude: exclude)
