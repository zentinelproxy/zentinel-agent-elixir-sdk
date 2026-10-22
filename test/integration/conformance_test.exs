defmodule Integration.ConformanceTest do
  @moduledoc """
  The SDK against a real Zentinel, through the shared conformance harness.

  The harness (`sdk-conformance/run.py` in zentinelproxy/zentinel) starts a
  `zentinel` binary in front of an echo upstream and checks over HTTP that the
  agents in `examples/` speak agent protocol v2: handshake, configure, header
  mutations, block, body inspection, reconnect. CI runs it through the
  harness's GitHub Action; this test runs the same thing locally:

      ZENTINEL_BIN=/path/to/zentinel \\
      ZENTINEL_CONFORMANCE_HARNESS=/path/to/zentinel/sdk-conformance/run.py \\
      mix test --only zentinel

  Both variables are required; without them the tests are excluded.
  """

  use ExUnit.Case

  @moduletag :zentinel
  @moduletag timeout: 600_000

  defp example(name) do
    mix = System.find_executable("mix") || "mix"
    root = Path.expand("../..", __DIR__)
    "cd #{root} && #{mix} run examples/#{name}"
  end

  defp harness(args) do
    System.cmd(
      "python3",
      [
        System.fetch_env!("ZENTINEL_CONFORMANCE_HARNESS"),
        "--zentinel-bin",
        System.fetch_env!("ZENTINEL_BIN") | args
      ],
      stderr_to_stdout: true,
      env: [{"MIX_ENV", "dev"}]
    )
  end

  test "conformance agent passes over UDS and gRPC" do
    {output, status} =
      harness([
        "--agent-cmd",
        example("conformance_agent.exs") <> " --socket {socket}",
        "--grpc-agent-cmd",
        example("conformance_agent.exs") <> " --grpc {grpc}"
      ])

    assert status == 0, output
  end

  test "README hello agent passes the hello profile" do
    {output, status} =
      harness(["--profile", "hello", "--agent-cmd", example("hello_agent.exs") <> " {socket}"])

    assert status == 0, output
  end
end
