# The conformance agent of the Zentinel SDK conformance harness.
#
# Implements the behaviour `sdk-conformance/README.md` in zentinelproxy/zentinel
# specifies, so the harness can check this SDK against a real proxy:
#
#     mix run examples/conformance_agent.exs --socket /tmp/conformance.sock
#     mix run examples/conformance_agent.exs --grpc 127.0.0.1:50051

defmodule ConformanceAgent do
  use ZentinelAgentSdk.V2.Agent

  @impl true
  def name, do: "conformance"

  @impl true
  def version, do: "0.3.0"

  @impl true
  def capabilities do
    AgentCapabilities.new()
    |> AgentCapabilities.with_name(name())
    |> AgentCapabilities.with_version(version())
    |> AgentCapabilities.handles_request_headers()
    |> AgentCapabilities.handles_request_body()
    |> AgentCapabilities.handles_response_headers()
  end

  @impl true
  def on_configure(config) do
    :persistent_term.put({__MODULE__, :config}, config)
    :ok
  end

  defp config_value do
    case :persistent_term.get({__MODULE__, :config}, nil) do
      %{"nested" => %{"value" => value}} when is_binary(value) -> value
      _ -> "unconfigured"
    end
  end

  @impl true
  def on_request(request) do
    if Request.path_starts_with?(request, "/block") do
      Decision.block(403) |> Decision.with_body("blocked-by-agent")
    else
      Decision.allow()
      |> Decision.add_request_header("X-Hello", "from-agent")
      |> Decision.add_request_header("X-Conformance-Config", config_value())
    end
  end

  @impl true
  def on_request_body(request) do
    body = Request.body(request) || ""

    if String.contains?(body, "block-this-body") do
      Decision.block(403) |> Decision.with_body("body-seen:" <> body)
    else
      Decision.allow()
    end
  end

  @impl true
  def on_response(_request, _response) do
    Decision.allow() |> Decision.add_response_header("X-Conformance-Response", "from-agent")
  end
end

{opts, _, _} = OptionParser.parse(System.argv(), strict: [socket: :string, grpc: :string])

transport =
  case {opts[:socket], opts[:grpc]} do
    {nil, nil} -> [socket: "/tmp/conformance.sock"]
    {socket, nil} -> [socket: socket]
    {nil, grpc} -> [transport: :grpc, grpc_address: grpc]
    {socket, grpc} -> [transport: :both, socket: socket, grpc_address: grpc]
  end

ZentinelAgentSdk.V2.run(ConformanceAgent, transport)
