# The README quick-start agent: adds X-Hello and allows.
#
# Kept identical to the README (apart from the Mix.install line and taking the
# socket path as an argument), so CI can run it through the conformance
# harness:
#
#     mix run examples/hello_agent.exs /tmp/hello.sock

defmodule HelloAgent do
  use ZentinelAgentSdk.V2.Agent

  @impl true
  def name, do: "hello"

  @impl true
  def on_request(_request) do
    Decision.allow() |> Decision.add_request_header("X-Hello", "from-agent")
  end
end

socket = List.first(System.argv()) || "/tmp/hello.sock"
ZentinelAgentSdk.V2.run(HelloAgent, socket: socket)
