#!/usr/bin/env elixir
# Simple Zentinel agent example.
#
# This example demonstrates a basic agent that:
# - Blocks requests to /admin paths
# - Adds custom headers to allowed requests
# - Logs request completions
#
# Run with: elixir examples/simple_agent.exs
# Or: mix run examples/simple_agent.exs

Mix.install([
  {:zentinel_agent_sdk, path: "."}
])

defmodule SimpleAgent do
  @moduledoc """
  A simple example agent that blocks admin paths.
  """

  use ZentinelAgentSdk.Agent

  @impl true
  def name, do: "simple-agent"

  @impl true
  def on_request(request) do
    cond do
      # Block admin paths
      Request.path_starts_with?(request, "/admin") ->
        Decision.deny()
        |> Decision.with_body("Access denied")
        |> Decision.with_tag("security")
        |> Decision.with_rule_id("ADMIN_BLOCKED")

      # Block requests without User-Agent
      Request.user_agent(request) == nil ->
        Decision.block(400)
        |> Decision.with_body("User-Agent header required")
        |> Decision.with_tag("validation")

      # Allow with custom header
      true ->
        Decision.allow()
        |> Decision.add_request_header("X-Agent-Processed", "true")
    end
  end

  @impl true
  def on_response(_request, _response) do
    Decision.allow()
    |> Decision.add_response_header("X-Processed-By", name())
  end

  @impl true
  def on_request_complete(request, status, duration_ms) do
    IO.puts(
      "Request completed: #{Request.method(request)} #{Request.path(request)} -> #{status} (#{duration_ms}ms)"
    )

    :ok
  end
end

# Parse command line args
{opts, _args, _invalid} =
  OptionParser.parse(System.argv(),
    strict: [socket: :string, log_level: :string, json_logs: :boolean]
  )

socket = Keyword.get(opts, :socket, "/tmp/zentinel-agent.sock")
log_level = Keyword.get(opts, :log_level, "info") |> String.to_atom()
json_logs = Keyword.get(opts, :json_logs, false)

# Run the agent
ZentinelAgentSdk.run(SimpleAgent,
  socket: socket,
  log_level: log_level,
  json_logs: json_logs
)
