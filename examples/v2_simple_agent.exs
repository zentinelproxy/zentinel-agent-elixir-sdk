#!/usr/bin/env elixir
# Simple V2 Zentinel agent example.
#
# This example demonstrates a basic V2 agent that:
# - Declares its capabilities
# - Blocks requests to /admin paths
# - Reports health status
# - Supports request cancellation
#
# Run with: elixir examples/v2_simple_agent.exs
# Or: mix run examples/v2_simple_agent.exs

Mix.install([
  {:zentinel_agent_sdk, path: "."}
])

defmodule SimpleAgentV2 do
  @moduledoc """
  A simple V2 agent that blocks admin paths with capability declaration.
  """

  use ZentinelAgentSdk.V2.Agent

  @impl true
  def name, do: "simple-agent-v2"

  @impl true
  def version, do: "1.0.0"

  @impl true
  def capabilities do
    AgentCapabilities.new()
    |> AgentCapabilities.with_name(name())
    |> AgentCapabilities.with_version(version())
    |> AgentCapabilities.handles_request_headers()
    |> AgentCapabilities.handles_response_headers()
    |> AgentCapabilities.supports_cancellation()
    |> AgentCapabilities.supports_health_check()
    |> AgentCapabilities.with_max_concurrent_requests(100)
  end

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
        |> Decision.add_request_header("X-Agent-Version", version())
    end
  end

  @impl true
  def on_response(_request, _response) do
    Decision.allow()
    |> Decision.add_response_header("X-Processed-By", "#{name()}/#{version()}")
  end

  @impl true
  def on_request_complete(request, status, duration_ms) do
    IO.puts(
      "[#{name()}] #{Request.method(request)} #{Request.path(request)} -> #{status} (#{duration_ms}ms)"
    )

    :ok
  end

  @impl true
  def health_check do
    # Simple health check - always healthy
    HealthStatus.healthy()
    |> HealthStatus.with_message("All systems operational")
  end

  @impl true
  def on_cancel(request_id, cancel_request) do
    IO.puts("[#{name()}] Request #{request_id} cancelled: #{cancel_request.reason || "no reason"}")
    :ok
  end

  @impl true
  def on_drain(timeout_ms, reason) do
    IO.puts("[#{name()}] Draining: #{reason || "shutdown"}, timeout: #{timeout_ms}ms")
    :ok
  end

  @impl true
  def on_shutdown do
    IO.puts("[#{name()}] Shutting down...")
    :ok
  end
end

# Parse command line args
{opts, _args, _invalid} =
  OptionParser.parse(System.argv(),
    strict: [
      socket: :string,
      log_level: :string,
      json_logs: :boolean,
      transport: :string,
      proxy_url: :string,
      auth_token: :string
    ]
  )

transport =
  case Keyword.get(opts, :transport, "uds") do
    "uds" -> :uds
    "reverse" -> :reverse
    other -> raise "Unknown transport: #{other}"
  end

socket = Keyword.get(opts, :socket, "/tmp/zentinel-agent-v2.sock")
log_level = Keyword.get(opts, :log_level, "info") |> String.to_atom()
json_logs = Keyword.get(opts, :json_logs, false)
proxy_url = Keyword.get(opts, :proxy_url)
auth_token = Keyword.get(opts, :auth_token)

# Run the agent
ZentinelAgentSdk.V2.run(SimpleAgentV2,
  transport: transport,
  socket: socket,
  proxy_url: proxy_url,
  auth_token: auth_token,
  log_level: log_level,
  json_logs: json_logs
)
