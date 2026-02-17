#!/usr/bin/env elixir
# Configurable Zentinel agent example.
#
# This example demonstrates an agent with typed configuration that:
# - Accepts rate limit configuration from the proxy
# - Tracks request counts per client IP
# - Rate limits clients exceeding the threshold
#
# Run with: elixir examples/configurable_agent.exs
# Or: mix run examples/configurable_agent.exs

Mix.install([
  {:zentinel_agent_sdk, path: "."}
])

defmodule RateLimitConfig do
  @moduledoc """
  Configuration for the rate limiting agent.
  """

  defstruct enabled: true,
            requests_per_minute: 100,
            blocked_paths: []
end

defmodule RateLimitAgent do
  @moduledoc """
  An agent that rate limits requests per client IP.

  Note: This example uses a simple ETS table for tracking request counts.
  In production, you might want to use a proper rate limiting library
  or distributed state management.
  """

  use ZentinelAgentSdk.ConfigurableAgent

  @impl true
  def name, do: "rate-limit-agent"

  @impl true
  def default_config, do: %RateLimitConfig{}

  @impl true
  def parse_config(config_map) do
    %RateLimitConfig{
      enabled: Map.get(config_map, "enabled", true),
      requests_per_minute: Map.get(config_map, "requests_per_minute", 100),
      blocked_paths: Map.get(config_map, "blocked_paths", [])
    }
  end

  @impl true
  def on_config_applied(config) do
    IO.puts("Configuration applied: #{inspect(config)}")

    # Create ETS table for request counts if it doesn't exist
    if :ets.whereis(:rate_limit_counts) == :undefined do
      :ets.new(:rate_limit_counts, [:named_table, :public, :set])

      # Start a process to reset counts every minute
      spawn(fn -> reset_counts_loop() end)
    end

    :ok
  end

  defp reset_counts_loop do
    Process.sleep(60_000)
    :ets.delete_all_objects(:rate_limit_counts)
    reset_counts_loop()
  end

  @impl true
  def on_request(request, config) do
    cond do
      # Check if agent is enabled
      not config.enabled ->
        Decision.allow()

      # Check blocked paths
      blocked_path?(request, config.blocked_paths) ->
        Decision.deny()
        |> Decision.with_body("Path is blocked")
        |> Decision.with_tag("blocked_path")

      # Check rate limit
      rate_limited?(request, config) ->
        client_ip = Request.client_ip(request)
        count = get_request_count(client_ip)

        Decision.rate_limited()
        |> Decision.with_body("Rate limit exceeded")
        |> Decision.with_tag("rate_limited")
        |> Decision.with_metadata("client_ip", client_ip)
        |> Decision.with_metadata("request_count", count)
        |> Decision.with_metadata("limit", config.requests_per_minute)

      # Allow with rate limit headers
      true ->
        client_ip = Request.client_ip(request)
        increment_request_count(client_ip)
        count = get_request_count(client_ip)
        remaining = config.requests_per_minute - count

        Decision.allow()
        |> Decision.add_response_header("X-RateLimit-Limit", Integer.to_string(config.requests_per_minute))
        |> Decision.add_response_header("X-RateLimit-Remaining", Integer.to_string(max(0, remaining)))
    end
  end

  defp blocked_path?(request, blocked_paths) do
    Enum.any?(blocked_paths, fn path ->
      Request.path_starts_with?(request, path)
    end)
  end

  defp rate_limited?(request, config) do
    client_ip = Request.client_ip(request)
    count = get_request_count(client_ip)
    count >= config.requests_per_minute
  end

  defp get_request_count(client_ip) do
    case :ets.lookup(:rate_limit_counts, client_ip) do
      [{^client_ip, count}] -> count
      [] -> 0
    end
  rescue
    ArgumentError -> 0
  end

  defp increment_request_count(client_ip) do
    try do
      :ets.update_counter(:rate_limit_counts, client_ip, 1, {client_ip, 0})
    rescue
      ArgumentError -> 0
    end
  end

  @impl true
  def on_response(_request, _response, _config) do
    Decision.allow()
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
ZentinelAgentSdk.run(RateLimitAgent,
  socket: socket,
  log_level: log_level,
  json_logs: json_logs
)
