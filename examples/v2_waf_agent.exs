#!/usr/bin/env elixir
# V2 WAF Agent example with full capabilities.
#
# This example demonstrates a more complete V2 agent that:
# - Inspects request headers and body for threats
# - Reports detailed health status
# - Exposes metrics
# - Supports streaming and cancellation
# - Uses typed configuration
#
# Run with: elixir examples/v2_waf_agent.exs
# Or: mix run examples/v2_waf_agent.exs

Mix.install([
  {:zentinel_agent_sdk, path: "."}
])

defmodule WafConfig do
  @moduledoc """
  Configuration for the WAF agent.
  """

  defstruct enabled: true,
            block_sql_injection: true,
            block_xss: true,
            max_body_size: 1_048_576,
            blocked_user_agents: [],
            allowed_content_types: ["application/json", "application/x-www-form-urlencoded", "text/plain"]
end

defmodule WafAgentV2 do
  @moduledoc """
  A V2 WAF agent with body inspection and metrics.
  """

  use ZentinelAgentSdk.V2.ConfigurableAgent

  # Track metrics
  @blocked_count :persistent_term.get({__MODULE__, :blocked_count}, 0)

  @impl true
  def name, do: "waf-agent-v2"

  @impl true
  def version, do: "2.0.0"

  @impl true
  def capabilities do
    AgentCapabilities.new()
    |> AgentCapabilities.with_name(name())
    |> AgentCapabilities.with_version(version())
    |> AgentCapabilities.handles_request_headers()
    |> AgentCapabilities.handles_request_body()
    |> AgentCapabilities.handles_response_headers()
    |> AgentCapabilities.supports_cancellation()
    |> AgentCapabilities.supports_health_check()
    |> AgentCapabilities.supports_metrics()
    |> AgentCapabilities.with_max_concurrent_requests(200)
    |> AgentCapabilities.with_custom("waf_version", "2.0")
  end

  @impl true
  def default_config, do: %WafConfig{}

  @impl true
  def parse_config(config_map) do
    %WafConfig{
      enabled: Map.get(config_map, "enabled", true),
      block_sql_injection: Map.get(config_map, "block_sql_injection", true),
      block_xss: Map.get(config_map, "block_xss", true),
      max_body_size: Map.get(config_map, "max_body_size", 1_048_576),
      blocked_user_agents: Map.get(config_map, "blocked_user_agents", []),
      allowed_content_types: Map.get(config_map, "allowed_content_types", [
        "application/json",
        "application/x-www-form-urlencoded",
        "text/plain"
      ])
    }
  end

  @impl true
  def on_config_applied(config) do
    IO.puts("[#{name()}] Configuration applied:")
    IO.puts("  Enabled: #{config.enabled}")
    IO.puts("  SQL Injection blocking: #{config.block_sql_injection}")
    IO.puts("  XSS blocking: #{config.block_xss}")
    IO.puts("  Max body size: #{config.max_body_size}")

    # Initialize metrics
    :persistent_term.put({__MODULE__, :blocked_count}, 0)
    :persistent_term.put({__MODULE__, :requests_processed}, 0)
    :persistent_term.put({__MODULE__, :latencies}, [])

    :ok
  end

  @impl true
  def on_request(request, config) do
    start_time = System.monotonic_time(:microsecond)

    result =
      cond do
        # Check if WAF is enabled
        not config.enabled ->
          Decision.allow()

        # Check blocked user agents
        blocked_user_agent?(request, config) ->
          increment_blocked()

          Decision.deny()
          |> Decision.with_body("Blocked user agent")
          |> Decision.with_tag("blocked_ua")
          |> Decision.with_rule_id("WAF_BLOCKED_UA")

        # Check content type for POST/PUT/PATCH
        not valid_content_type?(request, config) ->
          increment_blocked()

          Decision.block(415)
          |> Decision.with_body("Unsupported content type")
          |> Decision.with_tag("invalid_content_type")
          |> Decision.with_rule_id("WAF_INVALID_CT")

        # Allow but request body inspection if needed
        Request.is_post?(request) or Request.is_put?(request) or Request.is_patch?(request) ->
          Decision.allow()
          |> Decision.needs_more_data()

        # Allow GET/DELETE without body inspection
        true ->
          increment_processed()
          Decision.allow()
      end

    # Record latency
    elapsed = System.monotonic_time(:microsecond) - start_time
    record_latency(elapsed)

    result
  end

  @impl true
  def on_request_body(request, config) do
    body = Request.body_str(request)

    cond do
      # Check body size
      byte_size(body) > config.max_body_size ->
        increment_blocked()

        Decision.block(413)
        |> Decision.with_body("Request body too large")
        |> Decision.with_tag("body_too_large")
        |> Decision.with_rule_id("WAF_BODY_SIZE")

      # Check for SQL injection
      config.block_sql_injection and contains_sql_injection?(body) ->
        increment_blocked()

        Decision.deny()
        |> Decision.with_body("Potential SQL injection detected")
        |> Decision.with_tag("sql_injection")
        |> Decision.with_rule_id("WAF_SQLI")
        |> Decision.with_confidence(0.85)

      # Check for XSS
      config.block_xss and contains_xss?(body) ->
        increment_blocked()

        Decision.deny()
        |> Decision.with_body("Potential XSS detected")
        |> Decision.with_tag("xss")
        |> Decision.with_rule_id("WAF_XSS")
        |> Decision.with_confidence(0.80)

      # Allow
      true ->
        increment_processed()
        Decision.allow()
    end
  end

  @impl true
  def on_response(_request, _response, _config) do
    Decision.allow()
    |> Decision.add_response_header("X-WAF-Status", "passed")
    |> Decision.add_response_header("X-WAF-Version", version())
  end

  @impl true
  def health_check(config) do
    if config.enabled do
      HealthStatus.healthy()
      |> HealthStatus.with_message("WAF active")
      |> HealthStatus.with_metadata("rules_enabled", rules_enabled_count(config))
    else
      HealthStatus.degraded()
      |> HealthStatus.with_message("WAF disabled by configuration")
    end
  end

  @impl true
  def metrics(_config) do
    blocked = :persistent_term.get({__MODULE__, :blocked_count}, 0)
    processed = :persistent_term.get({__MODULE__, :requests_processed}, 0)
    latencies = :persistent_term.get({__MODULE__, :latencies}, [])

    MetricsReport.new()
    |> MetricsReport.counter("requests_blocked", blocked, %{"agent" => name()})
    |> MetricsReport.counter("requests_processed", processed, %{"agent" => name()})
    |> MetricsReport.gauge("rules_active", 4, %{"agent" => name()})
    |> MetricsReport.histogram("request_latency_us", Enum.take(latencies, 100), %{"agent" => name()})
    |> MetricsReport.with_labels(%{"version" => version()})
  end

  @impl true
  def on_cancel(request_id, _cancel_request) do
    IO.puts("[#{name()}] Cancelled request #{request_id}")
    :ok
  end

  @impl true
  def on_drain(timeout_ms, reason) do
    IO.puts("[#{name()}] Draining: #{reason}, timeout: #{timeout_ms}ms")

    # Flush metrics
    blocked = :persistent_term.get({__MODULE__, :blocked_count}, 0)
    processed = :persistent_term.get({__MODULE__, :requests_processed}, 0)
    IO.puts("[#{name()}] Final stats: blocked=#{blocked}, processed=#{processed}")

    :ok
  end

  @impl true
  def on_shutdown do
    IO.puts("[#{name()}] Shutting down WAF agent")
    :ok
  end

  # Private helpers

  defp blocked_user_agent?(request, config) do
    case Request.user_agent(request) do
      nil -> false
      ua -> Enum.any?(config.blocked_user_agents, &String.contains?(ua, &1))
    end
  end

  defp valid_content_type?(request, config) do
    case Request.content_type(request) do
      nil -> true  # No content type is OK for GET
      ct ->
        base_ct = ct |> String.split(";") |> List.first() |> String.trim()
        Enum.any?(config.allowed_content_types, &(&1 == base_ct))
    end
  end

  defp contains_sql_injection?(body) do
    patterns = [
      ~r/(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b.*\b(FROM|INTO|WHERE|TABLE)\b)/i,
      ~r/(\b(OR|AND)\b\s+\d+\s*=\s*\d+)/i,
      ~r/(--\s*$|;\s*--)/,
      ~r/(\bEXEC\b|\bEXECUTE\b)/i
    ]

    Enum.any?(patterns, &Regex.match?(&1, body))
  end

  defp contains_xss?(body) do
    patterns = [
      ~r/<script\b[^>]*>/i,
      ~r/javascript\s*:/i,
      ~r/on\w+\s*=/i,
      ~r/<iframe\b/i,
      ~r/<embed\b/i,
      ~r/<object\b/i
    ]

    Enum.any?(patterns, &Regex.match?(&1, body))
  end

  defp rules_enabled_count(config) do
    count = 0
    count = if config.block_sql_injection, do: count + 1, else: count
    count = if config.block_xss, do: count + 1, else: count
    count + 2  # blocked_user_agents and content_type checks
  end

  defp increment_blocked do
    current = :persistent_term.get({__MODULE__, :blocked_count}, 0)
    :persistent_term.put({__MODULE__, :blocked_count}, current + 1)
  end

  defp increment_processed do
    current = :persistent_term.get({__MODULE__, :requests_processed}, 0)
    :persistent_term.put({__MODULE__, :requests_processed}, current + 1)
  end

  defp record_latency(latency_us) do
    current = :persistent_term.get({__MODULE__, :latencies}, [])
    # Keep last 1000 latencies
    updated = [latency_us | Enum.take(current, 999)]
    :persistent_term.put({__MODULE__, :latencies}, updated)
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

socket = Keyword.get(opts, :socket, "/tmp/zentinel-waf-v2.sock")
log_level = Keyword.get(opts, :log_level, "info") |> String.to_atom()
json_logs = Keyword.get(opts, :json_logs, false)
proxy_url = Keyword.get(opts, :proxy_url)
auth_token = Keyword.get(opts, :auth_token)

# Run the agent
ZentinelAgentSdk.V2.run(WafAgentV2,
  transport: transport,
  socket: socket,
  proxy_url: proxy_url,
  auth_token: auth_token,
  log_level: log_level,
  json_logs: json_logs
)
