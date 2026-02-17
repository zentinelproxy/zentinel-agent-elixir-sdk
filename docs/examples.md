# Examples

Common patterns and use cases for Zentinel agents.

## Basic Request Blocking

Block requests based on path patterns:

```elixir
defmodule BlockingAgent do
  @moduledoc "Block specific paths."

  use ZentinelAgentSdk.Agent

  alias ZentinelAgentSdk.{Decision, Request}

  @blocked_paths ["/admin", "/internal", "/.git", "/.env"]

  @impl true
  def name, do: "blocking-agent"

  @impl true
  def on_request(request) do
    path = Request.path_only(request)

    blocked? = Enum.any?(@blocked_paths, fn blocked ->
      String.starts_with?(path, blocked)
    end)

    if blocked? do
      Decision.deny()
      |> Decision.with_body("Not Found")
      |> Decision.with_tag("path-blocked")
    else
      Decision.allow()
    end
  end
end
```

## IP-Based Access Control

Block or allow requests based on client IP:

```elixir
defmodule IPFilterAgent do
  @moduledoc "Allow only specific IPs."

  use ZentinelAgentSdk.Agent

  alias ZentinelAgentSdk.{Decision, Request}

  @allowed_ips MapSet.new(["10.0.0.1", "192.168.1.1", "127.0.0.1"])

  @impl true
  def name, do: "ip-filter"

  @impl true
  def on_request(request) do
    client_ip = Request.client_ip(request)

    if MapSet.member?(@allowed_ips, client_ip) do
      Decision.allow()
    else
      Decision.deny()
      |> Decision.with_tag("ip-blocked")
      |> Decision.with_metadata("blocked_ip", client_ip)
    end
  end
end
```

## Authentication Validation

Validate JWT tokens:

```elixir
defmodule AuthAgent do
  @moduledoc "Validate JWT authentication."

  use ZentinelAgentSdk.Agent

  alias ZentinelAgentSdk.{Decision, Request}

  @impl true
  def name, do: "auth-agent"

  @impl true
  def on_request(request) do
    # Skip auth for public paths
    if Request.path_starts_with?(request, "/public") do
      Decision.allow()
    else
      validate_auth(request)
    end
  end

  defp validate_auth(request) do
    case Request.authorization(request) do
      nil ->
        Decision.unauthorized()
        |> Decision.with_body("Missing Authorization header")
        |> Decision.with_tag("auth-missing")

      "Bearer " <> token ->
        validate_token(token)

      _ ->
        Decision.unauthorized()
        |> Decision.with_body("Invalid Authorization header format")
        |> Decision.with_tag("auth-invalid")
    end
  end

  defp validate_token(token) do
    # Use your preferred JWT library here
    case verify_jwt(token) do
      {:ok, claims} ->
        Decision.allow()
        |> Decision.add_request_header("X-User-ID", claims["sub"] || "")
        |> Decision.add_request_header("X-User-Role", claims["role"] || "")

      {:error, :expired} ->
        Decision.unauthorized()
        |> Decision.with_body("Token expired")
        |> Decision.with_tag("auth-expired")

      {:error, _reason} ->
        Decision.unauthorized()
        |> Decision.with_body("Invalid token")
        |> Decision.with_tag("auth-invalid")
    end
  end

  defp verify_jwt(_token) do
    # Placeholder - implement with your JWT library
    {:ok, %{"sub" => "user-123", "role" => "admin"}}
  end
end
```

## Rate Limiting

Simple in-memory rate limiting using ETS:

```elixir
defmodule RateLimitAgent do
  @moduledoc "Simple rate limiting agent."

  use ZentinelAgentSdk.Agent

  alias ZentinelAgentSdk.{Decision, Request}

  @max_requests 100
  @window_seconds 60

  def start_link do
    :ets.new(:rate_limits, [:set, :public, :named_table])
    :ok
  end

  @impl true
  def name, do: "rate-limit"

  @impl true
  def on_request(request) do
    key = Request.client_ip(request)
    now = System.system_time(:second)
    window_start = now - @window_seconds

    # Get current count, cleaning old entries
    count = get_request_count(key, window_start)

    if count >= @max_requests do
      Decision.rate_limited()
      |> Decision.with_body("Too many requests")
      |> Decision.with_tag("rate-limited")
      |> Decision.add_response_header("Retry-After", Integer.to_string(@window_seconds))
    else
      increment_count(key, now)
      remaining = @max_requests - count - 1

      Decision.allow()
      |> Decision.add_response_header("X-RateLimit-Limit", Integer.to_string(@max_requests))
      |> Decision.add_response_header("X-RateLimit-Remaining", Integer.to_string(remaining))
    end
  end

  defp get_request_count(key, window_start) do
    case :ets.lookup(:rate_limits, key) do
      [{^key, timestamps}] ->
        valid = Enum.filter(timestamps, fn t -> t > window_start end)
        :ets.insert(:rate_limits, {key, valid})
        length(valid)

      [] ->
        0
    end
  end

  defp increment_count(key, timestamp) do
    case :ets.lookup(:rate_limits, key) do
      [{^key, timestamps}] ->
        :ets.insert(:rate_limits, {key, [timestamp | timestamps]})

      [] ->
        :ets.insert(:rate_limits, {key, [timestamp]})
    end
  end
end
```

## Header Modification

Add, remove, or modify headers:

```elixir
defmodule HeaderAgent do
  @moduledoc "Modify request and response headers."

  use ZentinelAgentSdk.Agent

  alias ZentinelAgentSdk.{Decision, Request, Response}

  @impl true
  def name, do: "header-agent"

  @impl true
  def on_request(request) do
    Decision.allow()
    # Add headers for upstream
    |> Decision.add_request_header("X-Forwarded-By", "zentinel")
    |> Decision.add_request_header("X-Request-ID", Request.correlation_id(request))
    # Remove sensitive headers
    |> Decision.remove_request_header("X-Internal-Token")
  end

  @impl true
  def on_response(_request, _response) do
    Decision.allow()
    # Add security headers
    |> Decision.add_response_header("X-Frame-Options", "DENY")
    |> Decision.add_response_header("X-Content-Type-Options", "nosniff")
    |> Decision.add_response_header("X-XSS-Protection", "1; mode=block")
    # Remove server info
    |> Decision.remove_response_header("Server")
    |> Decision.remove_response_header("X-Powered-By")
  end
end
```

## Configurable Agent

Agent with runtime configuration:

```elixir
defmodule ConfigurableBlocker.Config do
  defstruct enabled: true, blocked_paths: ["/admin"], log_requests: false
end

defmodule ConfigurableBlocker do
  @moduledoc "Agent with runtime configuration."

  use ZentinelAgentSdk.ConfigurableAgent

  alias ConfigurableBlocker.Config
  alias ZentinelAgentSdk.{Decision, Request}

  @impl true
  def name, do: "configurable-blocker"

  @impl true
  def default_config, do: %Config{}

  @impl true
  def parse_config(config_map) do
    %Config{
      enabled: Map.get(config_map, "enabled", true),
      blocked_paths: Map.get(config_map, "blocked_paths", ["/admin"]),
      log_requests: Map.get(config_map, "log_requests", false)
    }
  end

  @impl true
  def on_config_applied(config) do
    IO.puts("Configuration updated: enabled=#{config.enabled}")
    :ok
  end

  @impl true
  def on_request(request, config) do
    if not config.enabled do
      Decision.allow()
    else
      if config.log_requests do
        IO.puts("Request: #{Request.method(request)} #{Request.path_only(request)}")
      end

      path = Request.path_only(request)

      blocked? = Enum.any?(config.blocked_paths, fn blocked ->
        String.starts_with?(path, blocked)
      end)

      if blocked?, do: Decision.deny(), else: Decision.allow()
    end
  end
end
```

## Request Logging

Log all requests with timing:

```elixir
defmodule LoggingAgent do
  @moduledoc "Log all requests."

  use ZentinelAgentSdk.Agent

  alias ZentinelAgentSdk.{Decision, Request}

  require Logger

  @impl true
  def name, do: "logging-agent"

  @impl true
  def on_request(request) do
    method = Request.method(request) |> String.downcase()

    Decision.allow()
    |> Decision.with_tag("method:#{method}")
    |> Decision.with_metadata("path", Request.path_only(request))
    |> Decision.with_metadata("client_ip", Request.client_ip(request))
  end

  @impl true
  def on_request_complete(request, status, duration_ms) do
    Logger.info(
      "#{Request.client_ip(request)} - #{Request.method(request)} #{Request.path_only(request)} " <>
      "-> #{status} (#{duration_ms}ms)"
    )
    :ok
  end
end
```

## Content-Type Validation

Validate request content types:

```elixir
defmodule ContentTypeAgent do
  @moduledoc "Validate content types for POST/PUT requests."

  use ZentinelAgentSdk.Agent

  alias ZentinelAgentSdk.{Decision, Request}

  @allowed_types MapSet.new([
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data"
  ])

  @impl true
  def name, do: "content-type-validator"

  @impl true
  def on_request(request) do
    method = Request.method(request)

    # Only check methods with body
    if method in ["POST", "PUT", "PATCH"] do
      validate_content_type(request)
    else
      Decision.allow()
    end
  end

  defp validate_content_type(request) do
    case Request.content_type(request) do
      nil ->
        Decision.block(400)
        |> Decision.with_body("Content-Type header required")

      content_type ->
        # Extract base type (ignore params like charset)
        base_type = content_type |> String.split(";") |> hd() |> String.trim() |> String.downcase()

        if MapSet.member?(@allowed_types, base_type) do
          Decision.allow()
        else
          Decision.block(415)
          |> Decision.with_body("Unsupported Content-Type: #{base_type}")
          |> Decision.with_tag("invalid-content-type")
        end
    end
  end
end
```

## Redirect Agent

Redirect requests to different URLs:

```elixir
defmodule RedirectAgent do
  @moduledoc "Redirect old paths to new locations."

  use ZentinelAgentSdk.Agent

  alias ZentinelAgentSdk.{Decision, Request}

  @redirects %{
    "/old-path" => "/new-path",
    "/legacy" => "/v2/api",
    "/blog" => "https://blog.example.com"
  }

  @impl true
  def name, do: "redirect-agent"

  @impl true
  def on_request(request) do
    path = Request.path_only(request)

    case Map.get(@redirects, path) do
      nil ->
        # Check for HTTP to HTTPS redirect
        maybe_https_redirect(request)

      new_location ->
        Decision.redirect(new_location)
    end
  end

  defp maybe_https_redirect(request) do
    proto = Request.header(request, "x-forwarded-proto")

    if proto == "http" do
      host = Request.host(request)
      uri = Request.uri(request)
      https_url = "https://#{host}#{uri}"
      Decision.redirect_permanent(https_url)
    else
      Decision.allow()
    end
  end
end
```

## Combining Multiple Checks

Agent that performs multiple validations:

```elixir
defmodule SecurityAgent do
  @moduledoc "Comprehensive security checks."

  use ZentinelAgentSdk.Agent

  alias ZentinelAgentSdk.{Decision, Request}

  @suspicious_patterns ["/..", "/etc/", "/proc/", ".php"]

  @impl true
  def name, do: "security-agent"

  @impl true
  def on_request(request) do
    with :ok <- check_user_agent(request),
         :ok <- check_path_traversal(request),
         :ok <- check_content_length(request) do
      Decision.allow()
      |> Decision.with_tag("security-passed")
      |> Decision.add_response_header("X-Security-Check", "passed")
    end
  end

  defp check_user_agent(request) do
    if Request.user_agent(request) do
      :ok
    else
      {:halt, Decision.block(400) |> Decision.with_body("User-Agent required")}
    end
  end

  defp check_path_traversal(request) do
    path = Request.path_only(request) |> String.downcase()

    suspicious? = Enum.any?(@suspicious_patterns, fn pattern ->
      String.contains?(path, pattern)
    end)

    if suspicious? do
      {:halt,
        Decision.deny()
        |> Decision.with_tag("path-traversal")
        |> Decision.with_rule_id("SEC-001")}
    else
      :ok
    end
  end

  defp check_content_length(request) do
    method = Request.method(request)

    if method in ["POST", "PUT"] and not Request.has_header?(request, "content-length") do
      {:halt, Decision.block(411) |> Decision.with_body("Content-Length required")}
    else
      :ok
    end
  end
end
```
