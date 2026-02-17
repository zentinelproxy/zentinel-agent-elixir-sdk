#!/usr/bin/env elixir
# Body inspection Zentinel agent example.
#
# This example demonstrates an agent that:
# - Inspects request bodies for sensitive data patterns
# - Blocks requests containing potential secrets
# - Logs suspicious activity
#
# Run with: elixir examples/body_inspection_agent.exs
# Or: mix run examples/body_inspection_agent.exs

Mix.install([
  {:zentinel_agent_sdk, path: "."}
])

defmodule BodyInspectionAgent do
  @moduledoc """
  An agent that inspects request bodies for sensitive data.
  """

  use ZentinelAgentSdk.Agent

  # Patterns that might indicate sensitive data
  @sensitive_patterns [
    # AWS credentials
    ~r/AKIA[0-9A-Z]{16}/,
    # Generic API keys
    ~r/api[_-]?key["\s:=]+["']?[a-zA-Z0-9]{32,}/i,
    # Private keys
    ~r/-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    # Credit card numbers (basic pattern)
    ~r/\b(?:\d{4}[-\s]?){3}\d{4}\b/,
    # Social Security Numbers
    ~r/\b\d{3}-\d{2}-\d{4}\b/
  ]

  @impl true
  def name, do: "body-inspection-agent"

  @impl true
  def on_request(request) do
    # For POST/PUT/PATCH requests with body, we need to inspect the body
    if has_body?(request) do
      Decision.allow()
      |> Decision.needs_more_data()
    else
      Decision.allow()
    end
  end

  @impl true
  def on_request_body(request) do
    body = Request.body_str(request)

    case find_sensitive_data(body) do
      nil ->
        Decision.allow()
        |> Decision.with_tag("body-inspected")

      pattern_name ->
        IO.puts("Blocked request containing sensitive data: #{pattern_name}")

        Decision.block(400)
        |> Decision.with_body("Request blocked: contains potentially sensitive data")
        |> Decision.with_tag("sensitive-data-detected")
        |> Decision.with_tag(pattern_name)
        |> Decision.with_rule_id("SENSITIVE_DATA_BLOCK")
        |> Decision.with_confidence(0.9)
    end
  end

  @impl true
  def on_response(request, response) do
    # Optionally inspect response bodies for data leakage
    if Response.is_json?(response) or Response.is_html?(response) do
      Decision.allow()
      |> Decision.needs_more_data()
    else
      Decision.allow()
    end
  end

  @impl true
  def on_response_body(request, response) do
    body = Response.body_str(response)

    case find_sensitive_data(body) do
      nil ->
        Decision.allow()

      pattern_name ->
        # Log but don't block responses - just add warning header
        IO.puts("Warning: Response may contain sensitive data: #{pattern_name}")

        Decision.allow()
        |> Decision.with_tag("sensitive-data-in-response")
        |> Decision.with_tag(pattern_name)
        |> Decision.add_response_header("X-Data-Warning", "potential-sensitive-data")
    end
  end

  defp has_body?(request) do
    method = Request.method(request) |> String.upcase()
    content_length = Request.content_length(request)

    method in ["POST", "PUT", "PATCH"] and
      (content_length == nil or content_length > 0)
  end

  defp find_sensitive_data(body) when is_binary(body) do
    Enum.find_value(@sensitive_patterns, fn {pattern, name} ->
      if Regex.match?(pattern, body), do: name
    end) ||
      Enum.find_value(pattern_with_names(), fn {pattern, name} ->
        if Regex.match?(pattern, body), do: name
      end)
  end

  defp pattern_with_names do
    [
      {~r/AKIA[0-9A-Z]{16}/, "aws-access-key"},
      {~r/api[_-]?key["\s:=]+["']?[a-zA-Z0-9]{32,}/i, "api-key"},
      {~r/-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/, "private-key"},
      {~r/\b(?:\d{4}[-\s]?){3}\d{4}\b/, "credit-card"},
      {~r/\b\d{3}-\d{2}-\d{4}\b/, "ssn"}
    ]
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
ZentinelAgentSdk.run(BodyInspectionAgent,
  socket: socket,
  log_level: log_level,
  json_logs: json_logs
)
