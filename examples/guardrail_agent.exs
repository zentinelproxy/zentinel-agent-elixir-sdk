#!/usr/bin/env elixir
# Guardrail agent example for AI content safety.
#
# This example demonstrates a guardrail agent that:
# - Detects prompt injection attempts in user input
# - Detects PII (emails, phone numbers, SSN patterns)
# - Returns structured detection results with confidence scores
#
# Run with: elixir examples/guardrail_agent.exs
# Or: mix run examples/guardrail_agent.exs

Mix.install([
  {:zentinel_agent_sdk, path: "."}
])

defmodule GuardrailAgent do
  @moduledoc """
  An agent that inspects content for prompt injection and PII.
  """

  use ZentinelAgentSdk.Agent

  alias ZentinelAgentSdk.Protocol.{
    GuardrailInspectEvent,
    GuardrailResponse,
    GuardrailDetection,
    TextSpan
  }

  # Prompt injection patterns
  @injection_patterns [
    {~r/ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)/i, "ignore_instructions"},
    {~r/disregard\s+(all\s+)?(previous|prior|above)/i, "disregard_previous"},
    {~r/you\s+are\s+now\s+(a|an|in)\s+/i, "role_switch"},
    {~r/pretend\s+(you('re|are)|to\s+be)/i, "pretend_role"},
    {~r/system\s*:\s*/i, "system_prompt_inject"},
    {~r/\[INST\]|\[\/INST\]|<<SYS>>|<<\/SYS>>/, "llama_format_inject"},
    {~r/<\|im_start\|>|<\|im_end\|>/, "chatml_format_inject"}
  ]

  # PII patterns
  @pii_patterns [
    {~r/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/, "email", "Email address"},
    {~r/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/, "phone", "Phone number"},
    {~r/\b\d{3}[-]?\d{2}[-]?\d{4}\b/, "ssn", "Social Security Number"},
    {~r/\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/, "credit_card", "Credit card number"}
  ]

  @impl true
  def name, do: "guardrail-agent"

  @impl true
  def on_request(_request) do
    # Allow all requests - guardrail inspection happens via on_guardrail_inspect
    Decision.allow()
  end

  @impl true
  def on_guardrail_inspect(%GuardrailInspectEvent{} = event) do
    case event.inspection_type do
      :prompt_injection -> detect_prompt_injection(event.content)
      :pii_detection -> detect_pii(event.content)
      _ -> GuardrailResponse.clean()
    end
  end

  defp detect_prompt_injection(content) do
    @injection_patterns
    |> Enum.reduce(GuardrailResponse.clean(), fn {pattern, category}, response ->
      case Regex.run(pattern, content, return: :index) do
        [{start, length}] ->
          detection =
            GuardrailDetection.new(
              "prompt_injection.#{category}",
              "Potential prompt injection detected: #{String.replace(category, "_", " ")}"
            )
            |> GuardrailDetection.with_severity(:high)
            |> GuardrailDetection.with_confidence(0.85)
            |> GuardrailDetection.with_span(start, start + length)

          GuardrailResponse.add_detection(response, detection)

        _ ->
          response
      end
    end)
  end

  defp detect_pii(content) do
    {response, redacted} =
      @pii_patterns
      |> Enum.reduce({GuardrailResponse.clean(), content}, fn {pattern, category, description},
                                                              {response, redacted} ->
        matches = Regex.scan(pattern, content, return: :index) |> List.flatten()

        Enum.reduce(matches, {response, redacted}, fn {start, length}, {resp, red} ->
          matched = String.slice(content, start, length)

          detection =
            GuardrailDetection.new("pii.#{category}", "#{description} detected")
            |> GuardrailDetection.with_severity(:medium)
            |> GuardrailDetection.with_confidence(0.95)
            |> GuardrailDetection.with_span(start, start + length)

          new_resp = GuardrailResponse.add_detection(resp, detection)
          new_red = String.replace(red, matched, "[REDACTED_#{String.upcase(category)}]", global: false)

          {new_resp, new_red}
        end)
      end)

    if response.detected do
      GuardrailResponse.with_redacted_content(response, redacted)
    else
      response
    end
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
ZentinelAgentSdk.run(GuardrailAgent,
  socket: socket,
  log_level: log_level,
  json_logs: json_logs
)
