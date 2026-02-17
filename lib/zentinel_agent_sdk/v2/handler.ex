defmodule ZentinelAgentSdk.V2.Handler do
  @moduledoc """
  GenServer that bridges V2 agents to the protocol layer.

  Manages:
  - Request state tracking
  - Body chunk accumulation
  - Lifecycle event dispatching
  - Health check responses
  - Metrics collection
  - Request cancellation

  This handler is used internally by the V2 runner and should not
  be used directly. Use `ZentinelAgentSdk.V2.Runner` instead.
  """

  use GenServer

  require Logger

  alias ZentinelAgentSdk.{Decision, Request, Response}

  alias ZentinelAgentSdk.V2.Types.{
    AgentCapabilities,
    CancelRequest,
    DrainRequest,
    HandshakeRequest,
    HandshakeResponse,
    HealthStatus,
    MetricsReport
  }

  alias ZentinelAgentSdk.Protocol.{
    ConfigureEvent,
    GuardrailInspectEvent,
    GuardrailResponse,
    RequestBodyChunkEvent,
    RequestCompleteEvent,
    RequestHeadersEvent,
    ResponseBodyChunkEvent,
    ResponseHeadersEvent
  }

  # ============================================================================
  # State
  # ============================================================================

  defmodule State do
    @moduledoc false

    @type t :: %__MODULE__{
            agent_module: module(),
            agent_config: term(),
            capabilities: AgentCapabilities.t(),
            is_configurable: boolean(),
            requests: %{String.t() => Request.t()},
            request_bodies: %{String.t() => binary()},
            response_bodies: %{String.t() => binary()},
            response_events: %{String.t() => ResponseHeadersEvent.t()},
            pending_requests: MapSet.t(),
            cancelled_requests: MapSet.t(),
            draining: boolean(),
            drain_timeout: integer() | nil,
            handshake_complete: boolean()
          }

    defstruct agent_module: nil,
              agent_config: nil,
              capabilities: %AgentCapabilities{},
              is_configurable: false,
              requests: %{},
              request_bodies: %{},
              response_bodies: %{},
              response_events: %{},
              pending_requests: MapSet.new(),
              cancelled_requests: MapSet.new(),
              draining: false,
              drain_timeout: nil,
              handshake_complete: false
  end

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Start the handler for a V2 agent module.
  """
  @spec start_link(module(), keyword()) :: GenServer.on_start()
  def start_link(agent_module, opts \\ []) do
    GenServer.start_link(__MODULE__, {agent_module, opts}, name: opts[:name])
  end

  @doc """
  Handle an incoming event and return the response.
  """
  @spec handle_event(GenServer.server(), map()) :: map()
  def handle_event(handler, event) do
    GenServer.call(handler, {:event, event})
  end

  @doc """
  Get the agent's capabilities.
  """
  @spec get_capabilities(GenServer.server()) :: AgentCapabilities.t()
  def get_capabilities(handler) do
    GenServer.call(handler, :get_capabilities)
  end

  @doc """
  Get the agent's health status.
  """
  @spec get_health(GenServer.server()) :: HealthStatus.t()
  def get_health(handler) do
    GenServer.call(handler, :get_health)
  end

  @doc """
  Get the agent's metrics.
  """
  @spec get_metrics(GenServer.server()) :: MetricsReport.t()
  def get_metrics(handler) do
    GenServer.call(handler, :get_metrics)
  end

  @doc """
  Get the handshake request to send to the proxy.
  """
  @spec get_handshake_request(GenServer.server(), String.t() | nil) :: HandshakeRequest.t()
  def get_handshake_request(handler, auth_token \\ nil) do
    GenServer.call(handler, {:get_handshake_request, auth_token})
  end

  @doc """
  Process a handshake response from the proxy.
  """
  @spec handle_handshake_response(GenServer.server(), HandshakeResponse.t()) ::
          :ok | {:error, String.t()}
  def handle_handshake_response(handler, response) do
    GenServer.call(handler, {:handshake_response, response})
  end

  @doc """
  Signal the handler to drain.
  """
  @spec drain(GenServer.server(), integer(), String.t() | nil) :: :ok
  def drain(handler, timeout_ms, reason \\ nil) do
    GenServer.call(handler, {:drain, timeout_ms, reason})
  end

  @doc """
  Signal the handler to shut down.
  """
  @spec shutdown(GenServer.server()) :: :ok
  def shutdown(handler) do
    GenServer.call(handler, :shutdown)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init({agent_module, _opts}) do
    is_configurable = function_exported?(agent_module, :parse_config, 1)

    # Build capabilities from agent
    capabilities =
      if function_exported?(agent_module, :capabilities, 0) do
        caps = agent_module.capabilities()

        # Set name and version from agent if not already set
        caps =
          if caps.agent_name == "unnamed-agent" and function_exported?(agent_module, :name, 0) do
            AgentCapabilities.with_name(caps, agent_module.name())
          else
            caps
          end

        if caps.agent_version == "0.0.0" and function_exported?(agent_module, :version, 0) do
          AgentCapabilities.with_version(caps, agent_module.version())
        else
          caps
        end
      else
        # Build capabilities from what callbacks are implemented
        caps =
          AgentCapabilities.new()
          |> AgentCapabilities.with_name(agent_module.name())

        caps =
          if function_exported?(agent_module, :version, 0) do
            AgentCapabilities.with_version(caps, agent_module.version())
          else
            caps
          end

        caps =
          if function_exported?(agent_module, :on_request_body, 1) or
               function_exported?(agent_module, :on_request_body, 2) do
            AgentCapabilities.handles_request_body(caps)
          else
            caps
          end

        caps =
          if function_exported?(agent_module, :on_response, 2) or
               function_exported?(agent_module, :on_response, 3) do
            AgentCapabilities.handles_response_headers(caps)
          else
            caps
          end

        caps =
          if function_exported?(agent_module, :on_response_body, 2) or
               function_exported?(agent_module, :on_response_body, 3) do
            AgentCapabilities.handles_response_body(caps)
          else
            caps
          end

        caps =
          if function_exported?(agent_module, :on_guardrail_inspect, 1) do
            AgentCapabilities.handles_guardrail_inspect(caps)
          else
            caps
          end

        caps =
          if function_exported?(agent_module, :health_check, 0) or
               function_exported?(agent_module, :health_check, 1) do
            AgentCapabilities.supports_health_check(caps)
          else
            caps
          end

        caps =
          if function_exported?(agent_module, :metrics, 0) or
               function_exported?(agent_module, :metrics, 1) do
            AgentCapabilities.supports_metrics(caps)
          else
            caps
          end

        if function_exported?(agent_module, :on_cancel, 2) do
          AgentCapabilities.supports_cancellation(caps)
        else
          caps
        end
      end

    state = %State{
      agent_module: agent_module,
      capabilities: capabilities,
      is_configurable: is_configurable
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:event, event}, _from, state) do
    {response, new_state} = process_event(event, state)
    {:reply, response, new_state}
  end

  def handle_call(:get_capabilities, _from, state) do
    {:reply, state.capabilities, state}
  end

  def handle_call(:get_health, _from, state) do
    health = get_health_status(state)
    {:reply, health, state}
  end

  def handle_call(:get_metrics, _from, state) do
    metrics = get_metrics_report(state)
    {:reply, metrics, state}
  end

  def handle_call({:get_handshake_request, auth_token}, _from, state) do
    request = HandshakeRequest.new(state.capabilities)

    request =
      if auth_token do
        HandshakeRequest.with_auth_token(request, auth_token)
      else
        request
      end

    {:reply, request, state}
  end

  def handle_call({:handshake_response, response}, _from, state) do
    if HandshakeResponse.accepted?(response) do
      Logger.info("Handshake accepted, agent_id: #{response.agent_id}")

      # Apply config from handshake if present
      state =
        if map_size(response.config) > 0 do
          apply_config(state, response.config)
        else
          state
        end

      {:reply, :ok, %{state | handshake_complete: true}}
    else
      Logger.error("Handshake rejected: #{response.error}")
      {:reply, {:error, response.error || "Handshake rejected"}, state}
    end
  end

  def handle_call({:drain, timeout_ms, reason}, _from, state) do
    Logger.info("Drain requested: #{reason || "no reason"}, timeout: #{timeout_ms}ms")

    # Notify agent
    if function_exported?(state.agent_module, :on_drain, 2) do
      state.agent_module.on_drain(timeout_ms, reason)
    end

    {:reply, :ok, %{state | draining: true, drain_timeout: timeout_ms}}
  end

  def handle_call(:shutdown, _from, state) do
    Logger.info("Shutdown requested")

    # Notify agent
    if function_exported?(state.agent_module, :on_shutdown, 0) do
      state.agent_module.on_shutdown()
    end

    {:reply, :ok, state}
  end

  @impl true
  def terminate(_reason, state) do
    # Final cleanup
    if function_exported?(state.agent_module, :on_shutdown, 0) do
      state.agent_module.on_shutdown()
    end

    :ok
  end

  # ============================================================================
  # Event Processing
  # ============================================================================

  defp process_event(event, state) do
    # Check if draining and this is a new request
    if state.draining and is_new_request?(event) do
      # Reject new requests when draining
      {Decision.block(503)
       |> Decision.with_body("Agent is draining")
       |> Decision.to_map(), state}
    else
      do_process_event(event, state)
    end
  end

  defp is_new_request?(%{"event_type" => "request_headers"}), do: true
  defp is_new_request?(_), do: false

  defp do_process_event(event, state) do
    event_type = Map.get(event, "event_type", "")
    payload = Map.get(event, "payload", %{})

    try do
      case event_type do
        "configure" ->
          handle_configure(state, payload)

        "request_headers" ->
          handle_request_headers(state, payload)

        "request_body_chunk" ->
          handle_request_body_chunk(state, payload)

        "response_headers" ->
          handle_response_headers(state, payload)

        "response_body_chunk" ->
          handle_response_body_chunk(state, payload)

        "request_complete" ->
          handle_request_complete(state, payload)

        "guardrail_inspect" ->
          handle_guardrail_inspect(state, payload)

        "cancel" ->
          handle_cancel(state, payload)

        "drain" ->
          handle_drain_event(state, payload)

        "health_check" ->
          handle_health_check(state)

        "metrics" ->
          handle_metrics(state)

        "stream_closed" ->
          handle_stream_closed(state, payload)

        _ ->
          Logger.warning("Unknown event type: #{event_type}")
          {Decision.allow() |> Decision.to_map(), state}
      end
    rescue
      e ->
        Logger.error("Error handling event #{event_type}: #{inspect(e)}")
        {Decision.allow() |> Decision.to_map(), state}
    end
  end

  defp handle_configure(state, payload) do
    event = ConfigureEvent.from_map(payload)
    new_state = apply_config(state, event.config)
    {%{"success" => true}, new_state}
  end

  defp apply_config(state, config) do
    if state.is_configurable do
      parsed_config = state.agent_module.parse_config(config)

      if function_exported?(state.agent_module, :on_config_applied, 1) do
        state.agent_module.on_config_applied(parsed_config)
      end

      %{state | agent_config: parsed_config}
    else
      case state.agent_module.on_configure(config) do
        :ok ->
          Logger.info("Agent configured")
          state

        {:error, reason} ->
          Logger.error("Configuration failed: #{reason}")
          state
      end
    end
  end

  defp handle_request_headers(state, payload) do
    event = RequestHeadersEvent.from_map(payload)
    request = Request.new(event)
    correlation_id = event.metadata.correlation_id

    # Track request
    state = %{
      state
      | requests: Map.put(state.requests, correlation_id, request),
        request_bodies: Map.put(state.request_bodies, correlation_id, <<>>),
        pending_requests: MapSet.put(state.pending_requests, correlation_id)
    }

    # Check if already cancelled
    if MapSet.member?(state.cancelled_requests, correlation_id) do
      state = %{state | cancelled_requests: MapSet.delete(state.cancelled_requests, correlation_id)}

      {Decision.block(499)
       |> Decision.with_body("Request cancelled")
       |> Decision.to_map(), state}
    else
      decision =
        if state.is_configurable do
          state.agent_module.on_request(request, state.agent_config)
        else
          state.agent_module.on_request(request)
        end

      {Decision.to_map(decision), state}
    end
  end

  defp handle_request_body_chunk(state, payload) do
    event = RequestBodyChunkEvent.from_map(payload)
    correlation_id = event.correlation_id

    # Check if cancelled
    if MapSet.member?(state.cancelled_requests, correlation_id) do
      {Decision.block(499) |> Decision.with_body("Request cancelled") |> Decision.to_map(), state}
    else
      # Accumulate body chunks
      state =
        if Map.has_key?(state.request_bodies, correlation_id) do
          current_body = Map.get(state.request_bodies, correlation_id, <<>>)

          %{
            state
            | request_bodies:
                Map.put(state.request_bodies, correlation_id, current_body <> event.data)
          }
        else
          state
        end

      # Only call handler on last chunk
      if event.is_last and Map.has_key?(state.requests, correlation_id) do
        request =
          state.requests
          |> Map.get(correlation_id)
          |> Request.with_body(Map.get(state.request_bodies, correlation_id, <<>>))

        decision =
          if state.is_configurable do
            state.agent_module.on_request_body(request, state.agent_config)
          else
            state.agent_module.on_request_body(request)
          end

        {Decision.to_map(decision), state}
      else
        {Decision.allow() |> Decision.needs_more_data() |> Decision.to_map(), state}
      end
    end
  end

  defp handle_response_headers(state, payload) do
    event = ResponseHeadersEvent.from_map(payload)
    correlation_id = event.correlation_id

    request = Map.get(state.requests, correlation_id)

    if request == nil do
      Logger.warning("No cached request for correlation_id: #{correlation_id}")
      {Decision.allow() |> Decision.to_map(), state}
    else
      response = Response.new(event)

      state = %{
        state
        | response_bodies: Map.put(state.response_bodies, correlation_id, <<>>),
          response_events: Map.put(state.response_events, correlation_id, event)
      }

      decision =
        if state.is_configurable do
          state.agent_module.on_response(request, response, state.agent_config)
        else
          state.agent_module.on_response(request, response)
        end

      {Decision.to_map(decision), state}
    end
  end

  defp handle_response_body_chunk(state, payload) do
    event = ResponseBodyChunkEvent.from_map(payload)
    correlation_id = event.correlation_id

    # Accumulate body chunks
    state =
      if Map.has_key?(state.response_bodies, correlation_id) do
        current_body = Map.get(state.response_bodies, correlation_id, <<>>)

        %{
          state
          | response_bodies:
              Map.put(state.response_bodies, correlation_id, current_body <> event.data)
        }
      else
        state
      end

    # Only call handler on last chunk
    if event.is_last and Map.has_key?(state.requests, correlation_id) do
      request = Map.get(state.requests, correlation_id)

      response_event =
        Map.get(
          state.response_events,
          correlation_id,
          %ResponseHeadersEvent{correlation_id: correlation_id, status: 200, headers: %{}}
        )

      response =
        Response.new(response_event)
        |> Response.with_body(Map.get(state.response_bodies, correlation_id, <<>>))

      decision =
        if state.is_configurable do
          state.agent_module.on_response_body(request, response, state.agent_config)
        else
          state.agent_module.on_response_body(request, response)
        end

      {Decision.to_map(decision), state}
    else
      {Decision.allow() |> Decision.needs_more_data() |> Decision.to_map(), state}
    end
  end

  defp handle_request_complete(state, payload) do
    event = RequestCompleteEvent.from_map(payload)
    correlation_id = event.correlation_id

    request = Map.get(state.requests, correlation_id)

    # Cleanup cached data
    state = %{
      state
      | requests: Map.delete(state.requests, correlation_id),
        request_bodies: Map.delete(state.request_bodies, correlation_id),
        response_bodies: Map.delete(state.response_bodies, correlation_id),
        response_events: Map.delete(state.response_events, correlation_id),
        pending_requests: MapSet.delete(state.pending_requests, correlation_id),
        cancelled_requests: MapSet.delete(state.cancelled_requests, correlation_id)
    }

    if request != nil do
      if state.is_configurable do
        state.agent_module.on_request_complete(
          request,
          event.status,
          event.duration_ms,
          state.agent_config
        )
      else
        state.agent_module.on_request_complete(request, event.status, event.duration_ms)
      end
    end

    {%{"success" => true}, state}
  end

  defp handle_guardrail_inspect(state, payload) do
    event = GuardrailInspectEvent.from_map(payload)
    response = state.agent_module.on_guardrail_inspect(event)

    audit_response = %{
      "tags" => if(response.detected, do: ["guardrail_detected"], else: []),
      "rule_ids" => Enum.map(response.detections, & &1.category),
      "confidence" => response.confidence,
      "custom" => %{
        "guardrail_response" => GuardrailResponse.to_map(response)
      }
    }

    {%{"version" => 2, "audit" => audit_response}, state}
  end

  defp handle_cancel(state, payload) do
    cancel_request = CancelRequest.from_map(payload)

    correlation_id =
      cancel_request.correlation_id || Integer.to_string(cancel_request.request_id)

    Logger.debug("Cancel request for: #{correlation_id}")

    # Mark as cancelled
    state = %{state | cancelled_requests: MapSet.put(state.cancelled_requests, correlation_id)}

    # Notify agent if callback exists
    if function_exported?(state.agent_module, :on_cancel, 2) do
      state.agent_module.on_cancel(cancel_request.request_id, cancel_request)
    end

    {%{"success" => true}, state}
  end

  defp handle_drain_event(state, payload) do
    drain_request = DrainRequest.from_map(payload)

    Logger.info("Drain event: timeout=#{drain_request.timeout_ms}ms, reason=#{drain_request.reason}")

    # Notify agent
    if function_exported?(state.agent_module, :on_drain, 2) do
      state.agent_module.on_drain(drain_request.timeout_ms, drain_request.reason)
    end

    pending_count = MapSet.size(state.pending_requests)

    {%{"success" => true, "pending_requests" => pending_count},
     %{state | draining: true, drain_timeout: drain_request.timeout_ms}}
  end

  defp handle_health_check(state) do
    health = get_health_status(state)
    {HealthStatus.to_map(health), state}
  end

  defp get_health_status(state) do
    if state.is_configurable do
      if function_exported?(state.agent_module, :health_check, 1) do
        state.agent_module.health_check(state.agent_config)
      else
        HealthStatus.healthy()
      end
    else
      if function_exported?(state.agent_module, :health_check, 0) do
        state.agent_module.health_check()
      else
        HealthStatus.healthy()
      end
    end
  end

  defp handle_metrics(state) do
    metrics = get_metrics_report(state)
    {MetricsReport.to_map(metrics), state}
  end

  defp get_metrics_report(state) do
    if state.is_configurable do
      if function_exported?(state.agent_module, :metrics, 1) do
        state.agent_module.metrics(state.agent_config)
      else
        MetricsReport.new()
      end
    else
      if function_exported?(state.agent_module, :metrics, 0) do
        state.agent_module.metrics()
      else
        MetricsReport.new()
      end
    end
  end

  defp handle_stream_closed(state, payload) do
    correlation_id = Map.get(payload, "correlation_id", "")
    reason = Map.get(payload, "reason")

    Logger.debug("Stream closed: #{correlation_id}, reason: #{reason}")

    # Notify agent
    if function_exported?(state.agent_module, :on_stream_closed, 2) do
      state.agent_module.on_stream_closed(correlation_id, reason)
    end

    # Cleanup any state for this stream
    state = %{
      state
      | requests: Map.delete(state.requests, correlation_id),
        request_bodies: Map.delete(state.request_bodies, correlation_id),
        response_bodies: Map.delete(state.response_bodies, correlation_id),
        response_events: Map.delete(state.response_events, correlation_id),
        pending_requests: MapSet.delete(state.pending_requests, correlation_id)
    }

    {%{"success" => true}, state}
  end
end
