defmodule ZentinelAgentSdk.V2.Types do
  @moduledoc """
  V2 protocol types for Zentinel agent communication.

  These types support the enhanced v2 protocol features including:
  - Agent capabilities declaration
  - Health status reporting
  - Metrics collection
  - Handshake negotiation
  """

  # ============================================================================
  # Health Status
  # ============================================================================

  defmodule HealthStatus do
    @moduledoc """
    Health status for v2 agents.

    Reports the current health state of the agent to the proxy.
    The proxy uses this information for load balancing and circuit breaking.

    ## Health States

    - `:healthy` - Agent is operating normally
    - `:degraded` - Agent is functional but with reduced capacity
    - `:unhealthy` - Agent cannot process requests

    ## Example

        HealthStatus.healthy()
        |> HealthStatus.with_message("All systems operational")

        HealthStatus.degraded()
        |> HealthStatus.with_message("High memory usage")
        |> HealthStatus.with_metadata("memory_percent", 85)
    """

    @type health_state :: :healthy | :degraded | :unhealthy

    @type t :: %__MODULE__{
            status: health_state(),
            message: String.t() | nil,
            metadata: map(),
            timestamp: DateTime.t()
          }

    defstruct status: :healthy,
              message: nil,
              metadata: %{},
              timestamp: nil

    @doc "Create a healthy status."
    @spec healthy() :: t()
    def healthy do
      %__MODULE__{
        status: :healthy,
        timestamp: DateTime.utc_now()
      }
    end

    @doc "Create a degraded status."
    @spec degraded() :: t()
    def degraded do
      %__MODULE__{
        status: :degraded,
        timestamp: DateTime.utc_now()
      }
    end

    @doc "Create an unhealthy status."
    @spec unhealthy() :: t()
    def unhealthy do
      %__MODULE__{
        status: :unhealthy,
        timestamp: DateTime.utc_now()
      }
    end

    @doc "Set a status message."
    @spec with_message(t(), String.t()) :: t()
    def with_message(%__MODULE__{} = health, message) do
      %{health | message: message}
    end

    @doc "Add metadata to the health status."
    @spec with_metadata(t(), String.t(), term()) :: t()
    def with_metadata(%__MODULE__{metadata: metadata} = health, key, value) do
      %{health | metadata: Map.put(metadata, key, value)}
    end

    @doc "Check if the agent is healthy."
    @spec healthy?(t()) :: boolean()
    def healthy?(%__MODULE__{status: :healthy}), do: true
    def healthy?(_), do: false

    @doc "Check if the agent can process requests (healthy or degraded)."
    @spec can_process?(t()) :: boolean()
    def can_process?(%__MODULE__{status: status}) when status in [:healthy, :degraded], do: true
    def can_process?(_), do: false

    @doc "Convert to map for serialization."
    @spec to_map(t()) :: map()
    def to_map(%__MODULE__{} = health) do
      result = %{
        "status" => Atom.to_string(health.status),
        "timestamp" => DateTime.to_iso8601(health.timestamp || DateTime.utc_now())
      }

      result = if health.message, do: Map.put(result, "message", health.message), else: result

      if map_size(health.metadata) > 0 do
        Map.put(result, "metadata", health.metadata)
      else
        result
      end
    end

    @doc "Create from a map."
    @spec from_map(map()) :: t()
    def from_map(data) when is_map(data) do
      status =
        case Map.get(data, "status", "healthy") do
          "healthy" -> :healthy
          "degraded" -> :degraded
          "unhealthy" -> :unhealthy
          other when is_atom(other) -> other
          other -> String.to_atom(other)
        end

      timestamp =
        case Map.get(data, "timestamp") do
          nil -> DateTime.utc_now()
          ts when is_binary(ts) -> DateTime.from_iso8601(ts) |> elem(1)
          ts -> ts
        end

      %__MODULE__{
        status: status,
        message: Map.get(data, "message"),
        metadata: Map.get(data, "metadata", %{}),
        timestamp: timestamp
      }
    end
  end

  # ============================================================================
  # Agent Capabilities
  # ============================================================================

  defmodule AgentCapabilities do
    @moduledoc """
    Declares agent capabilities for v2 protocol negotiation.

    Capabilities are exchanged during handshake to inform the proxy
    what features the agent supports.

    ## Example

        AgentCapabilities.new()
        |> AgentCapabilities.with_name("my-waf-agent")
        |> AgentCapabilities.with_version("1.0.0")
        |> AgentCapabilities.handles_request_body()
        |> AgentCapabilities.handles_response_headers()
        |> AgentCapabilities.with_max_concurrent_requests(100)
        |> AgentCapabilities.supports_streaming()
        |> AgentCapabilities.supports_cancellation()
    """

    @type t :: %__MODULE__{
            agent_name: String.t(),
            agent_version: String.t(),
            protocol_version: integer(),
            handles_request_headers: boolean(),
            handles_request_body: boolean(),
            handles_response_headers: boolean(),
            handles_response_body: boolean(),
            handles_websocket_frames: boolean(),
            handles_guardrail_inspect: boolean(),
            max_concurrent_requests: integer() | nil,
            supports_streaming: boolean(),
            supports_cancellation: boolean(),
            supports_health_check: boolean(),
            supports_metrics: boolean(),
            custom: map()
          }

    defstruct agent_name: "unnamed-agent",
              agent_version: "0.0.0",
              protocol_version: 2,
              handles_request_headers: true,
              handles_request_body: false,
              handles_response_headers: false,
              handles_response_body: false,
              handles_websocket_frames: false,
              handles_guardrail_inspect: false,
              max_concurrent_requests: nil,
              supports_streaming: false,
              supports_cancellation: true,
              supports_health_check: true,
              supports_metrics: false,
              custom: %{}

    @doc "Create new capabilities with defaults."
    @spec new() :: t()
    def new, do: %__MODULE__{}

    @doc "Set the agent name."
    @spec with_name(t(), String.t()) :: t()
    def with_name(%__MODULE__{} = caps, name), do: %{caps | agent_name: name}

    @doc "Set the agent version."
    @spec with_version(t(), String.t()) :: t()
    def with_version(%__MODULE__{} = caps, version), do: %{caps | agent_version: version}

    @doc "Enable request headers handling (enabled by default)."
    @spec handles_request_headers(t()) :: t()
    def handles_request_headers(%__MODULE__{} = caps),
      do: %{caps | handles_request_headers: true}

    @doc "Enable request body handling."
    @spec handles_request_body(t()) :: t()
    def handles_request_body(%__MODULE__{} = caps),
      do: %{caps | handles_request_body: true}

    @doc "Enable response headers handling."
    @spec handles_response_headers(t()) :: t()
    def handles_response_headers(%__MODULE__{} = caps),
      do: %{caps | handles_response_headers: true}

    @doc "Enable response body handling."
    @spec handles_response_body(t()) :: t()
    def handles_response_body(%__MODULE__{} = caps),
      do: %{caps | handles_response_body: true}

    @doc "Enable WebSocket frame handling."
    @spec handles_websocket_frames(t()) :: t()
    def handles_websocket_frames(%__MODULE__{} = caps),
      do: %{caps | handles_websocket_frames: true}

    @doc "Enable guardrail inspection handling."
    @spec handles_guardrail_inspect(t()) :: t()
    def handles_guardrail_inspect(%__MODULE__{} = caps),
      do: %{caps | handles_guardrail_inspect: true}

    @doc "Set maximum concurrent requests the agent can handle."
    @spec with_max_concurrent_requests(t(), integer()) :: t()
    def with_max_concurrent_requests(%__MODULE__{} = caps, max),
      do: %{caps | max_concurrent_requests: max}

    @doc "Enable streaming support."
    @spec supports_streaming(t()) :: t()
    def supports_streaming(%__MODULE__{} = caps),
      do: %{caps | supports_streaming: true}

    @doc "Enable request cancellation support."
    @spec supports_cancellation(t()) :: t()
    def supports_cancellation(%__MODULE__{} = caps),
      do: %{caps | supports_cancellation: true}

    @doc "Enable health check support."
    @spec supports_health_check(t()) :: t()
    def supports_health_check(%__MODULE__{} = caps),
      do: %{caps | supports_health_check: true}

    @doc "Enable metrics reporting support."
    @spec supports_metrics(t()) :: t()
    def supports_metrics(%__MODULE__{} = caps),
      do: %{caps | supports_metrics: true}

    @doc "Add custom capability metadata."
    @spec with_custom(t(), String.t(), term()) :: t()
    def with_custom(%__MODULE__{custom: custom} = caps, key, value),
      do: %{caps | custom: Map.put(custom, key, value)}

    @doc "Convert to map for serialization."
    @spec to_map(t()) :: map()
    def to_map(%__MODULE__{} = caps) do
      result = %{
        "agent_name" => caps.agent_name,
        "agent_version" => caps.agent_version,
        "protocol_version" => caps.protocol_version,
        "handles_request_headers" => caps.handles_request_headers,
        "handles_request_body" => caps.handles_request_body,
        "handles_response_headers" => caps.handles_response_headers,
        "handles_response_body" => caps.handles_response_body,
        "handles_websocket_frames" => caps.handles_websocket_frames,
        "handles_guardrail_inspect" => caps.handles_guardrail_inspect,
        "supports_streaming" => caps.supports_streaming,
        "supports_cancellation" => caps.supports_cancellation,
        "supports_health_check" => caps.supports_health_check,
        "supports_metrics" => caps.supports_metrics
      }

      result =
        if caps.max_concurrent_requests,
          do: Map.put(result, "max_concurrent_requests", caps.max_concurrent_requests),
          else: result

      if map_size(caps.custom) > 0 do
        Map.put(result, "custom", caps.custom)
      else
        result
      end
    end

    @doc "Create from a map."
    @spec from_map(map()) :: t()
    def from_map(data) when is_map(data) do
      %__MODULE__{
        agent_name: Map.get(data, "agent_name", "unnamed-agent"),
        agent_version: Map.get(data, "agent_version", "0.0.0"),
        protocol_version: Map.get(data, "protocol_version", 2),
        handles_request_headers: Map.get(data, "handles_request_headers", true),
        handles_request_body: Map.get(data, "handles_request_body", false),
        handles_response_headers: Map.get(data, "handles_response_headers", false),
        handles_response_body: Map.get(data, "handles_response_body", false),
        handles_websocket_frames: Map.get(data, "handles_websocket_frames", false),
        handles_guardrail_inspect: Map.get(data, "handles_guardrail_inspect", false),
        max_concurrent_requests: Map.get(data, "max_concurrent_requests"),
        supports_streaming: Map.get(data, "supports_streaming", false),
        supports_cancellation: Map.get(data, "supports_cancellation", true),
        supports_health_check: Map.get(data, "supports_health_check", true),
        supports_metrics: Map.get(data, "supports_metrics", false),
        custom: Map.get(data, "custom", %{})
      }
    end
  end

  # ============================================================================
  # Handshake Types
  # ============================================================================

  defmodule HandshakeRequest do
    @moduledoc """
    Handshake request sent by the agent during connection setup.

    The agent sends this message to register itself with the proxy
    and declare its capabilities.

    ## Example

        HandshakeRequest.new(capabilities)
        |> HandshakeRequest.with_auth_token("secret-token")
    """

    @type t :: %__MODULE__{
            capabilities: AgentCapabilities.t(),
            auth_token: String.t() | nil,
            metadata: map()
          }

    defstruct capabilities: %AgentCapabilities{},
              auth_token: nil,
              metadata: %{}

    @doc "Create a new handshake request."
    @spec new(AgentCapabilities.t()) :: t()
    def new(%AgentCapabilities{} = capabilities) do
      %__MODULE__{capabilities: capabilities}
    end

    @doc "Set authentication token."
    @spec with_auth_token(t(), String.t()) :: t()
    def with_auth_token(%__MODULE__{} = request, token),
      do: %{request | auth_token: token}

    @doc "Add metadata to the handshake."
    @spec with_metadata(t(), String.t(), term()) :: t()
    def with_metadata(%__MODULE__{metadata: metadata} = request, key, value),
      do: %{request | metadata: Map.put(metadata, key, value)}

    @doc "Convert to map for serialization."
    @spec to_map(t()) :: map()
    def to_map(%__MODULE__{} = request) do
      result = %{
        "capabilities" => AgentCapabilities.to_map(request.capabilities)
      }

      result =
        if request.auth_token,
          do: Map.put(result, "auth_token", request.auth_token),
          else: result

      if map_size(request.metadata) > 0 do
        Map.put(result, "metadata", request.metadata)
      else
        result
      end
    end

    @doc "Create from a map."
    @spec from_map(map()) :: t()
    def from_map(data) when is_map(data) do
      caps =
        case Map.get(data, "capabilities") do
          nil -> %AgentCapabilities{}
          caps_data -> AgentCapabilities.from_map(caps_data)
        end

      %__MODULE__{
        capabilities: caps,
        auth_token: Map.get(data, "auth_token"),
        metadata: Map.get(data, "metadata", %{})
      }
    end
  end

  defmodule HandshakeResponse do
    @moduledoc """
    Handshake response sent by the proxy to the agent.

    Contains the result of registration and any configuration
    the agent should use.

    ## Example

        # Successful handshake
        HandshakeResponse.accepted()
        |> HandshakeResponse.with_agent_id("waf-1234")
        |> HandshakeResponse.with_config(%{"rate_limit" => 100})

        # Rejected handshake
        HandshakeResponse.rejected("Authentication failed")
    """

    @type t :: %__MODULE__{
            accepted: boolean(),
            agent_id: String.t() | nil,
            error: String.t() | nil,
            config: map(),
            proxy_version: String.t() | nil,
            metadata: map()
          }

    defstruct accepted: false,
              agent_id: nil,
              error: nil,
              config: %{},
              proxy_version: nil,
              metadata: %{}

    @doc "Create an accepted handshake response."
    @spec accepted() :: t()
    def accepted, do: %__MODULE__{accepted: true}

    @doc "Create a rejected handshake response."
    @spec rejected(String.t()) :: t()
    def rejected(error), do: %__MODULE__{accepted: false, error: error}

    @doc "Set the agent ID assigned by the proxy."
    @spec with_agent_id(t(), String.t()) :: t()
    def with_agent_id(%__MODULE__{} = response, agent_id),
      do: %{response | agent_id: agent_id}

    @doc "Set configuration for the agent."
    @spec with_config(t(), map()) :: t()
    def with_config(%__MODULE__{} = response, config),
      do: %{response | config: config}

    @doc "Set the proxy version."
    @spec with_proxy_version(t(), String.t()) :: t()
    def with_proxy_version(%__MODULE__{} = response, version),
      do: %{response | proxy_version: version}

    @doc "Add metadata to the response."
    @spec with_metadata(t(), String.t(), term()) :: t()
    def with_metadata(%__MODULE__{metadata: metadata} = response, key, value),
      do: %{response | metadata: Map.put(metadata, key, value)}

    @doc "Check if handshake was accepted."
    @spec accepted?(t()) :: boolean()
    def accepted?(%__MODULE__{accepted: true}), do: true
    def accepted?(_), do: false

    @doc "Convert to map for serialization."
    @spec to_map(t()) :: map()
    def to_map(%__MODULE__{} = response) do
      result = %{"accepted" => response.accepted}

      result =
        if response.agent_id, do: Map.put(result, "agent_id", response.agent_id), else: result

      result = if response.error, do: Map.put(result, "error", response.error), else: result

      result =
        if map_size(response.config) > 0,
          do: Map.put(result, "config", response.config),
          else: result

      result =
        if response.proxy_version,
          do: Map.put(result, "proxy_version", response.proxy_version),
          else: result

      if map_size(response.metadata) > 0 do
        Map.put(result, "metadata", response.metadata)
      else
        result
      end
    end

    @doc "Create from a map."
    @spec from_map(map()) :: t()
    def from_map(data) when is_map(data) do
      %__MODULE__{
        accepted: Map.get(data, "accepted", false),
        agent_id: Map.get(data, "agent_id"),
        error: Map.get(data, "error"),
        config: Map.get(data, "config", %{}),
        proxy_version: Map.get(data, "proxy_version"),
        metadata: Map.get(data, "metadata", %{})
      }
    end
  end

  # ============================================================================
  # Metrics Types
  # ============================================================================

  defmodule MetricsReport do
    @moduledoc """
    Metrics report for v2 agents.

    Agents can report metrics to the proxy for centralized monitoring
    and alerting.

    ## Example

        MetricsReport.new()
        |> MetricsReport.counter("requests_processed", 1234)
        |> MetricsReport.gauge("active_connections", 42)
        |> MetricsReport.histogram("request_latency_ms", [1, 2, 5, 10, 50])
        |> MetricsReport.with_labels(%{"agent" => "waf-1"})
    """

    @type metric_type :: :counter | :gauge | :histogram

    @type metric :: %{
            name: String.t(),
            type: metric_type(),
            value: number() | [number()],
            labels: map()
          }

    @type t :: %__MODULE__{
            metrics: [metric()],
            timestamp: DateTime.t(),
            labels: map()
          }

    defstruct metrics: [],
              timestamp: nil,
              labels: %{}

    @doc "Create a new metrics report."
    @spec new() :: t()
    def new, do: %__MODULE__{timestamp: DateTime.utc_now()}

    @doc "Add a counter metric."
    @spec counter(t(), String.t(), number(), map()) :: t()
    def counter(%__MODULE__{metrics: metrics} = report, name, value, labels \\ %{}) do
      metric = %{name: name, type: :counter, value: value, labels: labels}
      %{report | metrics: metrics ++ [metric]}
    end

    @doc "Add a gauge metric."
    @spec gauge(t(), String.t(), number(), map()) :: t()
    def gauge(%__MODULE__{metrics: metrics} = report, name, value, labels \\ %{}) do
      metric = %{name: name, type: :gauge, value: value, labels: labels}
      %{report | metrics: metrics ++ [metric]}
    end

    @doc "Add a histogram metric (list of observed values)."
    @spec histogram(t(), String.t(), [number()], map()) :: t()
    def histogram(%__MODULE__{metrics: metrics} = report, name, values, labels \\ %{}) do
      metric = %{name: name, type: :histogram, value: values, labels: labels}
      %{report | metrics: metrics ++ [metric]}
    end

    @doc "Set global labels applied to all metrics."
    @spec with_labels(t(), map()) :: t()
    def with_labels(%__MODULE__{} = report, labels),
      do: %{report | labels: labels}

    @doc "Convert to map for serialization."
    @spec to_map(t()) :: map()
    def to_map(%__MODULE__{} = report) do
      metrics =
        Enum.map(report.metrics, fn m ->
          %{
            "name" => m.name,
            "type" => Atom.to_string(m.type),
            "value" => m.value,
            "labels" => m.labels
          }
        end)

      result = %{
        "metrics" => metrics,
        "timestamp" => DateTime.to_iso8601(report.timestamp || DateTime.utc_now())
      }

      if map_size(report.labels) > 0 do
        Map.put(result, "labels", report.labels)
      else
        result
      end
    end

    @doc "Create from a map."
    @spec from_map(map()) :: t()
    def from_map(data) when is_map(data) do
      metrics =
        data
        |> Map.get("metrics", [])
        |> Enum.map(fn m ->
          type =
            case Map.get(m, "type", "counter") do
              "counter" -> :counter
              "gauge" -> :gauge
              "histogram" -> :histogram
              other when is_atom(other) -> other
              other -> String.to_atom(other)
            end

          %{
            name: Map.get(m, "name", ""),
            type: type,
            value: Map.get(m, "value", 0),
            labels: Map.get(m, "labels", %{})
          }
        end)

      timestamp =
        case Map.get(data, "timestamp") do
          nil -> DateTime.utc_now()
          ts when is_binary(ts) -> DateTime.from_iso8601(ts) |> elem(1)
          ts -> ts
        end

      %__MODULE__{
        metrics: metrics,
        timestamp: timestamp,
        labels: Map.get(data, "labels", %{})
      }
    end
  end

  # ============================================================================
  # Cancellation Types
  # ============================================================================

  defmodule CancelRequest do
    @moduledoc """
    Request to cancel an in-flight request.

    Used by the proxy to signal that a request should be aborted,
    typically due to client disconnect or timeout.
    """

    @type t :: %__MODULE__{
            request_id: integer(),
            correlation_id: String.t() | nil,
            reason: String.t() | nil
          }

    defstruct request_id: 0,
              correlation_id: nil,
              reason: nil

    @doc "Create a cancel request."
    @spec new(integer()) :: t()
    def new(request_id), do: %__MODULE__{request_id: request_id}

    @doc "Set the correlation ID."
    @spec with_correlation_id(t(), String.t()) :: t()
    def with_correlation_id(%__MODULE__{} = req, id),
      do: %{req | correlation_id: id}

    @doc "Set the cancellation reason."
    @spec with_reason(t(), String.t()) :: t()
    def with_reason(%__MODULE__{} = req, reason),
      do: %{req | reason: reason}

    @doc "Convert to map for serialization."
    @spec to_map(t()) :: map()
    def to_map(%__MODULE__{} = req) do
      result = %{"request_id" => req.request_id}

      result =
        if req.correlation_id,
          do: Map.put(result, "correlation_id", req.correlation_id),
          else: result

      if req.reason do
        Map.put(result, "reason", req.reason)
      else
        result
      end
    end

    @doc "Create from a map."
    @spec from_map(map()) :: t()
    def from_map(data) when is_map(data) do
      %__MODULE__{
        request_id: Map.get(data, "request_id", 0),
        correlation_id: Map.get(data, "correlation_id"),
        reason: Map.get(data, "reason")
      }
    end
  end

  # ============================================================================
  # Drain Types
  # ============================================================================

  defmodule DrainRequest do
    @moduledoc """
    Request to drain the agent (stop accepting new requests).

    Used during graceful shutdown to allow in-flight requests
    to complete before the agent stops.
    """

    @type t :: %__MODULE__{
            timeout_ms: integer(),
            reason: String.t() | nil
          }

    defstruct timeout_ms: 30_000,
              reason: nil

    @doc "Create a drain request with timeout in milliseconds."
    @spec new(integer()) :: t()
    def new(timeout_ms \\ 30_000), do: %__MODULE__{timeout_ms: timeout_ms}

    @doc "Set the drain reason."
    @spec with_reason(t(), String.t()) :: t()
    def with_reason(%__MODULE__{} = req, reason),
      do: %{req | reason: reason}

    @doc "Convert to map for serialization."
    @spec to_map(t()) :: map()
    def to_map(%__MODULE__{} = req) do
      result = %{"timeout_ms" => req.timeout_ms}

      if req.reason do
        Map.put(result, "reason", req.reason)
      else
        result
      end
    end

    @doc "Create from a map."
    @spec from_map(map()) :: t()
    def from_map(data) when is_map(data) do
      %__MODULE__{
        timeout_ms: Map.get(data, "timeout_ms", 30_000),
        reason: Map.get(data, "reason")
      }
    end
  end
end
