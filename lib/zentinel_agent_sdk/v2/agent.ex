defmodule ZentinelAgentSdk.V2.Agent do
  @moduledoc """
  V2 behaviour for Zentinel agents with enhanced capabilities.

  Extends the base Agent behaviour with v2 protocol features:
  - Capability declaration
  - Health reporting
  - Metrics collection
  - Lifecycle callbacks (shutdown, drain, stream close)
  - Request cancellation

  ## Example

      defmodule MyWafAgent do
        use ZentinelAgentSdk.V2.Agent

        @impl true
        def name, do: "waf-agent"

        @impl true
        def version, do: "1.0.0"

        @impl true
        def capabilities do
          AgentCapabilities.new()
          |> AgentCapabilities.handles_request_headers()
          |> AgentCapabilities.handles_request_body()
          |> AgentCapabilities.with_max_concurrent_requests(100)
          |> AgentCapabilities.supports_cancellation()
        end

        @impl true
        def on_request(request) do
          # WAF logic here
          Decision.allow()
        end

        @impl true
        def health_check do
          HealthStatus.healthy()
        end

        @impl true
        def on_drain(timeout_ms, reason) do
          Logger.info("Draining: \#{reason}")
          :ok
        end
      end

  ## Callbacks

  ### Required Callbacks
  - `name/0` - Agent name for identification
  - `capabilities/0` - Declare agent capabilities

  ### Optional Callbacks
  - `version/0` - Agent version string
  - `on_configure/1` - Handle configuration from proxy
  - `on_request/1` - Process request headers
  - `on_request_body/1` - Process request body
  - `on_response/2` - Process response headers
  - `on_response_body/2` - Process response body
  - `on_request_complete/3` - Request completion notification
  - `on_guardrail_inspect/1` - Guardrail content inspection
  - `on_cancel/2` - Handle request cancellation
  - `on_drain/2` - Handle drain request
  - `on_shutdown/0` - Handle shutdown signal
  - `on_stream_closed/2` - Handle stream close
  - `health_check/0` - Return current health status
  - `metrics/0` - Return current metrics
  """

  alias ZentinelAgentSdk.{Decision, Request, Response}

  alias ZentinelAgentSdk.V2.Types.{
    AgentCapabilities,
    CancelRequest,
    DrainRequest,
    HealthStatus,
    MetricsReport
  }

  alias ZentinelAgentSdk.Protocol.{GuardrailInspectEvent, GuardrailResponse}

  # ============================================================================
  # Required Callbacks
  # ============================================================================

  @doc """
  Return the agent name for logging and identification.
  """
  @callback name() :: String.t()

  @doc """
  Return the agent's capabilities declaration.

  This is called during handshake to inform the proxy what
  event types the agent handles and what features it supports.
  """
  @callback capabilities() :: AgentCapabilities.t()

  # ============================================================================
  # Optional Callbacks - Identity
  # ============================================================================

  @doc """
  Return the agent version.

  Used for debugging and observability.
  """
  @callback version() :: String.t()

  # ============================================================================
  # Optional Callbacks - Configuration
  # ============================================================================

  @doc """
  Handle configuration from the proxy.

  Called once when the agent connects to the proxy.
  Override to validate and store configuration.

  Returns `:ok` on success, `{:error, reason}` on failure.
  """
  @callback on_configure(config :: map()) :: :ok | {:error, String.t()}

  # ============================================================================
  # Optional Callbacks - Request Processing
  # ============================================================================

  @doc """
  Process incoming request headers.

  Called when request headers are received from the client.
  Override to implement request inspection and filtering.
  """
  @callback on_request(request :: Request.t()) :: Decision.t()

  @doc """
  Process request body.

  Called when request body is available (if body inspection enabled).
  Override to inspect or modify request body content.
  """
  @callback on_request_body(request :: Request.t()) :: Decision.t()

  @doc """
  Process response headers from upstream.

  Called when response headers are received from the upstream server.
  Override to inspect or modify response headers.
  """
  @callback on_response(request :: Request.t(), response :: Response.t()) :: Decision.t()

  @doc """
  Process response body.

  Called when response body is available (if body inspection enabled).
  Override to inspect or modify response body content.
  """
  @callback on_response_body(request :: Request.t(), response :: Response.t()) :: Decision.t()

  @doc """
  Called when request processing is complete.

  Override for logging, metrics, or cleanup.
  """
  @callback on_request_complete(
              request :: Request.t(),
              status :: integer(),
              duration_ms :: integer()
            ) :: :ok

  @doc """
  Inspect content for guardrail violations.

  Called when content needs to be analyzed for prompt injection
  or PII detection. Override to implement custom guardrail logic.
  """
  @callback on_guardrail_inspect(event :: GuardrailInspectEvent.t()) :: GuardrailResponse.t()

  # ============================================================================
  # Optional Callbacks - V2 Lifecycle
  # ============================================================================

  @doc """
  Handle request cancellation.

  Called when the proxy cancels an in-flight request,
  typically due to client disconnect or timeout.

  ## Parameters

  - `request_id` - The ID of the cancelled request
  - `cancel_request` - Details about the cancellation

  ## Returns

  Return `:ok` to acknowledge cancellation.
  """
  @callback on_cancel(request_id :: integer(), cancel_request :: CancelRequest.t()) :: :ok

  @doc """
  Handle drain request.

  Called when the proxy signals the agent to stop accepting
  new requests in preparation for shutdown.

  ## Parameters

  - `timeout_ms` - Maximum time to wait for in-flight requests
  - `reason` - Optional reason for the drain

  ## Returns

  Return `:ok` when ready for shutdown.
  """
  @callback on_drain(timeout_ms :: integer(), reason :: String.t() | nil) :: :ok

  @doc """
  Handle shutdown signal.

  Called when the agent should stop. This is the last callback
  before the agent process terminates.

  Use this for cleanup:
  - Close database connections
  - Flush metrics
  - Release resources

  ## Returns

  Return `:ok` when shutdown is complete.
  """
  @callback on_shutdown() :: :ok

  @doc """
  Handle stream close notification.

  Called when a streaming connection (WebSocket, SSE) is closed.

  ## Parameters

  - `correlation_id` - The ID of the closed stream
  - `reason` - Optional reason for closure

  ## Returns

  Return `:ok` to acknowledge.
  """
  @callback on_stream_closed(correlation_id :: String.t(), reason :: String.t() | nil) :: :ok

  # ============================================================================
  # Optional Callbacks - Health & Metrics
  # ============================================================================

  @doc """
  Return the current health status.

  Called periodically by the proxy to check agent health.
  Override to implement custom health logic.

  ## Example

      def health_check do
        if database_connected?() do
          HealthStatus.healthy()
        else
          HealthStatus.unhealthy()
          |> HealthStatus.with_message("Database unavailable")
        end
      end
  """
  @callback health_check() :: HealthStatus.t()

  @doc """
  Return current metrics.

  Called periodically when metrics collection is enabled.
  Override to expose agent-specific metrics.

  ## Example

      def metrics do
        MetricsReport.new()
        |> MetricsReport.counter("requests_blocked", @blocked_count)
        |> MetricsReport.gauge("rules_loaded", length(@rules))
      end
  """
  @callback metrics() :: MetricsReport.t()

  # ============================================================================
  # Optional Callbacks Declaration
  # ============================================================================

  @optional_callbacks version: 0,
                      on_configure: 1,
                      on_request: 1,
                      on_request_body: 1,
                      on_response: 2,
                      on_response_body: 2,
                      on_request_complete: 3,
                      on_guardrail_inspect: 1,
                      on_cancel: 2,
                      on_drain: 2,
                      on_shutdown: 0,
                      on_stream_closed: 2,
                      health_check: 0,
                      metrics: 0

  # ============================================================================
  # __using__ Macro
  # ============================================================================

  defmacro __using__(_opts) do
    quote do
      @behaviour ZentinelAgentSdk.V2.Agent

      alias ZentinelAgentSdk.{Decision, Request, Response}

      alias ZentinelAgentSdk.V2.Types.{
        AgentCapabilities,
        CancelRequest,
        DrainRequest,
        HealthStatus,
        MetricsReport
      }

      alias ZentinelAgentSdk.Protocol.{GuardrailInspectEvent, GuardrailResponse}

      # Default implementations

      @impl true
      def version, do: "0.0.0"

      @impl true
      def on_configure(_config), do: :ok

      @impl true
      def on_request(_request), do: Decision.allow()

      @impl true
      def on_request_body(_request), do: Decision.allow()

      @impl true
      def on_response(_request, _response), do: Decision.allow()

      @impl true
      def on_response_body(_request, _response), do: Decision.allow()

      @impl true
      def on_request_complete(_request, _status, _duration_ms), do: :ok

      @impl true
      def on_guardrail_inspect(_event), do: GuardrailResponse.clean()

      @impl true
      def on_cancel(_request_id, _cancel_request), do: :ok

      @impl true
      def on_drain(_timeout_ms, _reason), do: :ok

      @impl true
      def on_shutdown, do: :ok

      @impl true
      def on_stream_closed(_correlation_id, _reason), do: :ok

      @impl true
      def health_check, do: HealthStatus.healthy()

      @impl true
      def metrics, do: MetricsReport.new()

      defoverridable version: 0,
                     on_configure: 1,
                     on_request: 1,
                     on_request_body: 1,
                     on_response: 2,
                     on_response_body: 2,
                     on_request_complete: 3,
                     on_guardrail_inspect: 1,
                     on_cancel: 2,
                     on_drain: 2,
                     on_shutdown: 0,
                     on_stream_closed: 2,
                     health_check: 0,
                     metrics: 0
    end
  end
end

defmodule ZentinelAgentSdk.V2.ConfigurableAgent do
  @moduledoc """
  V2 behaviour for agents with typed configuration support.

  Extends `ZentinelAgentSdk.V2.Agent` with configuration parsing.

  ## Example

      defmodule MyConfig do
        defstruct rate_limit: 100, enabled: true, rules_path: nil
      end

      defmodule RateLimitAgentV2 do
        use ZentinelAgentSdk.V2.ConfigurableAgent

        @impl true
        def name, do: "rate-limit-v2"

        @impl true
        def version, do: "2.0.0"

        @impl true
        def capabilities do
          AgentCapabilities.new()
          |> AgentCapabilities.with_name(name())
          |> AgentCapabilities.with_version(version())
          |> AgentCapabilities.handles_request_headers()
          |> AgentCapabilities.supports_health_check()
        end

        @impl true
        def default_config, do: %MyConfig{}

        @impl true
        def parse_config(config_map) do
          %MyConfig{
            rate_limit: Map.get(config_map, "rate_limit", 100),
            enabled: Map.get(config_map, "enabled", true),
            rules_path: Map.get(config_map, "rules_path")
          }
        end

        @impl true
        def on_request(request, config) do
          if config.enabled do
            # Rate limiting logic
            Decision.allow()
          else
            Decision.allow()
          end
        end
      end
  """

  alias ZentinelAgentSdk.{Decision, Request, Response}

  alias ZentinelAgentSdk.V2.Types.{
    AgentCapabilities,
    CancelRequest,
    HealthStatus,
    MetricsReport
  }

  alias ZentinelAgentSdk.Protocol.{GuardrailInspectEvent, GuardrailResponse}

  # ============================================================================
  # Required Callbacks
  # ============================================================================

  @callback name() :: String.t()
  @callback capabilities() :: AgentCapabilities.t()
  @callback default_config() :: term()
  @callback parse_config(config_map :: map()) :: term()

  # ============================================================================
  # Optional Callbacks
  # ============================================================================

  @callback version() :: String.t()
  @callback on_config_applied(config :: term()) :: :ok
  @callback on_request(request :: Request.t(), config :: term()) :: Decision.t()
  @callback on_request_body(request :: Request.t(), config :: term()) :: Decision.t()

  @callback on_response(
              request :: Request.t(),
              response :: Response.t(),
              config :: term()
            ) :: Decision.t()

  @callback on_response_body(
              request :: Request.t(),
              response :: Response.t(),
              config :: term()
            ) :: Decision.t()

  @callback on_request_complete(
              request :: Request.t(),
              status :: integer(),
              duration_ms :: integer(),
              config :: term()
            ) :: :ok

  @callback on_guardrail_inspect(event :: GuardrailInspectEvent.t()) :: GuardrailResponse.t()
  @callback on_cancel(request_id :: integer(), cancel_request :: CancelRequest.t()) :: :ok
  @callback on_drain(timeout_ms :: integer(), reason :: String.t() | nil) :: :ok
  @callback on_shutdown() :: :ok
  @callback on_stream_closed(correlation_id :: String.t(), reason :: String.t() | nil) :: :ok
  @callback health_check(config :: term()) :: HealthStatus.t()
  @callback metrics(config :: term()) :: MetricsReport.t()

  @optional_callbacks version: 0,
                      on_config_applied: 1,
                      on_request: 2,
                      on_request_body: 2,
                      on_response: 3,
                      on_response_body: 3,
                      on_request_complete: 4,
                      on_guardrail_inspect: 1,
                      on_cancel: 2,
                      on_drain: 2,
                      on_shutdown: 0,
                      on_stream_closed: 2,
                      health_check: 1,
                      metrics: 1

  defmacro __using__(_opts) do
    quote do
      @behaviour ZentinelAgentSdk.V2.ConfigurableAgent

      alias ZentinelAgentSdk.{Decision, Request, Response}

      alias ZentinelAgentSdk.V2.Types.{
        AgentCapabilities,
        CancelRequest,
        DrainRequest,
        HealthStatus,
        MetricsReport
      }

      alias ZentinelAgentSdk.Protocol.{GuardrailInspectEvent, GuardrailResponse}

      @impl true
      def version, do: "0.0.0"

      @impl true
      def on_config_applied(_config), do: :ok

      @impl true
      def on_request(_request, _config), do: Decision.allow()

      @impl true
      def on_request_body(_request, _config), do: Decision.allow()

      @impl true
      def on_response(_request, _response, _config), do: Decision.allow()

      @impl true
      def on_response_body(_request, _response, _config), do: Decision.allow()

      @impl true
      def on_request_complete(_request, _status, _duration_ms, _config), do: :ok

      @impl true
      def on_guardrail_inspect(_event), do: GuardrailResponse.clean()

      @impl true
      def on_cancel(_request_id, _cancel_request), do: :ok

      @impl true
      def on_drain(_timeout_ms, _reason), do: :ok

      @impl true
      def on_shutdown, do: :ok

      @impl true
      def on_stream_closed(_correlation_id, _reason), do: :ok

      @impl true
      def health_check(_config), do: HealthStatus.healthy()

      @impl true
      def metrics(_config), do: MetricsReport.new()

      defoverridable version: 0,
                     on_config_applied: 1,
                     on_request: 2,
                     on_request_body: 2,
                     on_response: 3,
                     on_response_body: 3,
                     on_request_complete: 4,
                     on_guardrail_inspect: 1,
                     on_cancel: 2,
                     on_drain: 2,
                     on_shutdown: 0,
                     on_stream_closed: 2,
                     health_check: 1,
                     metrics: 1
    end
  end
end
