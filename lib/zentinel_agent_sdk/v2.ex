defmodule ZentinelAgentSdk.V2 do
  @moduledoc """
  V2 protocol support for Zentinel agents.

  The v2 protocol provides enhanced features over v1:

  - **Capability declaration** - Agents declare what event types they handle
  - **Health reporting** - Agents report health status for load balancing
  - **Metrics collection** - Agents can expose custom metrics
  - **Request cancellation** - Proxy can cancel in-flight requests
  - **Graceful shutdown** - Drain support for zero-downtime deployments
  - **Multiple transports** - UDS, gRPC, and reverse connections

  ## Quick Start

      defmodule MyAgentV2 do
        use ZentinelAgentSdk.V2.Agent

        @impl true
        def name, do: "my-agent-v2"

        @impl true
        def capabilities do
          AgentCapabilities.new()
          |> AgentCapabilities.with_name(name())
          |> AgentCapabilities.handles_request_headers()
          |> AgentCapabilities.handles_request_body()
          |> AgentCapabilities.supports_cancellation()
        end

        @impl true
        def on_request(request) do
          if Request.path_starts_with?(request, "/blocked") do
            Decision.deny()
          else
            Decision.allow()
          end
        end

        @impl true
        def health_check do
          HealthStatus.healthy()
        end
      end

      # Run with UDS transport
      ZentinelAgentSdk.V2.run(MyAgentV2,
        transport: :uds,
        socket: "/var/run/zentinel/my-agent.sock"
      )

  ## Modules

  ### Behaviours
  - `ZentinelAgentSdk.V2.Agent` - Base v2 agent behaviour
  - `ZentinelAgentSdk.V2.ConfigurableAgent` - V2 agent with typed config

  ### Types
  - `ZentinelAgentSdk.V2.Types.AgentCapabilities` - Capability declaration
  - `ZentinelAgentSdk.V2.Types.HealthStatus` - Health status reporting
  - `ZentinelAgentSdk.V2.Types.MetricsReport` - Metrics collection
  - `ZentinelAgentSdk.V2.Types.HandshakeRequest` - Handshake request
  - `ZentinelAgentSdk.V2.Types.HandshakeResponse` - Handshake response
  - `ZentinelAgentSdk.V2.Types.CancelRequest` - Request cancellation
  - `ZentinelAgentSdk.V2.Types.DrainRequest` - Drain request

  ### Runtime
  - `ZentinelAgentSdk.V2.Handler` - Event handler GenServer
  - `ZentinelAgentSdk.V2.Runner` - Agent runner with transport support

  ## Transports

  ### UDS (Unix Domain Socket)

  The default transport, suitable for agents co-located with the proxy.

      ZentinelAgentSdk.V2.run(MyAgent,
        transport: :uds,
        socket: "/var/run/zentinel/agent.sock"
      )

  ### Reverse Connection

  For agents that need to connect to the proxy (e.g., behind NAT).

      ZentinelAgentSdk.V2.run(MyAgent,
        transport: :reverse,
        proxy_url: "http://proxy.internal:9090/agents",
        auth_token: "secret",
        reconnect: true
      )

  ## Lifecycle Callbacks

  V2 agents can implement lifecycle callbacks:

  - `on_drain/2` - Called when the agent should stop accepting new requests
  - `on_shutdown/0` - Called when the agent is shutting down
  - `on_stream_closed/2` - Called when a streaming connection is closed
  - `on_cancel/2` - Called when a request is cancelled

  ## Health Checks

  Implement `health_check/0` to report agent health:

      def health_check do
        if database_healthy?() do
          HealthStatus.healthy()
        else
          HealthStatus.unhealthy()
          |> HealthStatus.with_message("Database unavailable")
        end
      end

  ## Metrics

  Implement `metrics/0` to expose custom metrics:

      def metrics do
        MetricsReport.new()
        |> MetricsReport.counter("requests_blocked", @blocked_count)
        |> MetricsReport.gauge("rules_loaded", length(@rules))
        |> MetricsReport.histogram("processing_time_ms", @latencies)
      end
  """

  alias ZentinelAgentSdk.V2.Runner

  @doc """
  Run a V2 agent with the given options.

  ## Options

  ### Transport Selection
  - `:transport` - Transport type: `:uds` (default), `:reverse`

  ### UDS Options
  - `:socket` - Unix socket path (default: "/tmp/zentinel-agent.sock")
  - `:socket_permissions` - File permissions (default: 0o660)

  ### Reverse Connection Options
  - `:proxy_url` - URL of proxy's agent registration endpoint
  - `:auth_token` - Authentication token
  - `:reconnect` - Auto-reconnect on disconnect (default: true)
  - `:reconnect_interval` - Milliseconds between retries (default: 5000)
  - `:max_reconnect_attempts` - Max retries (default: unlimited)

  ### Logging
  - `:log_level` - :debug, :info, :warning, :error
  - `:json_logs` - Enable JSON logging (default: false)

  ## Example

      ZentinelAgentSdk.V2.run(MyAgent,
        transport: :uds,
        socket: "/var/run/zentinel/my-agent.sock",
        log_level: :info
      )
  """
  @spec run(module(), keyword()) :: :ok | {:error, term()}
  def run(agent_module, opts \\ []) do
    Runner.run(agent_module, opts)
  end

  @doc """
  Start a V2 agent as a linked process.

  Returns `{:ok, pid}` on success.
  """
  @spec start_link(module(), keyword()) :: {:ok, pid()} | {:error, term()}
  def start_link(agent_module, opts \\ []) do
    Runner.start_link(agent_module, opts)
  end

  @doc """
  Returns a child spec for supervising a V2 agent.

  ## Example

      children = [
        ZentinelAgentSdk.V2.child_spec(MyAgent, socket: "/tmp/agent.sock")
      ]

      Supervisor.start_link(children, strategy: :one_for_one)
  """
  @spec child_spec(module(), keyword()) :: Supervisor.child_spec()
  def child_spec(agent_module, opts \\ []) do
    Runner.child_spec(agent_module, opts)
  end
end
