defmodule ZentinelAgentSdk do
  @moduledoc """
  Elixir SDK for building Zentinel proxy agents.

  This SDK provides the tools to build custom agents that integrate with the
  Zentinel proxy. Agents can inspect and modify HTTP requests and responses,
  implement security policies, rate limiting, and more.

  ## Protocol Versions

  The SDK supports two protocol versions:

  - **v1 (Legacy)** - JSON over UDS, simple request/response
  - **v2 (Current)** - Enhanced protocol with capabilities, health checks, metrics

  ## Quick Start (v1)

      defmodule MyAgent do
        use ZentinelAgentSdk.Agent

        @impl true
        def name, do: "my-agent"

        @impl true
        def on_request(request) do
          if Request.path_starts_with?(request, "/blocked") do
            Decision.deny()
            |> Decision.with_body("Access denied")
          else
            Decision.allow()
          end
        end
      end

      # Run the agent
      ZentinelAgentSdk.run(MyAgent)

  ## Quick Start (v2)

      defmodule MyAgentV2 do
        use ZentinelAgentSdk.V2.Agent

        @impl true
        def name, do: "my-agent-v2"

        @impl true
        def capabilities do
          AgentCapabilities.new()
          |> AgentCapabilities.with_name(name())
          |> AgentCapabilities.handles_request_headers()
          |> AgentCapabilities.supports_health_check()
        end

        @impl true
        def on_request(request) do
          Decision.allow()
        end

        @impl true
        def health_check do
          HealthStatus.healthy()
        end
      end

      # Run with v2 protocol
      ZentinelAgentSdk.V2.run(MyAgentV2)

  ## Core Modules (v1)

  - `ZentinelAgentSdk.Agent` - The behaviour for implementing agents
  - `ZentinelAgentSdk.ConfigurableAgent` - For agents with typed configuration
  - `ZentinelAgentSdk.Request` - Request wrapper with helper functions
  - `ZentinelAgentSdk.Response` - Response wrapper with helper functions
  - `ZentinelAgentSdk.Decision` - Fluent API for building agent responses
  - `ZentinelAgentSdk.Runner` - Agent server and runner

  ## V2 Modules

  - `ZentinelAgentSdk.V2` - V2 protocol entry point
  - `ZentinelAgentSdk.V2.Agent` - V2 agent behaviour with capabilities
  - `ZentinelAgentSdk.V2.ConfigurableAgent` - V2 agent with typed config
  - `ZentinelAgentSdk.V2.Types` - V2 protocol types (capabilities, health, metrics)
  - `ZentinelAgentSdk.V2.Handler` - V2 event handler
  - `ZentinelAgentSdk.V2.Runner` - V2 runner with transport support
  """

  alias ZentinelAgentSdk.Runner

  @doc """
  Run an agent with default options.

  ## Options

  - `:socket` - Unix socket path (default: "/tmp/zentinel-agent.sock")
  - `:log_level` - Log level (:debug, :info, :warning, :error)
  - `:json_logs` - Enable JSON log format (default: false)

  ## Example

      ZentinelAgentSdk.run(MyAgent, socket: "/var/run/my-agent.sock")
  """
  @spec run(module(), keyword()) :: :ok | {:error, term()}
  def run(agent_module, opts \\ []) do
    Runner.run(agent_module, opts)
  end
end
