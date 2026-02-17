defmodule ZentinelAgentSdk.Agent do
  @moduledoc """
  Behaviour for Zentinel agents.

  Implement this behaviour to create a custom agent that can process
  HTTP requests and responses in the Zentinel proxy pipeline.

  ## Example

      defmodule MyAgent do
        use ZentinelAgentSdk.Agent

        @impl true
        def name, do: "my-agent"

        @impl true
        def on_request(request) do
          alias ZentinelAgentSdk.{Decision, Request}

          if Request.path_starts_with?(request, "/blocked") do
            Decision.deny() |> Decision.with_body("Blocked")
          else
            Decision.allow()
          end
        end
      end

  ## Callbacks

  All callbacks have default implementations that return `Decision.allow()`,
  so you only need to implement the callbacks relevant to your use case.

  - `name/0` - Required. Returns the agent name for logging.
  - `on_configure/1` - Called when the agent receives configuration from the proxy.
  - `on_request/1` - Called when request headers are received.
  - `on_request_body/1` - Called when the full request body is available.
  - `on_response/2` - Called when response headers are received from upstream.
  - `on_response_body/2` - Called when the full response body is available.
  - `on_request_complete/3` - Called when request processing is complete.
  - `on_guardrail_inspect/1` - Called for guardrail content inspection.
  """

  alias ZentinelAgentSdk.{Decision, Request, Response}
  alias ZentinelAgentSdk.Protocol.{GuardrailInspectEvent, GuardrailResponse}

  @doc """
  Return the agent name for logging and identification.
  """
  @callback name() :: String.t()

  @doc """
  Handle configuration from the proxy.

  Called once when the agent connects to the proxy.
  Override to validate and store configuration.

  Returns `:ok` on success, `{:error, reason}` on failure.
  """
  @callback on_configure(config :: map()) :: :ok | {:error, String.t()}

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

  @optional_callbacks on_configure: 1,
                      on_request: 1,
                      on_request_body: 1,
                      on_response: 2,
                      on_response_body: 2,
                      on_request_complete: 3,
                      on_guardrail_inspect: 1

  defmacro __using__(_opts) do
    quote do
      @behaviour ZentinelAgentSdk.Agent

      alias ZentinelAgentSdk.{Decision, Request, Response}
      alias ZentinelAgentSdk.Protocol.{GuardrailInspectEvent, GuardrailResponse}

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

      defoverridable on_configure: 1,
                     on_request: 1,
                     on_request_body: 1,
                     on_response: 2,
                     on_response_body: 2,
                     on_request_complete: 3,
                     on_guardrail_inspect: 1
    end
  end
end

defmodule ZentinelAgentSdk.ConfigurableAgent do
  @moduledoc """
  Behaviour for agents with typed configuration support.

  Use this behaviour when your agent needs structured configuration.
  Define a struct for your configuration and implement `parse_config/1`
  to convert the proxy's configuration map to your config struct.

  ## Example

      defmodule MyConfig do
        defstruct rate_limit: 100, enabled: true
      end

      defmodule MyAgent do
        use ZentinelAgentSdk.ConfigurableAgent

        @impl true
        def name, do: "my-agent"

        @impl true
        def default_config, do: %MyConfig{}

        @impl true
        def parse_config(config_map) do
          %MyConfig{
            rate_limit: Map.get(config_map, "rate_limit", 100),
            enabled: Map.get(config_map, "enabled", true)
          }
        end

        @impl true
        def on_request(request, config) do
          if not config.enabled do
            Decision.allow()
          else
            # Use config.rate_limit...
            Decision.allow()
          end
        end
      end

  ## State Management

  The configuration is stored in a GenServer and passed to callbacks.
  This allows agents to be stateless modules while still having access
  to configuration.
  """

  alias ZentinelAgentSdk.{Decision, Request, Response}
  alias ZentinelAgentSdk.Protocol.{GuardrailInspectEvent, GuardrailResponse}

  @doc """
  Return the agent name for logging and identification.
  """
  @callback name() :: String.t()

  @doc """
  Return the default configuration.
  """
  @callback default_config() :: term()

  @doc """
  Parse configuration map from proxy into your config struct.
  """
  @callback parse_config(config_map :: map()) :: term()

  @doc """
  Called after configuration is applied.

  Override for any post-configuration setup.
  """
  @callback on_config_applied(config :: term()) :: :ok

  @doc """
  Process incoming request headers with configuration.
  """
  @callback on_request(request :: Request.t(), config :: term()) :: Decision.t()

  @doc """
  Process request body with configuration.
  """
  @callback on_request_body(request :: Request.t(), config :: term()) :: Decision.t()

  @doc """
  Process response headers with configuration.
  """
  @callback on_response(
              request :: Request.t(),
              response :: Response.t(),
              config :: term()
            ) :: Decision.t()

  @doc """
  Process response body with configuration.
  """
  @callback on_response_body(
              request :: Request.t(),
              response :: Response.t(),
              config :: term()
            ) :: Decision.t()

  @doc """
  Called when request processing is complete.
  """
  @callback on_request_complete(
              request :: Request.t(),
              status :: integer(),
              duration_ms :: integer(),
              config :: term()
            ) :: :ok

  @doc """
  Inspect content for guardrail violations.

  Called when content needs to be analyzed for prompt injection
  or PII detection. Override to implement custom guardrail logic.
  """
  @callback on_guardrail_inspect(event :: GuardrailInspectEvent.t()) :: GuardrailResponse.t()

  @optional_callbacks on_config_applied: 1,
                      on_request: 2,
                      on_request_body: 2,
                      on_response: 3,
                      on_response_body: 3,
                      on_request_complete: 4,
                      on_guardrail_inspect: 1

  defmacro __using__(_opts) do
    quote do
      @behaviour ZentinelAgentSdk.ConfigurableAgent

      alias ZentinelAgentSdk.{Decision, Request, Response}
      alias ZentinelAgentSdk.Protocol.{GuardrailInspectEvent, GuardrailResponse}

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

      defoverridable on_config_applied: 1,
                     on_request: 2,
                     on_request_body: 2,
                     on_response: 3,
                     on_response_body: 3,
                     on_request_complete: 4,
                     on_guardrail_inspect: 1
    end
  end
end
