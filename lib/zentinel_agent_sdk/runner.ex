# Define Config first so it can be used by other modules in this file
defmodule ZentinelAgentSdk.Runner.Config do
  @moduledoc false

  @type t :: %__MODULE__{
          socket_path: String.t(),
          name: String.t(),
          json_logs: boolean(),
          log_level: atom()
        }

  defstruct socket_path: "/tmp/zentinel-agent.sock",
            name: "agent",
            json_logs: false,
            log_level: :info

  @spec new(module(), keyword()) :: t()
  def new(agent_module, opts) do
    name =
      if function_exported?(agent_module, :name, 0) do
        agent_module.name()
      else
        "agent"
      end

    %__MODULE__{
      socket_path: Keyword.get(opts, :socket, "/tmp/zentinel-agent.sock"),
      name: name,
      json_logs: Keyword.get(opts, :json_logs, false),
      log_level: Keyword.get(opts, :log_level, :info)
    }
  end
end

# Define Handler next
defmodule ZentinelAgentSdk.Runner.Handler do
  @moduledoc false

  require Logger

  alias ZentinelAgentSdk.{Decision, Request, Response}

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

  @type t :: %__MODULE__{
          agent_module: module(),
          config: ZentinelAgentSdk.Runner.Config.t(),
          agent_config: term(),
          requests: %{String.t() => Request.t()},
          request_bodies: %{String.t() => binary()},
          response_bodies: %{String.t() => binary()},
          response_events: %{String.t() => ResponseHeadersEvent.t()}
        }

  defstruct [
    :agent_module,
    :config,
    agent_config: nil,
    requests: %{},
    request_bodies: %{},
    response_bodies: %{},
    response_events: %{}
  ]

  @spec new(module(), ZentinelAgentSdk.Runner.Config.t()) :: t()
  def new(agent_module, config) do
    %__MODULE__{
      agent_module: agent_module,
      config: config
    }
  end

  @spec handle_event(t(), map()) :: {map(), t()}
  def handle_event(handler, event) do
    event_type = Map.get(event, "event_type", "")
    payload = Map.get(event, "payload", %{})

    try do
      case event_type do
        "configure" ->
          handle_configure(handler, payload)

        "request_headers" ->
          handle_request_headers(handler, payload)

        "request_body_chunk" ->
          handle_request_body_chunk(handler, payload)

        "response_headers" ->
          handle_response_headers(handler, payload)

        "response_body_chunk" ->
          handle_response_body_chunk(handler, payload)

        "request_complete" ->
          handle_request_complete(handler, payload)

        "guardrail_inspect" ->
          handle_guardrail_inspect(handler, payload)

        _ ->
          Logger.warning("Unknown event type: #{event_type}")
          {Decision.allow() |> Decision.to_map(), handler}
      end
    rescue
      e ->
        Logger.error("Error handling event #{event_type}: #{inspect(e)}")
        {Decision.allow() |> Decision.to_map(), handler}
    end
  end

  defp handle_configure(handler, payload) do
    event = ConfigureEvent.from_map(payload)

    result =
      if is_configurable_agent?(handler.agent_module) do
        config = handler.agent_module.parse_config(event.config)
        handler.agent_module.on_config_applied(config)
        {%{"success" => true}, %{handler | agent_config: config}}
      else
        case handler.agent_module.on_configure(event.config) do
          :ok ->
            Logger.info("Agent configured: #{event.agent_id}")
            {%{"success" => true}, handler}

          {:error, reason} ->
            Logger.error("Configuration failed: #{reason}")
            {%{"success" => false, "error" => reason}, handler}
        end
      end

    result
  end

  defp handle_request_headers(handler, payload) do
    event = RequestHeadersEvent.from_map(payload)
    request = Request.new(event)
    correlation_id = event.metadata.correlation_id

    # Cache request for response correlation
    handler = %{
      handler
      | requests: Map.put(handler.requests, correlation_id, request),
        request_bodies: Map.put(handler.request_bodies, correlation_id, <<>>)
    }

    decision =
      if is_configurable_agent?(handler.agent_module) do
        handler.agent_module.on_request(request, handler.agent_config)
      else
        handler.agent_module.on_request(request)
      end

    {Decision.to_map(decision), handler}
  end

  defp handle_request_body_chunk(handler, payload) do
    event = RequestBodyChunkEvent.from_map(payload)
    correlation_id = event.correlation_id

    # Accumulate body chunks
    handler =
      if Map.has_key?(handler.request_bodies, correlation_id) do
        current_body = Map.get(handler.request_bodies, correlation_id, <<>>)

        %{
          handler
          | request_bodies:
              Map.put(handler.request_bodies, correlation_id, current_body <> event.data)
        }
      else
        handler
      end

    # Only call handler on last chunk
    if event.is_last and Map.has_key?(handler.requests, correlation_id) do
      request =
        handler.requests
        |> Map.get(correlation_id)
        |> Request.with_body(Map.get(handler.request_bodies, correlation_id, <<>>))

      decision =
        if is_configurable_agent?(handler.agent_module) do
          handler.agent_module.on_request_body(request, handler.agent_config)
        else
          handler.agent_module.on_request_body(request)
        end

      {Decision.to_map(decision), handler}
    else
      {Decision.allow() |> Decision.needs_more_data() |> Decision.to_map(), handler}
    end
  end

  defp handle_response_headers(handler, payload) do
    event = ResponseHeadersEvent.from_map(payload)
    correlation_id = event.correlation_id

    request = Map.get(handler.requests, correlation_id)

    if request == nil do
      Logger.warning("No cached request for correlation_id: #{correlation_id}")
      {Decision.allow() |> Decision.to_map(), handler}
    else
      response = Response.new(event)

      handler = %{
        handler
        | response_bodies: Map.put(handler.response_bodies, correlation_id, <<>>),
          response_events: Map.put(handler.response_events, correlation_id, event)
      }

      decision =
        if is_configurable_agent?(handler.agent_module) do
          handler.agent_module.on_response(request, response, handler.agent_config)
        else
          handler.agent_module.on_response(request, response)
        end

      {Decision.to_map(decision), handler}
    end
  end

  defp handle_response_body_chunk(handler, payload) do
    event = ResponseBodyChunkEvent.from_map(payload)
    correlation_id = event.correlation_id

    # Accumulate body chunks
    handler =
      if Map.has_key?(handler.response_bodies, correlation_id) do
        current_body = Map.get(handler.response_bodies, correlation_id, <<>>)

        %{
          handler
          | response_bodies:
              Map.put(handler.response_bodies, correlation_id, current_body <> event.data)
        }
      else
        handler
      end

    # Only call handler on last chunk
    if event.is_last and Map.has_key?(handler.requests, correlation_id) do
      request = Map.get(handler.requests, correlation_id)

      response_event =
        Map.get(
          handler.response_events,
          correlation_id,
          %ResponseHeadersEvent{correlation_id: correlation_id, status: 200, headers: %{}}
        )

      response =
        Response.new(response_event)
        |> Response.with_body(Map.get(handler.response_bodies, correlation_id, <<>>))

      decision =
        if is_configurable_agent?(handler.agent_module) do
          handler.agent_module.on_response_body(request, response, handler.agent_config)
        else
          handler.agent_module.on_response_body(request, response)
        end

      {Decision.to_map(decision), handler}
    else
      {Decision.allow() |> Decision.needs_more_data() |> Decision.to_map(), handler}
    end
  end

  defp handle_request_complete(handler, payload) do
    event = RequestCompleteEvent.from_map(payload)
    correlation_id = event.correlation_id

    request = Map.get(handler.requests, correlation_id)

    # Cleanup cached data
    handler = %{
      handler
      | requests: Map.delete(handler.requests, correlation_id),
        request_bodies: Map.delete(handler.request_bodies, correlation_id),
        response_bodies: Map.delete(handler.response_bodies, correlation_id),
        response_events: Map.delete(handler.response_events, correlation_id)
    }

    if request != nil do
      if is_configurable_agent?(handler.agent_module) do
        handler.agent_module.on_request_complete(
          request,
          event.status,
          event.duration_ms,
          handler.agent_config
        )
      else
        handler.agent_module.on_request_complete(request, event.status, event.duration_ms)
      end
    end

    {%{"success" => true}, handler}
  end

  defp handle_guardrail_inspect(handler, payload) do
    event = GuardrailInspectEvent.from_map(payload)

    # Call the agent's on_guardrail_inspect callback
    response = handler.agent_module.on_guardrail_inspect(event)

    # Build the response with guardrail_response in audit.custom
    audit_response = %{
      "tags" => if(response.detected, do: ["guardrail_detected"], else: []),
      "rule_ids" => Enum.map(response.detections, & &1.category),
      "confidence" => response.confidence,
      "custom" => %{
        "guardrail_response" => GuardrailResponse.to_map(response)
      }
    }

    {%{"version" => 1, "audit" => audit_response}, handler}
  end

  defp is_configurable_agent?(module) do
    # Check if the module implements ConfigurableAgent by looking for parse_config/1
    function_exported?(module, :parse_config, 1)
  end
end

# Define Runner last since it depends on Config and Handler
defmodule ZentinelAgentSdk.Runner do
  @moduledoc """
  Runner for starting and managing an agent.

  Starts a Unix socket server and routes protocol events to the agent.

  ## Example

      # Simple agent
      ZentinelAgentSdk.Runner.run(MyAgent, socket: "/tmp/my-agent.sock")

      # With options
      ZentinelAgentSdk.Runner.run(MyAgent,
        socket: "/tmp/my-agent.sock",
        log_level: :debug,
        json_logs: true
      )
  """

  require Logger

  alias ZentinelAgentSdk.Runner.{Config, Handler}

  @doc """
  Run an agent with the given options.

  ## Options

  - `:socket` - Unix socket path (default: "/tmp/zentinel-agent.sock")
  - `:log_level` - Log level (:debug, :info, :warning, :error)
  - `:json_logs` - Enable JSON log format (default: false)

  This function blocks until the agent is shut down.
  """
  @spec run(module(), keyword()) :: :ok | {:error, term()}
  def run(agent_module, opts \\ []) do
    config = Config.new(agent_module, opts)
    setup_logging(config)

    socket_path = config.socket_path

    # Clean up existing socket
    if File.exists?(socket_path) do
      File.rm!(socket_path)
    end

    # Ensure parent directory exists
    socket_path |> Path.dirname() |> File.mkdir_p!()

    Logger.info("Agent '#{config.name}' starting on #{socket_path}")

    # Start listening on Unix socket
    {:ok, listen_socket} =
      :gen_tcp.listen(0, [
        :binary,
        {:packet, :raw},
        {:active, false},
        {:reuseaddr, true},
        {:ifaddr, {:local, String.to_charlist(socket_path)}}
      ])

    # Set socket permissions
    File.chmod!(socket_path, 0o660)

    # Set up signal handling via trap_exit
    Process.flag(:trap_exit, true)

    Logger.info("Agent '#{config.name}' listening on #{socket_path}")

    try do
      accept_loop(listen_socket, agent_module, config)
    after
      :gen_tcp.close(listen_socket)

      if File.exists?(socket_path) do
        File.rm!(socket_path)
      end

      Logger.info("Agent shutdown complete")
    end

    :ok
  end

  defp accept_loop(listen_socket, agent_module, config) do
    case :gen_tcp.accept(listen_socket, 1000) do
      {:ok, client_socket} ->
        Logger.debug("New connection accepted")
        spawn_link(fn -> handle_connection(client_socket, agent_module, config) end)
        accept_loop(listen_socket, agent_module, config)

      {:error, :timeout} ->
        # Check for shutdown signal
        receive do
          {:EXIT, _pid, _reason} ->
            Logger.info("Shutdown signal received")
            :ok
        after
          0 -> accept_loop(listen_socket, agent_module, config)
        end

      {:error, :closed} ->
        Logger.info("Listen socket closed")
        :ok

      {:error, reason} ->
        Logger.error("Accept error: #{inspect(reason)}")
        :ok
    end
  end

  defp handle_connection(socket, agent_module, config) do
    handler = Handler.new(agent_module, config)

    try do
      connection_loop(socket, handler)
    rescue
      e ->
        Logger.error("Connection error: #{inspect(e)}")
    after
      :gen_tcp.close(socket)
      Logger.debug("Connection closed")
    end
  end

  defp connection_loop(socket, handler) do
    case ZentinelAgentSdk.Protocol.read_message(socket) do
      {:ok, message} ->
        {response, handler} = Handler.handle_event(handler, message)

        case ZentinelAgentSdk.Protocol.write_message(socket, response) do
          :ok ->
            connection_loop(socket, handler)

          {:error, reason} ->
            Logger.error("Failed to send response: #{reason}")
        end

      :closed ->
        :ok

      {:error, reason} ->
        Logger.error("Failed to read message: #{reason}")
    end
  end

  defp setup_logging(%Config{log_level: level, json_logs: json_logs, name: name}) do
    # Configure Logger
    Logger.configure(level: level)

    if json_logs do
      # JSON logging would need a custom backend or formatter
      # For now, we'll just note it in the metadata
      Logger.metadata(agent: name, format: :json)
    else
      Logger.metadata(agent: name)
    end
  end
end
