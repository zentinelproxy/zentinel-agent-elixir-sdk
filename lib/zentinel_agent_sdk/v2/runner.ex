defmodule ZentinelAgentSdk.V2.Runner do
  @moduledoc """
  Runs a v2 agent on agent protocol v2.

  Transports:
  - Unix domain socket (`:uds`, the default): the proxy connects to the
    agent's socket.
  - gRPC (`:grpc`): `zentinel.agent.v2.AgentServiceV2` over HTTP/2,
    for a proxy configured with `grpc "http://host:port"`.
  - Both (`:both`): the socket and gRPC at once.
  - Reverse (`:reverse`): the agent dials a reverse-connection listener and
    registers. The `zentinel` binary does not open such a listener yet, so this
    transport only works with proxies built on the protocol crate's
    `ReverseConnectionListener`.

  ## Example - UDS Transport

      ZentinelAgentSdk.V2.Runner.run(MyAgent,
        transport: :uds,
        socket: "/var/run/zentinel/my-agent.sock",
        log_level: :info
      )

  ## Example - gRPC Transport

      ZentinelAgentSdk.V2.Runner.run(MyAgent,
        transport: :grpc,
        grpc_address: "127.0.0.1:50051"
      )

  ## Options

  ### Common Options
  - `:transport` - `:uds` (default), `:grpc`, `:both` or `:reverse`
  - `:log_level` - Log level (:debug, :info, :warning, :error)
  - `:json_logs` - Enable JSON log format (default: false)

  ### UDS Transport Options
  - `:socket` - Unix socket path (default: "/tmp/zentinel-agent.sock")
  - `:socket_permissions` - Socket file permissions (default: 0o660)

  ### gRPC Transport Options
  - `:grpc_address` - `"host:port"` to listen on (default: "0.0.0.0:50051")

  ### Reverse Connection Options
  - `:proxy_url` - `tcp://host:port` (or `http(s)://`) of the proxy's
    reverse-connection listener
  - `:auth_token` - Token presented at registration
  - `:reconnect` - Auto-reconnect on disconnect (default: true)
  - `:reconnect_interval` - Milliseconds between reconnect attempts (default: 5000)
  - `:max_reconnect_attempts` - Max reconnect attempts (default: unlimited)

  ## Wire protocol (UDS)

  Every message is `length (4 bytes, big-endian) | type (1 byte) | JSON`,
  where `length` counts the type byte (see `ZentinelAgentSdk.V2.UDS`). The
  proxy sends a handshake request (0x01) and the agent answers with its
  capabilities (0x02). The proxy then sends its configuration (Configure,
  0x17) and uses the connection once the agent's reply allows it. Events
  are answered with an `AgentResponse` (0x20) that carries the event's
  correlation id in `audit.custom.correlation_id`; Ping (0x41) is answered
  with Pong (0x42). Events on a connection are handled concurrently; a
  Configure is answered before the next message is read.
  """

  require Logger

  alias ZentinelAgentSdk.V2.{GrpcServer, Handler, UDS}
  alias ZentinelAgentSdk.V2.Types.AgentCapabilities

  @protocol_version 2

  # ============================================================================
  # Configuration
  # ============================================================================

  defmodule Config do
    @moduledoc false

    @type transport :: :uds | :grpc | :both | :reverse

    @type t :: %__MODULE__{
            transport: transport(),
            socket_path: String.t(),
            socket_permissions: integer(),
            grpc_address: String.t(),
            proxy_url: String.t() | nil,
            auth_token: String.t() | nil,
            reconnect: boolean(),
            reconnect_interval: integer(),
            max_reconnect_attempts: integer() | nil,
            log_level: atom(),
            json_logs: boolean(),
            name: String.t()
          }

    defstruct transport: :uds,
              socket_path: "/tmp/zentinel-agent.sock",
              socket_permissions: 0o660,
              grpc_address: "0.0.0.0:50051",
              proxy_url: nil,
              auth_token: nil,
              reconnect: true,
              reconnect_interval: 5_000,
              max_reconnect_attempts: nil,
              log_level: :info,
              json_logs: false,
              name: "agent"

    @spec new(module(), keyword()) :: t()
    def new(agent_module, opts) do
      name =
        if function_exported?(agent_module, :name, 0) do
          agent_module.name()
        else
          "agent"
        end

      %__MODULE__{
        transport: Keyword.get(opts, :transport, :uds),
        socket_path: Keyword.get(opts, :socket, "/tmp/zentinel-agent.sock"),
        socket_permissions: Keyword.get(opts, :socket_permissions, 0o660),
        grpc_address: Keyword.get(opts, :grpc_address, "0.0.0.0:50051"),
        proxy_url: Keyword.get(opts, :proxy_url),
        auth_token: Keyword.get(opts, :auth_token),
        reconnect: Keyword.get(opts, :reconnect, true),
        reconnect_interval: Keyword.get(opts, :reconnect_interval, 5_000),
        max_reconnect_attempts: Keyword.get(opts, :max_reconnect_attempts),
        log_level: Keyword.get(opts, :log_level, :info),
        json_logs: Keyword.get(opts, :json_logs, false),
        name: name
      }
    end
  end

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Run a V2 agent with the given options.

  This function blocks until the agent is shut down.
  """
  @spec run(module(), keyword()) :: :ok | {:error, term()}
  def run(agent_module, opts \\ []) do
    config = Config.new(agent_module, opts)
    setup_logging(config)

    Logger.info("Starting V2 agent '#{config.name}'")

    {:ok, handler} = Handler.start_link(agent_module)

    caps = Handler.get_capabilities(handler)
    log_capabilities(caps)

    result =
      try do
        case config.transport do
          :uds ->
            run_uds_server(handler, config)

          :grpc ->
            run_grpc_server(handler, config)

          :both ->
            {:ok, _} = start_grpc(handler, config)
            run_uds_server(handler, config)

          :reverse ->
            run_reverse_connection(handler, config)

          other ->
            {:error, {:unknown_transport, other}}
        end
      after
        Handler.shutdown(handler)
        Logger.info("Agent shutdown complete")
      end

    case result do
      {:error, _} = error -> error
      _ -> :ok
    end
  end

  @doc """
  Run a V2 agent as a supervised child.

  Returns a child spec for use in a supervision tree.
  """
  @spec child_spec(module(), keyword()) :: Supervisor.child_spec()
  def child_spec(agent_module, opts \\ []) do
    %{
      id: {__MODULE__, agent_module},
      start: {__MODULE__, :start_link, [agent_module, opts]},
      type: :worker,
      restart: :permanent
    }
  end

  @doc """
  Start a V2 agent as a linked process.
  """
  @spec start_link(module(), keyword()) :: {:ok, pid()} | {:error, term()}
  def start_link(agent_module, opts \\ []) do
    Task.start_link(fn -> run(agent_module, opts) end)
  end

  # ============================================================================
  # UDS Server
  # ============================================================================

  defp run_uds_server(handler, config) do
    socket_path = config.socket_path

    if File.exists?(socket_path) do
      File.rm!(socket_path)
    end

    socket_path |> Path.dirname() |> File.mkdir_p!()

    {:ok, listen_socket} =
      :gen_tcp.listen(0, [
        :binary,
        {:packet, :raw},
        {:active, false},
        {:backlog, 128},
        {:ifaddr, {:local, String.to_charlist(socket_path)}}
      ])

    File.chmod!(socket_path, config.socket_permissions)

    # A linked parent (start_link/child_spec) exiting stops the server.
    Process.flag(:trap_exit, true)

    Logger.info("V2 agent '#{config.name}' listening on #{socket_path}")

    try do
      accept_loop(listen_socket, handler)
    after
      :gen_tcp.close(listen_socket)

      if File.exists?(socket_path) do
        File.rm!(socket_path)
      end
    end
  end

  defp accept_loop(listen_socket, handler) do
    case :gen_tcp.accept(listen_socket, 1000) do
      {:ok, client_socket} ->
        Logger.debug("New connection accepted")
        # Not linked: a connection ending must not stop the server.
        pid = spawn(fn -> receive(do: (:go -> serve_connection(client_socket, handler))) end)
        :ok = :gen_tcp.controlling_process(client_socket, pid)
        send(pid, :go)
        accept_loop(listen_socket, handler)

      {:error, :timeout} ->
        receive do
          {:EXIT, _pid, reason} ->
            Logger.info("Shutdown signal received (#{inspect(reason)})")
            :ok
        after
          0 -> accept_loop(listen_socket, handler)
        end

      {:error, :closed} ->
        Logger.info("Listen socket closed")
        :ok

      {:error, reason} ->
        Logger.error("Accept error: #{inspect(reason)}")
        :ok
    end
  end

  @doc false
  # Serve one proxy connection: handshake, then events until it closes.
  # Public for tests; `socket` is a passive gen_tcp socket.
  @spec serve_connection(:gen_tcp.socket(), GenServer.server()) :: :ok
  def serve_connection(socket, handler) do
    case UDS.read_frame(socket) do
      {:ok, 0x01, payload} ->
        with {:ok, request} <- decode_json(payload),
             :ok <- send_handshake(socket, handler, request) do
          Logger.debug("Handshake completed with #{request["proxy_id"]}")
          event_loop(socket, handler)
        else
          {:error, reason} -> Logger.error("Handshake failed: #{reason}")
        end

      {:ok, type, _payload} ->
        Logger.error("Expected a handshake request, got message type 0x#{hex(type)}")

      :closed ->
        :ok

      {:error, reason} ->
        Logger.error("Failed to read handshake: #{reason}")
    end
  rescue
    e -> Logger.error("Connection error: #{Exception.message(e)}")
  after
    :gen_tcp.close(socket)
    Logger.debug("Connection closed")
  end

  defp send_handshake(socket, handler, request) do
    caps = Handler.get_capabilities(handler)
    versions = request["supported_versions"] || [@protocol_version]
    ok = @protocol_version in versions

    response = %{
      "protocol_version" => @protocol_version,
      "capabilities" => AgentCapabilities.to_uds_map(caps),
      "success" => ok,
      "error" =>
        if(ok, do: nil, else: "protocol v2 not offered (proxy supports #{inspect(versions)})"),
      "encoding" => "json"
    }

    case UDS.write_frame(socket, :handshake_response, response) do
      :ok when ok -> :ok
      :ok -> {:error, response["error"]}
      {:error, reason} -> {:error, "could not send handshake response: #{inspect(reason)}"}
    end
  end

  defp event_loop(socket, handler) do
    case UDS.read_frame(socket) do
      {:ok, 0x41, payload} ->
        _ = UDS.write_frame(socket, :pong, payload)
        event_loop(socket, handler)

      {:ok, 0x40, payload} ->
        # Cancel: no reply expected.
        with {:ok, data} <- decode_json(payload), do: Handler.dispatch(handler, "cancel", data)
        event_loop(socket, handler)

      {:ok, type, payload} ->
        case UDS.event_type(type) do
          nil ->
            Logger.debug("Ignoring message type 0x#{hex(type)}")

          "configure" ->
            # Answered before the next message is read, so no request on this
            # connection precedes its configuration.
            respond(socket, handler, "configure", payload)

          event_type ->
            spawn(fn -> respond(socket, handler, event_type, payload) end)
        end

        event_loop(socket, handler)

      :closed ->
        :ok

      {:error, reason} ->
        Logger.error("Failed to read message: #{reason}")
    end
  end

  defp respond(socket, handler, event_type, payload) do
    case decode_json(payload) do
      {:ok, data} ->
        response =
          handler
          |> Handler.dispatch(event_type, data)
          |> with_correlation_id(correlation_id_of(data))

        case UDS.write_frame(socket, :agent_response, response) do
          :ok -> :ok
          {:error, reason} -> Logger.debug("Failed to send response: #{inspect(reason)}")
        end

      {:error, reason} ->
        Logger.error("Undecodable #{event_type} message: #{reason}")
    end
  end

  @doc false
  # The proxy matches a response to its request by
  # `audit.custom.correlation_id`.
  @spec with_correlation_id(map(), String.t()) :: map()
  def with_correlation_id(response, correlation_id) do
    audit = Map.get(response, "audit") || %{}
    custom = Map.get(audit, "custom") || %{}

    Map.put(
      response,
      "audit",
      Map.put(audit, "custom", Map.put(custom, "correlation_id", correlation_id))
    )
  end

  @doc false
  # The correlation id of an event payload (top level, or in `metadata`).
  @spec correlation_id_of(map()) :: String.t()
  def correlation_id_of(%{"correlation_id" => cid}) when is_binary(cid) and cid != "", do: cid

  def correlation_id_of(%{"metadata" => %{"correlation_id" => cid}}) when is_binary(cid),
    do: cid

  def correlation_id_of(_), do: ""

  defp decode_json(""), do: {:ok, %{}}

  defp decode_json(payload) do
    case Jason.decode(payload) do
      {:ok, data} when is_map(data) -> {:ok, data}
      {:ok, _} -> {:error, "payload is not a JSON object"}
      {:error, e} -> {:error, Exception.message(e)}
    end
  end

  defp hex(byte), do: byte |> Integer.to_string(16) |> String.pad_leading(2, "0")

  # ============================================================================
  # gRPC Server
  # ============================================================================

  defp start_grpc(handler, config) do
    result = GrpcServer.start_link(handler, config.grpc_address)
    Logger.info("V2 agent '#{config.name}' serving gRPC on #{config.grpc_address}")
    result
  end

  defp run_grpc_server(handler, config) do
    Process.flag(:trap_exit, true)

    case start_grpc(handler, config) do
      {:ok, pid} ->
        receive do
          {:EXIT, ^pid, reason} ->
            Logger.error("gRPC server stopped: #{inspect(reason)}")

          {:EXIT, _pid, reason} ->
            Logger.info("Shutdown signal received (#{inspect(reason)})")
        end

      {:error, reason} = error ->
        Logger.error("Could not start the gRPC server: #{inspect(reason)}")
        error
    end
  end

  # ============================================================================
  # Reverse Connection
  # ============================================================================

  defp run_reverse_connection(handler, config) do
    if config.proxy_url == nil do
      Logger.error("proxy_url is required for reverse connection transport")
      {:error, :missing_proxy_url}
    else
      reverse_connection_loop(handler, config, 0)
    end
  end

  defp reverse_connection_loop(handler, config, attempt) do
    if config.max_reconnect_attempts != nil and attempt >= config.max_reconnect_attempts do
      Logger.error("Max reconnect attempts (#{config.max_reconnect_attempts}) reached")
      {:error, :max_reconnect_attempts}
    else
      Logger.info("Connecting to proxy at #{config.proxy_url} (attempt #{attempt + 1})")

      result =
        with {:ok, socket} <- connect_reverse(config),
             :ok <- register(socket, handler, config) do
          Logger.info("Registered with the proxy")
          event_loop(socket, handler)
          close(socket)
          :connected
        end

      cond do
        not config.reconnect ->
          if result == :connected, do: :ok, else: result

        result == :connected ->
          Logger.info("Connection lost, reconnecting in #{config.reconnect_interval}ms")
          Process.sleep(config.reconnect_interval)
          reverse_connection_loop(handler, config, 0)

        true ->
          Logger.error("Reverse connection failed: #{inspect(result)}")
          Process.sleep(config.reconnect_interval)
          reverse_connection_loop(handler, config, attempt + 1)
      end
    end
  end

  defp close({:sslsocket, _, _} = socket), do: :ssl.close(socket)
  defp close(socket), do: :gen_tcp.close(socket)

  defp connect_reverse(config) do
    uri = URI.parse(config.proxy_url)
    host = uri.host || "localhost"
    port = uri.port || 80
    opts = [:binary, {:packet, :raw}, {:active, false}, {:nodelay, true}]

    with {:ok, socket} <- :gen_tcp.connect(String.to_charlist(host), port, opts, 10_000) do
      if uri.scheme in ["https", "tls"] do
        :ssl.connect(socket, [verify: :verify_peer, cacerts: :public_key.cacerts_get()], 10_000)
      else
        {:ok, socket}
      end
    end
  end

  # Registration (the protocol crate's `RegistrationRequest`), sent as a
  # handshake request frame; the proxy answers with a handshake response
  # frame carrying a `RegistrationResponse`.
  defp register(socket, handler, config) do
    caps = Handler.get_capabilities(handler)

    request = %{
      "protocol_version" => @protocol_version,
      "agent_id" => caps.agent_name,
      "capabilities" => AgentCapabilities.to_uds_map(caps),
      "auth_token" => config.auth_token,
      "metadata" => nil
    }

    with :ok <- UDS.write_frame(socket, :handshake_request, request),
         {:ok, 0x02, payload} <- UDS.read_frame(socket),
         {:ok, %{"success" => true}} <- decode_json(payload) do
      :ok
    else
      {:ok, %{"error" => error}} -> {:error, "registration rejected: #{error}"}
      {:ok, type, _} -> {:error, "unexpected message type 0x#{hex(type)}"}
      other -> {:error, other}
    end
  end

  # ============================================================================
  # Logging Setup
  # ============================================================================

  defp setup_logging(%Config{log_level: level, json_logs: json_logs, name: name}) do
    Logger.configure(level: level)

    if json_logs do
      Logger.metadata(agent: name, format: :json)
    else
      Logger.metadata(agent: name)
    end
  end

  defp log_capabilities(%AgentCapabilities{} = caps) do
    Logger.info("Agent capabilities:")
    Logger.info("  Name: #{caps.agent_name}")
    Logger.info("  Version: #{caps.agent_version}")
    Logger.info("  Protocol: v#{caps.protocol_version}")

    handlers = []
    handlers = if caps.handles_request_headers, do: ["request_headers" | handlers], else: handlers
    handlers = if caps.handles_request_body, do: ["request_body" | handlers], else: handlers
    handlers = if caps.handles_response_headers, do: ["response_headers" | handlers], else: handlers
    handlers = if caps.handles_response_body, do: ["response_body" | handlers], else: handlers
    handlers = if caps.handles_websocket_frames, do: ["websocket" | handlers], else: handlers
    handlers = if caps.handles_guardrail_inspect, do: ["guardrail" | handlers], else: handlers

    Logger.info("  Handles: #{Enum.join(Enum.reverse(handlers), ", ")}")

    features = []
    features = if caps.supports_streaming, do: ["streaming" | features], else: features
    features = if caps.supports_cancellation, do: ["cancellation" | features], else: features
    features = if caps.supports_health_check, do: ["health_check" | features], else: features
    features = if caps.supports_metrics, do: ["metrics" | features], else: features

    Logger.info("  Features: #{Enum.join(Enum.reverse(features), ", ")}")

    if caps.max_concurrent_requests do
      Logger.info("  Max concurrent: #{caps.max_concurrent_requests}")
    end
  end
end
