defmodule ZentinelAgentSdk.V2.Runner do
  @moduledoc """
  V2 runner for starting and managing agents with enhanced protocol support.

  Supports multiple transport types:
  - Unix Domain Sockets (UDS)
  - gRPC (via Mint HTTP/2)
  - Reverse connections (agent connects to proxy)

  ## Example - UDS Transport

      ZentinelAgentSdk.V2.Runner.run(MyAgent,
        transport: :uds,
        socket: "/var/run/zentinel/my-agent.sock",
        log_level: :info
      )

  ## Example - Reverse Connection

      ZentinelAgentSdk.V2.Runner.run(MyAgent,
        transport: :reverse,
        proxy_url: "http://localhost:9090/agents",
        auth_token: "secret-token",
        reconnect: true
      )

  ## Options

  ### Common Options
  - `:transport` - Transport type: `:uds` (default), `:reverse`
  - `:log_level` - Log level (:debug, :info, :warning, :error)
  - `:json_logs` - Enable JSON log format (default: false)
  - `:auth_token` - Authentication token for handshake

  ### UDS Transport Options
  - `:socket` - Unix socket path (default: "/tmp/zentinel-agent.sock")
  - `:socket_permissions` - Socket file permissions (default: 0o660)

  ### Reverse Connection Options
  - `:proxy_url` - URL of the proxy's agent registration endpoint
  - `:reconnect` - Auto-reconnect on disconnect (default: true)
  - `:reconnect_interval` - Milliseconds between reconnect attempts (default: 5000)
  - `:max_reconnect_attempts` - Max reconnect attempts (default: unlimited)

  ## Lifecycle

  The runner manages the complete agent lifecycle:

  1. **Startup** - Initialize handler, prepare capabilities
  2. **Connect** - Establish transport connection
  3. **Handshake** - Exchange capabilities with proxy
  4. **Running** - Process events
  5. **Drain** - Stop accepting new requests
  6. **Shutdown** - Clean up and exit
  """

  require Logger

  alias ZentinelAgentSdk.Protocol
  alias ZentinelAgentSdk.V2.Handler

  alias ZentinelAgentSdk.V2.Types.{
    AgentCapabilities,
    HandshakeRequest,
    HandshakeResponse
  }

  # ============================================================================
  # Configuration
  # ============================================================================

  defmodule Config do
    @moduledoc false

    @type transport :: :uds | :reverse

    @type t :: %__MODULE__{
            transport: transport(),
            socket_path: String.t(),
            socket_permissions: integer(),
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

    # Start handler
    {:ok, handler} = Handler.start_link(agent_module)

    # Log capabilities
    caps = Handler.get_capabilities(handler)
    log_capabilities(caps)

    try do
      case config.transport do
        :uds ->
          run_uds_server(handler, config)

        :reverse ->
          run_reverse_connection(handler, config)
      end
    after
      # Shutdown handler
      Handler.shutdown(handler)
      Logger.info("Agent shutdown complete")
    end

    :ok
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

    # Clean up existing socket
    if File.exists?(socket_path) do
      File.rm!(socket_path)
    end

    # Ensure parent directory exists
    socket_path |> Path.dirname() |> File.mkdir_p!()

    Logger.info("Starting UDS server on #{socket_path}")

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
    File.chmod!(socket_path, config.socket_permissions)

    # Set up signal handling
    Process.flag(:trap_exit, true)

    Logger.info("V2 agent '#{config.name}' listening on #{socket_path}")

    try do
      accept_loop(listen_socket, handler, config)
    after
      :gen_tcp.close(listen_socket)

      if File.exists?(socket_path) do
        File.rm!(socket_path)
      end
    end
  end

  defp accept_loop(listen_socket, handler, config) do
    case :gen_tcp.accept(listen_socket, 1000) do
      {:ok, client_socket} ->
        Logger.debug("New connection accepted")
        spawn_link(fn -> handle_uds_connection(client_socket, handler, config) end)
        accept_loop(listen_socket, handler, config)

      {:error, :timeout} ->
        # Check for shutdown signal
        receive do
          {:EXIT, _pid, _reason} ->
            Logger.info("Shutdown signal received")
            :ok
        after
          0 -> accept_loop(listen_socket, handler, config)
        end

      {:error, :closed} ->
        Logger.info("Listen socket closed")
        :ok

      {:error, reason} ->
        Logger.error("Accept error: #{inspect(reason)}")
        :ok
    end
  end

  defp handle_uds_connection(socket, handler, config) do
    try do
      # Perform V2 handshake
      case perform_handshake(socket, handler, config) do
        {:ok, _response} ->
          Logger.debug("Handshake complete, entering event loop")
          uds_connection_loop(socket, handler)

        {:error, reason} ->
          Logger.error("Handshake failed: #{reason}")
      end
    rescue
      e ->
        Logger.error("Connection error: #{inspect(e)}")
    after
      :gen_tcp.close(socket)
      Logger.debug("Connection closed")
    end
  end

  defp perform_handshake(socket, handler, config) do
    # Read handshake initiation from proxy
    case Protocol.read_message(socket) do
      {:ok, %{"event_type" => "handshake_init"} = _init} ->
        # Build and send our handshake request
        request = Handler.get_handshake_request(handler, config.auth_token)
        request_map = %{"event_type" => "handshake_request", "payload" => HandshakeRequest.to_map(request)}

        case Protocol.write_message(socket, request_map) do
          :ok ->
            # Wait for handshake response
            case Protocol.read_message(socket) do
              {:ok, %{"event_type" => "handshake_response", "payload" => payload}} ->
                response = HandshakeResponse.from_map(payload)
                Handler.handle_handshake_response(handler, response)

              {:ok, msg} ->
                {:error, "Unexpected handshake response: #{inspect(msg)}"}

              {:error, reason} ->
                {:error, "Failed to read handshake response: #{reason}"}

              :closed ->
                {:error, "Connection closed during handshake"}
            end

          {:error, reason} ->
            {:error, "Failed to send handshake request: #{reason}"}
        end

      {:ok, %{"event_type" => event_type}} ->
        # Proxy didn't send handshake init, might be v1 compatible
        # Send capabilities proactively
        Logger.debug("No handshake init received (got #{event_type}), proceeding with v1 compatibility")
        {:ok, nil}

      {:ok, msg} when is_map(msg) ->
        # Might be a direct event (v1 compatibility)
        Logger.debug("Received non-handshake message, assuming v1 compatibility")
        {:ok, nil}

      {:error, reason} ->
        {:error, "Failed to read handshake init: #{reason}"}

      :closed ->
        {:error, "Connection closed before handshake"}
    end
  end

  defp uds_connection_loop(socket, handler) do
    case Protocol.read_message(socket) do
      {:ok, message} ->
        response = Handler.handle_event(handler, message)

        case Protocol.write_message(socket, response) do
          :ok ->
            uds_connection_loop(socket, handler)

          {:error, reason} ->
            Logger.error("Failed to send response: #{reason}")
        end

      :closed ->
        :ok

      {:error, reason} ->
        Logger.error("Failed to read message: #{reason}")
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
    # Check max attempts
    if config.max_reconnect_attempts != nil and attempt >= config.max_reconnect_attempts do
      Logger.error("Max reconnect attempts (#{config.max_reconnect_attempts}) reached")
      {:error, :max_reconnect_attempts}
    else
      Logger.info("Connecting to proxy at #{config.proxy_url} (attempt #{attempt + 1})")

      case connect_reverse(config) do
        {:ok, socket} ->
          Logger.info("Connected to proxy")

          # Perform handshake
          case perform_reverse_handshake(socket, handler, config) do
            {:ok, _response} ->
              Logger.info("Handshake complete")
              reverse_event_loop(socket, handler, config)

              # Connection ended
              if config.reconnect do
                Logger.info("Connection lost, reconnecting in #{config.reconnect_interval}ms")
                Process.sleep(config.reconnect_interval)
                reverse_connection_loop(handler, config, 0)
              else
                :ok
              end

            {:error, reason} ->
              Logger.error("Handshake failed: #{reason}")

              if config.reconnect do
                Process.sleep(config.reconnect_interval)
                reverse_connection_loop(handler, config, attempt + 1)
              else
                {:error, reason}
              end
          end

        {:error, reason} ->
          Logger.error("Failed to connect: #{inspect(reason)}")

          if config.reconnect do
            Process.sleep(config.reconnect_interval)
            reverse_connection_loop(handler, config, attempt + 1)
          else
            {:error, reason}
          end
      end
    end
  end

  defp connect_reverse(config) do
    uri = URI.parse(config.proxy_url)

    host = uri.host || "localhost"
    port = uri.port || 80

    # Connect via TCP
    opts = [
      :binary,
      {:packet, :raw},
      {:active, false},
      {:nodelay, true}
    ]

    case :gen_tcp.connect(String.to_charlist(host), port, opts, 10_000) do
      {:ok, socket} ->
        # If HTTPS, upgrade to TLS
        if uri.scheme == "https" do
          ssl_opts = [
            verify: :verify_peer,
            cacerts: :public_key.cacerts_get()
          ]

          :ssl.connect(socket, ssl_opts, 10_000)
        else
          {:ok, socket}
        end

      error ->
        error
    end
  end

  defp perform_reverse_handshake(socket, handler, config) do
    # For reverse connections, we initiate the handshake
    request = Handler.get_handshake_request(handler, config.auth_token)
    request_map = %{"event_type" => "handshake_request", "payload" => HandshakeRequest.to_map(request)}

    case send_message(socket, request_map) do
      :ok ->
        # Wait for response
        case read_message(socket) do
          {:ok, %{"event_type" => "handshake_response", "payload" => payload}} ->
            response = HandshakeResponse.from_map(payload)
            Handler.handle_handshake_response(handler, response)

          {:ok, msg} ->
            {:error, "Unexpected response: #{inspect(msg)}"}

          error ->
            error
        end

      error ->
        error
    end
  end

  defp reverse_event_loop(socket, handler, config) do
    case read_message(socket) do
      {:ok, message} ->
        response = Handler.handle_event(handler, message)

        case send_message(socket, response) do
          :ok ->
            reverse_event_loop(socket, handler, config)

          {:error, reason} ->
            Logger.error("Failed to send response: #{reason}")
        end

      :closed ->
        Logger.info("Connection closed by proxy")
        :ok

      {:error, reason} ->
        Logger.error("Connection error: #{reason}")
    end
  end

  # Helper for sending messages over socket (handles both TCP and SSL)
  defp send_message(socket, data) when is_port(socket) do
    Protocol.write_message(socket, data)
  end

  defp send_message({:sslsocket, _, _} = socket, data) do
    case Protocol.encode_message(data) do
      {:ok, encoded} ->
        case :ssl.send(socket, encoded) do
          :ok -> :ok
          {:error, reason} -> {:error, "SSL send failed: #{inspect(reason)}"}
        end

      error ->
        error
    end
  end

  # Helper for reading messages over socket (handles both TCP and SSL)
  defp read_message(socket) when is_port(socket) do
    Protocol.read_message(socket)
  end

  defp read_message({:sslsocket, _, _} = socket) do
    case :ssl.recv(socket, 4) do
      {:ok, <<length::big-unsigned-32>>} ->
        case :ssl.recv(socket, length) do
          {:ok, json_bytes} ->
            case Jason.decode(json_bytes) do
              {:ok, decoded} -> {:ok, decoded}
              {:error, _} -> {:error, "Failed to decode JSON"}
            end

          {:error, :closed} ->
            :closed

          {:error, reason} ->
            {:error, "SSL read body failed: #{inspect(reason)}"}
        end

      {:error, :closed} ->
        :closed

      {:error, reason} ->
        {:error, "SSL read length failed: #{inspect(reason)}"}
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
