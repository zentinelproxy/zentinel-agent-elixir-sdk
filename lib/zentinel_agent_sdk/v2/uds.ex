defmodule ZentinelAgentSdk.V2.UDS do
  @moduledoc """
  Agent protocol v2 over a Unix domain socket: framing and message types.

  Every message is framed as:

      +----------------+--------+-----------------+
      | length (4, BE) | type   | payload (JSON)  |
      +----------------+--------+-----------------+

  `length` counts the type byte and the payload. This matches
  `zentinel_agent_protocol::v2::uds` in the proxy.
  """

  @max_message_size 16 * 1024 * 1024

  @doc "Largest frame the proxy sends or accepts (16 MiB)."
  @spec max_message_size() :: pos_integer()
  def max_message_size, do: @max_message_size

  # Message type bytes.
  @handshake_request 0x01
  @handshake_response 0x02
  @request_headers 0x10
  @request_body_chunk 0x11
  @response_headers 0x12
  @response_body_chunk 0x13
  @request_complete 0x14
  @websocket_frame 0x15
  @guardrail_inspect 0x16
  @configure 0x17
  @agent_response 0x20
  @health_status 0x30
  @metrics_report 0x31
  @config_update_request 0x32
  @flow_control 0x33
  @cancel 0x40
  @ping 0x41
  @pong 0x42

  @types %{
    handshake_request: @handshake_request,
    handshake_response: @handshake_response,
    request_headers: @request_headers,
    request_body_chunk: @request_body_chunk,
    response_headers: @response_headers,
    response_body_chunk: @response_body_chunk,
    request_complete: @request_complete,
    websocket_frame: @websocket_frame,
    guardrail_inspect: @guardrail_inspect,
    configure: @configure,
    agent_response: @agent_response,
    health_status: @health_status,
    metrics_report: @metrics_report,
    config_update_request: @config_update_request,
    flow_control: @flow_control,
    cancel: @cancel,
    ping: @ping,
    pong: @pong
  }

  @names Map.new(@types, fn {k, v} -> {v, k} end)

  @doc "The type byte of a message type name, e.g. `:agent_response` -> `0x20`."
  @spec type_byte(atom()) :: byte()
  def type_byte(name), do: Map.fetch!(@types, name)

  @doc "The name of a type byte, or `{:unknown, byte}`."
  @spec type_name(byte()) :: atom() | {:unknown, byte()}
  def type_name(byte), do: Map.get(@names, byte, {:unknown, byte})

  # Frames that carry an event the handler answers with an AgentResponse,
  # mapped to the handler's event type.
  @event_types %{
    @request_headers => "request_headers",
    @request_body_chunk => "request_body_chunk",
    @response_headers => "response_headers",
    @response_body_chunk => "response_body_chunk",
    @request_complete => "request_complete",
    @websocket_frame => "websocket_frame",
    @guardrail_inspect => "guardrail_inspect",
    @configure => "configure"
  }

  @doc "The handler event type of an event frame, or `nil` for other frames."
  @spec event_type(byte()) :: String.t() | nil
  def event_type(byte), do: Map.get(@event_types, byte)

  # Event numbers as the UDS handshake reports them (`supported_events`).
  @uds_event_numbers %{
    "configure" => 0,
    "request_headers" => 1,
    "request_body_chunk" => 2,
    "response_headers" => 3,
    "response_body_chunk" => 4,
    "request_complete" => 5,
    "websocket_frame" => 6,
    "guardrail_inspect" => 7
  }

  @doc "The number the UDS handshake uses for an event type."
  @spec uds_event_number(String.t()) :: non_neg_integer() | nil
  def uds_event_number(event), do: Map.get(@uds_event_numbers, event)

  @doc """
  Frame a payload (iodata or a term to encode as JSON).

  Returns `{:ok, iodata}` or `{:error, reason}` when the frame is too large.
  """
  @spec encode_frame(atom() | byte(), iodata() | map()) :: {:ok, iodata()} | {:error, String.t()}
  def encode_frame(type, payload) when is_atom(type), do: encode_frame(type_byte(type), payload)

  def encode_frame(type, payload) when is_map(payload),
    do: encode_frame(type, Jason.encode_to_iodata!(payload))

  def encode_frame(type, payload) when is_integer(type) and type in 0..255 do
    size = IO.iodata_length(payload)

    if size + 1 > @max_message_size do
      {:error, "message of #{size} bytes exceeds the #{@max_message_size} byte limit"}
    else
      {:ok, [<<size + 1::big-unsigned-32, type>>, payload]}
    end
  end

  @doc """
  Decode one frame from the start of `data`.

  Returns `{:ok, type, payload, rest}`, `:more` when `data` holds no complete
  frame yet, or `{:error, reason}`.
  """
  @spec decode_frame(binary()) ::
          {:ok, byte(), binary(), binary()} | :more | {:error, String.t()}
  def decode_frame(<<0::32, _::binary>>), do: {:error, "zero-length message"}

  def decode_frame(<<length::big-unsigned-32, _::binary>>) when length > @max_message_size,
    do: {:error, "message of #{length} bytes exceeds the #{@max_message_size} byte limit"}

  def decode_frame(<<length::big-unsigned-32, type, rest::binary>>)
      when byte_size(rest) >= length - 1 do
    {payload, rest} = :erlang.split_binary(rest, length - 1)
    {:ok, type, payload, rest}
  end

  def decode_frame(_), do: :more

  @doc """
  Read one frame from a passive socket.

  Returns `{:ok, type, payload}`, `:closed`, or `{:error, reason}`.
  """
  @spec read_frame(:gen_tcp.socket() | :ssl.sslsocket()) ::
          {:ok, byte(), binary()} | :closed | {:error, String.t()}
  def read_frame(socket) do
    with {:ok, <<length::big-unsigned-32>>} <- recv(socket, 4),
         :ok <- check_length(length),
         {:ok, <<type, payload::binary>>} <- recv(socket, length) do
      {:ok, type, payload}
    else
      {:error, :closed} -> :closed
      {:error, reason} when is_binary(reason) -> {:error, reason}
      {:error, reason} -> {:error, "read failed: #{inspect(reason)}"}
    end
  end

  defp check_length(0), do: {:error, "zero-length message"}

  defp check_length(length) when length > @max_message_size,
    do: {:error, "message of #{length} bytes exceeds the #{@max_message_size} byte limit"}

  defp check_length(_), do: :ok

  @doc """
  Write one frame.

  A frame is written with a single send, so processes may share a socket
  without interleaving frames.
  """
  @spec write_frame(:gen_tcp.socket() | :ssl.sslsocket(), atom() | byte(), iodata() | map()) ::
          :ok | {:error, term()}
  def write_frame(socket, type, payload) do
    with {:ok, frame} <- encode_frame(type, payload) do
      send_data(socket, frame)
    end
  end

  defp recv({:sslsocket, _, _} = socket, n), do: :ssl.recv(socket, n)
  defp recv(socket, n), do: :gen_tcp.recv(socket, n)

  defp send_data({:sslsocket, _, _} = socket, data), do: :ssl.send(socket, data)
  defp send_data(socket, data), do: :gen_tcp.send(socket, data)
end
