defmodule ZentinelAgentSdk.Protocol do
  @moduledoc """
  Protocol definitions for Zentinel agent communication.

  This module defines the wire format and message types for communication
  between the Zentinel proxy and agents over Unix sockets.
  """

  @protocol_version 2
  # Legacy v1 message size limit (10 MB). V2 uses 16 MB (UDS) / 10 MB (gRPC).
  @max_message_size 10 * 1024 * 1024

  @doc "Returns the current protocol version."
  @spec protocol_version() :: integer()
  def protocol_version, do: @protocol_version

  @doc "Returns the maximum message size in bytes."
  @spec max_message_size() :: integer()
  def max_message_size, do: @max_message_size

  @type event_type ::
          :request_headers
          | :request_body_chunk
          | :response_headers
          | :response_body_chunk
          | :request_complete
          | :websocket_frame
          | :configure
          | :guardrail_inspect

  @type guardrail_inspection_type :: :prompt_injection | :pii_detection
  @type detection_severity :: :low | :medium | :high | :critical

  @doc """
  Parse an event type string to atom.
  """
  @spec parse_event_type(String.t()) :: event_type()
  def parse_event_type("request_headers"), do: :request_headers
  def parse_event_type("request_body_chunk"), do: :request_body_chunk
  def parse_event_type("response_headers"), do: :response_headers
  def parse_event_type("response_body_chunk"), do: :response_body_chunk
  def parse_event_type("request_complete"), do: :request_complete
  def parse_event_type("websocket_frame"), do: :websocket_frame
  def parse_event_type("configure"), do: :configure
  def parse_event_type("guardrail_inspect"), do: :guardrail_inspect
  def parse_event_type(other), do: raise("Unknown event type: #{other}")

  # Request Metadata

  defmodule RequestMetadata do
    @moduledoc "Metadata about the request being processed."

    @type t :: %__MODULE__{
            correlation_id: String.t(),
            request_id: String.t(),
            client_ip: String.t(),
            client_port: integer(),
            server_name: String.t() | nil,
            protocol: String.t(),
            tls_version: String.t() | nil,
            tls_cipher: String.t() | nil,
            route_id: String.t() | nil,
            upstream_id: String.t() | nil,
            timestamp: String.t() | nil,
            traceparent: String.t() | nil
          }

    defstruct [
      :correlation_id,
      :request_id,
      :client_ip,
      :client_port,
      :server_name,
      :tls_version,
      :tls_cipher,
      :route_id,
      :upstream_id,
      :timestamp,
      :traceparent,
      protocol: "HTTP/1.1"
    ]

    @doc "Create RequestMetadata from a map."
    @spec from_map(map()) :: t()
    def from_map(data) when is_map(data) do
      %__MODULE__{
        correlation_id: Map.get(data, "correlation_id", ""),
        request_id: Map.get(data, "request_id", ""),
        client_ip: Map.get(data, "client_ip", ""),
        client_port: Map.get(data, "client_port", 0),
        server_name: Map.get(data, "server_name"),
        protocol: Map.get(data, "protocol", "HTTP/1.1"),
        tls_version: Map.get(data, "tls_version"),
        tls_cipher: Map.get(data, "tls_cipher"),
        route_id: Map.get(data, "route_id"),
        upstream_id: Map.get(data, "upstream_id"),
        timestamp: Map.get(data, "timestamp"),
        traceparent: Map.get(data, "traceparent")
      }
    end
  end

  # Event Types

  defmodule RequestHeadersEvent do
    @moduledoc "Event for incoming request headers."

    @type t :: %__MODULE__{
            metadata: RequestMetadata.t(),
            method: String.t(),
            uri: String.t(),
            headers: %{String.t() => [String.t()]}
          }

    defstruct [:metadata, :method, :uri, headers: %{}]

    @doc "Create RequestHeadersEvent from a map."
    @spec from_map(map()) :: t()
    def from_map(data) when is_map(data) do
      %__MODULE__{
        metadata: RequestMetadata.from_map(Map.get(data, "metadata", %{})),
        method: Map.get(data, "method", "GET"),
        uri: Map.get(data, "uri", "/"),
        headers: Map.get(data, "headers", %{})
      }
    end
  end

  defmodule RequestBodyChunkEvent do
    @moduledoc "Event for request body chunks."

    @type t :: %__MODULE__{
            correlation_id: String.t(),
            data: binary(),
            chunk_index: integer(),
            is_last: boolean(),
            total_size: integer() | nil,
            bytes_received: integer()
          }

    defstruct [:correlation_id, :data, :chunk_index, :is_last, :total_size, bytes_received: 0]

    @doc "Create RequestBodyChunkEvent from a map."
    @spec from_map(map()) :: t()
    def from_map(data) when is_map(data) do
      raw_data = Map.get(data, "data", "")
      decoded = if raw_data != "", do: Base.decode64!(raw_data), else: <<>>

      %__MODULE__{
        correlation_id: Map.get(data, "correlation_id", ""),
        data: decoded,
        chunk_index: Map.get(data, "chunk_index", 0),
        is_last: Map.get(data, "is_last", true),
        total_size: Map.get(data, "total_size"),
        bytes_received: Map.get(data, "bytes_received", 0)
      }
    end
  end

  defmodule ResponseHeadersEvent do
    @moduledoc "Event for response headers from upstream."

    @type t :: %__MODULE__{
            correlation_id: String.t(),
            status: integer(),
            headers: %{String.t() => [String.t()]}
          }

    defstruct [:correlation_id, :status, headers: %{}]

    @doc "Create ResponseHeadersEvent from a map."
    @spec from_map(map()) :: t()
    def from_map(data) when is_map(data) do
      %__MODULE__{
        correlation_id: Map.get(data, "correlation_id", ""),
        status: Map.get(data, "status", 200),
        headers: Map.get(data, "headers", %{})
      }
    end
  end

  defmodule ResponseBodyChunkEvent do
    @moduledoc "Event for response body chunks."

    @type t :: %__MODULE__{
            correlation_id: String.t(),
            data: binary(),
            chunk_index: integer(),
            is_last: boolean(),
            total_size: integer() | nil,
            bytes_received: integer()
          }

    defstruct [:correlation_id, :data, :chunk_index, :is_last, :total_size, bytes_received: 0]

    @doc "Create ResponseBodyChunkEvent from a map."
    @spec from_map(map()) :: t()
    def from_map(data) when is_map(data) do
      raw_data = Map.get(data, "data", "")
      decoded = if raw_data != "", do: Base.decode64!(raw_data), else: <<>>

      %__MODULE__{
        correlation_id: Map.get(data, "correlation_id", ""),
        data: decoded,
        chunk_index: Map.get(data, "chunk_index", 0),
        is_last: Map.get(data, "is_last", true),
        total_size: Map.get(data, "total_size"),
        bytes_received: Map.get(data, "bytes_received", 0)
      }
    end
  end

  defmodule RequestCompleteEvent do
    @moduledoc "Event when request processing is complete."

    @type t :: %__MODULE__{
            correlation_id: String.t(),
            status: integer(),
            duration_ms: integer(),
            request_size: integer(),
            response_size: integer(),
            error: String.t() | nil
          }

    defstruct [:correlation_id, :status, :duration_ms, :request_size, :response_size, :error]

    @doc "Create RequestCompleteEvent from a map."
    @spec from_map(map()) :: t()
    def from_map(data) when is_map(data) do
      %__MODULE__{
        correlation_id: Map.get(data, "correlation_id", ""),
        status: Map.get(data, "status", 0),
        duration_ms: Map.get(data, "duration_ms", 0),
        request_size: Map.get(data, "request_size", 0),
        response_size: Map.get(data, "response_size", 0),
        error: Map.get(data, "error")
      }
    end
  end

  defmodule WebSocketFrameEvent do
    @moduledoc "Event for WebSocket frames."

    @type t :: %__MODULE__{
            correlation_id: String.t(),
            opcode: integer(),
            data: binary(),
            direction: String.t(),
            frame_index: integer()
          }

    defstruct [:correlation_id, :opcode, :data, :direction, :frame_index]

    @doc "Create WebSocketFrameEvent from a map."
    @spec from_map(map()) :: t()
    def from_map(data) when is_map(data) do
      raw_data = Map.get(data, "data", "")
      decoded = if raw_data != "", do: Base.decode64!(raw_data), else: <<>>

      %__MODULE__{
        correlation_id: Map.get(data, "correlation_id", ""),
        opcode: Map.get(data, "opcode", 1),
        data: decoded,
        direction: Map.get(data, "direction", "client_to_server"),
        frame_index: Map.get(data, "frame_index", 0)
      }
    end
  end

  defmodule ConfigureEvent do
    @moduledoc "Event for agent configuration."

    @type t :: %__MODULE__{
            agent_id: String.t(),
            config: map()
          }

    defstruct [:agent_id, config: %{}]

    @doc "Create ConfigureEvent from a map."
    @spec from_map(map()) :: t()
    def from_map(data) when is_map(data) do
      %__MODULE__{
        agent_id: Map.get(data, "agent_id", ""),
        config: Map.get(data, "config", %{})
      }
    end
  end

  # Guardrail Types

  defmodule TextSpan do
    @moduledoc "Byte span indicating location in content."

    @type t :: %__MODULE__{
            start: integer(),
            end_pos: integer()
          }

    defstruct [:start, :end_pos]

    @doc "Create TextSpan from a map."
    @spec from_map(map()) :: t()
    def from_map(data) when is_map(data) do
      %__MODULE__{
        start: Map.get(data, "start", 0),
        end_pos: Map.get(data, "end", 0)
      }
    end

    @doc "Convert to map for serialization."
    @spec to_map(t()) :: map()
    def to_map(%__MODULE__{} = span) do
      %{"start" => span.start, "end" => span.end_pos}
    end
  end

  defmodule GuardrailDetection do
    @moduledoc "A single guardrail detection result."

    alias ZentinelAgentSdk.Protocol.TextSpan

    @type t :: %__MODULE__{
            category: String.t(),
            description: String.t(),
            severity: atom(),
            confidence: float() | nil,
            span: TextSpan.t() | nil
          }

    defstruct [:category, :description, severity: :medium, confidence: nil, span: nil]

    @doc "Create a new detection."
    @spec new(String.t(), String.t()) :: t()
    def new(category, description) do
      %__MODULE__{category: category, description: description}
    end

    @doc "Set the severity level."
    @spec with_severity(t(), atom()) :: t()
    def with_severity(detection, severity), do: %{detection | severity: severity}

    @doc "Set the confidence score."
    @spec with_confidence(t(), float()) :: t()
    def with_confidence(detection, confidence), do: %{detection | confidence: confidence}

    @doc "Set the text span."
    @spec with_span(t(), integer(), integer()) :: t()
    def with_span(detection, start_pos, end_pos) do
      %{detection | span: %TextSpan{start: start_pos, end_pos: end_pos}}
    end

    @doc "Convert to map for serialization."
    @spec to_map(t()) :: map()
    def to_map(%__MODULE__{} = detection) do
      result = %{
        "category" => detection.category,
        "description" => detection.description,
        "severity" => Atom.to_string(detection.severity)
      }

      result =
        if detection.confidence != nil,
          do: Map.put(result, "confidence", detection.confidence),
          else: result

      result =
        if detection.span != nil,
          do: Map.put(result, "span", TextSpan.to_map(detection.span)),
          else: result

      result
    end
  end

  defmodule GuardrailInspectEvent do
    @moduledoc "Event for guardrail content inspection."

    @type t :: %__MODULE__{
            correlation_id: String.t(),
            inspection_type: atom(),
            content: String.t(),
            model: String.t() | nil,
            categories: [String.t()],
            route_id: String.t() | nil,
            metadata: map()
          }

    defstruct [
      :correlation_id,
      :inspection_type,
      :content,
      :model,
      :route_id,
      categories: [],
      metadata: %{}
    ]

    @doc "Create GuardrailInspectEvent from a map."
    @spec from_map(map()) :: t()
    def from_map(data) when is_map(data) do
      inspection_type =
        case Map.get(data, "inspection_type", "prompt_injection") do
          "prompt_injection" -> :prompt_injection
          "pii_detection" -> :pii_detection
          other -> String.to_atom(other)
        end

      %__MODULE__{
        correlation_id: Map.get(data, "correlation_id", ""),
        inspection_type: inspection_type,
        content: Map.get(data, "content", ""),
        model: Map.get(data, "model"),
        categories: Map.get(data, "categories", []),
        route_id: Map.get(data, "route_id"),
        metadata: Map.get(data, "metadata", %{})
      }
    end
  end

  defmodule GuardrailResponse do
    @moduledoc "Response from guardrail inspection."

    alias ZentinelAgentSdk.Protocol.GuardrailDetection

    @type t :: %__MODULE__{
            detected: boolean(),
            confidence: float(),
            detections: [GuardrailDetection.t()],
            redacted_content: String.t() | nil
          }

    defstruct detected: false, confidence: 0.0, detections: [], redacted_content: nil

    @doc "Create a clean response indicating nothing detected."
    @spec clean() :: t()
    def clean, do: %__MODULE__{}

    @doc "Create a response with a single detection."
    @spec with_detection(GuardrailDetection.t()) :: t()
    def with_detection(detection) do
      %__MODULE__{
        detected: true,
        confidence: detection.confidence || 1.0,
        detections: [detection]
      }
    end

    @doc "Add a detection to this response."
    @spec add_detection(t(), GuardrailDetection.t()) :: t()
    def add_detection(response, detection) do
      new_confidence = max(response.confidence, detection.confidence || 0.0)

      %{
        response
        | detected: true,
          confidence: new_confidence,
          detections: response.detections ++ [detection]
      }
    end

    @doc "Set the redacted content for PII detection."
    @spec with_redacted_content(t(), String.t()) :: t()
    def with_redacted_content(response, content) do
      %{response | redacted_content: content}
    end

    @doc "Convert to map for serialization."
    @spec to_map(t()) :: map()
    def to_map(%__MODULE__{} = response) do
      result = %{
        "detected" => response.detected,
        "confidence" => response.confidence,
        "detections" => Enum.map(response.detections, &GuardrailDetection.to_map/1)
      }

      if response.redacted_content != nil do
        Map.put(result, "redacted_content", response.redacted_content)
      else
        result
      end
    end
  end

  # Response Types

  defmodule HeaderOp do
    @moduledoc "Header operation for request/response modification."

    @type operation :: :set | :add | :remove

    @type t :: %__MODULE__{
            operation: operation(),
            name: String.t(),
            value: String.t() | nil
          }

    defstruct [:operation, :name, :value]

    @doc "Create a set header operation."
    @spec set(String.t(), String.t()) :: t()
    def set(name, value), do: %__MODULE__{operation: :set, name: name, value: value}

    @doc "Create an add header operation."
    @spec add(String.t(), String.t()) :: t()
    def add(name, value), do: %__MODULE__{operation: :add, name: name, value: value}

    @doc "Create a remove header operation."
    @spec remove(String.t()) :: t()
    def remove(name), do: %__MODULE__{operation: :remove, name: name}

    @doc "Convert to map for serialization."
    @spec to_map(t()) :: map()
    def to_map(%__MODULE__{operation: :remove, name: name}) do
      %{"remove" => %{"name" => name}}
    end

    def to_map(%__MODULE__{operation: op, name: name, value: value}) do
      %{Atom.to_string(op) => %{"name" => name, "value" => value || ""}}
    end
  end

  defmodule AuditMetadata do
    @moduledoc "Audit metadata for logging and observability."

    @type t :: %__MODULE__{
            tags: [String.t()],
            rule_ids: [String.t()],
            confidence: float() | nil,
            reason_codes: [String.t()],
            custom: map()
          }

    defstruct tags: [], rule_ids: [], confidence: nil, reason_codes: [], custom: %{}

    @doc "Convert to map for serialization."
    @spec to_map(t()) :: map()
    def to_map(%__MODULE__{} = audit) do
      result = %{}

      result = if audit.tags != [], do: Map.put(result, "tags", audit.tags), else: result

      result =
        if audit.rule_ids != [], do: Map.put(result, "rule_ids", audit.rule_ids), else: result

      result =
        if audit.confidence != nil,
          do: Map.put(result, "confidence", audit.confidence),
          else: result

      result =
        if audit.reason_codes != [],
          do: Map.put(result, "reason_codes", audit.reason_codes),
          else: result

      result = if audit.custom != %{}, do: Map.put(result, "custom", audit.custom), else: result

      result
    end
  end

  defmodule AgentResponse do
    @moduledoc "Response from agent to proxy."

    alias ZentinelAgentSdk.Protocol.{HeaderOp, AuditMetadata}

    @type t :: %__MODULE__{
            version: integer(),
            decision: String.t() | map(),
            request_headers: [HeaderOp.t()],
            response_headers: [HeaderOp.t()],
            routing_metadata: map(),
            audit: AuditMetadata.t(),
            needs_more: boolean(),
            request_body_mutation: map() | nil,
            response_body_mutation: map() | nil,
            websocket_decision: map() | nil
          }

    defstruct version: 2,
              decision: "allow",
              request_headers: [],
              response_headers: [],
              routing_metadata: %{},
              audit: %AuditMetadata{},
              needs_more: false,
              request_body_mutation: nil,
              response_body_mutation: nil,
              websocket_decision: nil

    @doc "Convert to map for serialization."
    @spec to_map(t()) :: map()
    def to_map(%__MODULE__{} = response) do
      %{
        "version" => response.version,
        "decision" => response.decision,
        "request_headers" => Enum.map(response.request_headers, &HeaderOp.to_map/1),
        "response_headers" => Enum.map(response.response_headers, &HeaderOp.to_map/1),
        "routing_metadata" => response.routing_metadata,
        "audit" => AuditMetadata.to_map(response.audit),
        "needs_more" => response.needs_more,
        "request_body_mutation" => response.request_body_mutation,
        "response_body_mutation" => response.response_body_mutation,
        "websocket_decision" => response.websocket_decision
      }
    end
  end

  # Message encoding/decoding

  @doc """
  Encode a message with length prefix for socket transmission.

  Returns `{:ok, binary}` on success, `{:error, reason}` on failure.
  """
  @spec encode_message(map()) :: {:ok, binary()} | {:error, String.t()}
  def encode_message(data) when is_map(data) do
    json_bytes = Jason.encode!(data)
    length = byte_size(json_bytes)

    if length > @max_message_size do
      {:error, "Message size #{length} exceeds maximum #{@max_message_size}"}
    else
      {:ok, <<length::big-unsigned-32>> <> json_bytes}
    end
  end

  @doc """
  Decode a length-prefixed message.

  Returns `{:ok, map}` on success, `{:error, reason}` on failure.
  """
  @spec decode_message(binary()) :: {:ok, map()} | {:error, String.t()}
  def decode_message(data) when is_binary(data) do
    if byte_size(data) < 4 do
      {:error, "Message too short to contain length prefix"}
    else
      <<length::big-unsigned-32, rest::binary>> = data

      if length > @max_message_size do
        {:error, "Message size #{length} exceeds maximum #{@max_message_size}"}
      else
        json_bytes = binary_part(rest, 0, length)

        case Jason.decode(json_bytes) do
          {:ok, decoded} -> {:ok, decoded}
          {:error, _} -> {:error, "Failed to decode JSON message"}
        end
      end
    end
  end

  @doc """
  Read a length-prefixed message from a socket.

  Returns `{:ok, map}` on success, `{:error, reason}` on failure, or `:closed` if connection closed.
  """
  @spec read_message(port()) :: {:ok, map()} | {:error, String.t()} | :closed
  def read_message(socket) do
    case :gen_tcp.recv(socket, 4) do
      {:ok, <<length::big-unsigned-32>>} ->
        if length > @max_message_size do
          {:error, "Message size #{length} exceeds maximum #{@max_message_size}"}
        else
          case :gen_tcp.recv(socket, length) do
            {:ok, json_bytes} ->
              case Jason.decode(json_bytes) do
                {:ok, decoded} -> {:ok, decoded}
                {:error, _} -> {:error, "Failed to decode JSON message"}
              end

            {:error, :closed} ->
              :closed

            {:error, reason} ->
              {:error, "Failed to read message body: #{inspect(reason)}"}
          end
        end

      {:error, :closed} ->
        :closed

      {:error, reason} ->
        {:error, "Failed to read message length: #{inspect(reason)}"}
    end
  end

  @doc """
  Write a length-prefixed message to a socket.

  Returns `:ok` on success, `{:error, reason}` on failure.
  """
  @spec write_message(port(), map()) :: :ok | {:error, String.t()}
  def write_message(socket, data) when is_map(data) do
    case encode_message(data) do
      {:ok, encoded} ->
        case :gen_tcp.send(socket, encoded) do
          :ok -> :ok
          {:error, reason} -> {:error, "Failed to send message: #{inspect(reason)}"}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Parse an incoming event from the proxy.

  Returns `{event_type, event_struct}`.
  """
  @spec parse_event(map()) ::
          {:request_headers, RequestHeadersEvent.t()}
          | {:request_body_chunk, RequestBodyChunkEvent.t()}
          | {:response_headers, ResponseHeadersEvent.t()}
          | {:response_body_chunk, ResponseBodyChunkEvent.t()}
          | {:request_complete, RequestCompleteEvent.t()}
          | {:websocket_frame, WebSocketFrameEvent.t()}
          | {:configure, ConfigureEvent.t()}
          | {:guardrail_inspect, GuardrailInspectEvent.t()}
  def parse_event(%{"type" => type} = data) do
    event_type = parse_event_type(type)
    event_data = Map.get(data, "data", data)

    event =
      case event_type do
        :request_headers -> RequestHeadersEvent.from_map(event_data)
        :request_body_chunk -> RequestBodyChunkEvent.from_map(event_data)
        :response_headers -> ResponseHeadersEvent.from_map(event_data)
        :response_body_chunk -> ResponseBodyChunkEvent.from_map(event_data)
        :request_complete -> RequestCompleteEvent.from_map(event_data)
        :websocket_frame -> WebSocketFrameEvent.from_map(event_data)
        :configure -> ConfigureEvent.from_map(event_data)
        :guardrail_inspect -> GuardrailInspectEvent.from_map(event_data)
      end

    {event_type, event}
  end
end
