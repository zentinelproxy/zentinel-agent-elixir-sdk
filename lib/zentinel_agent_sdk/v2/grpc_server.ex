defmodule ZentinelAgentSdk.V2.GrpcServer do
  @moduledoc """
  Agent protocol v2 over gRPC: the `zentinel.agent.v2.AgentServiceV2` service.

  The proxy opens one bidirectional `ProcessStream` per connection and sends
  a handshake, then a `ConfigureEvent` followed by a `Ping`; the `Pong` tells
  it the configuration was applied. Events follow. Messages are converted to
  the JSON shapes `ZentinelAgentSdk.V2.Handler` works with, so both transports
  run the same agent code.

  Started by `ZentinelAgentSdk.V2.run/2` with `transport: :grpc` (or `:both`)
  and `grpc_address: "host:port"`.
  """

  require Logger

  alias ZentinelAgentSdk.V2.Handler
  alias ZentinelAgentSdk.V2.Types.AgentCapabilities
  alias ZentinelAgentSdk.V2.Proto

  @protocol_version 2

  # gRPC `EventType` numbers (they differ from the UDS handshake's).
  @grpc_event_numbers %{
    "request_headers" => 1,
    "request_body_chunk" => 2,
    "response_headers" => 3,
    "response_body_chunk" => 4,
    "request_complete" => 5,
    "websocket_frame" => 6,
    "guardrail_inspect" => 7,
    "configure" => 8
  }

  @event_kinds %{
    request_headers: "request_headers",
    request_body_chunk: "request_body_chunk",
    response_headers: "response_headers",
    response_body_chunk: "response_body_chunk",
    request_complete: "request_complete",
    guardrail: "guardrail_inspect",
    websocket_frame: "websocket_frame"
  }

  defmodule Service do
    @moduledoc false
    use GRPC.Service,
      name: "zentinel.agent.v2.AgentServiceV2",
      protoc_gen_elixir_version: "0.17.1"

    rpc(
      :ProcessStream,
      stream(ZentinelAgentSdk.V2.Proto.ProxyToAgent),
      stream(ZentinelAgentSdk.V2.Proto.AgentToProxy)
    )

    rpc(
      :ControlStream,
      stream(ZentinelAgentSdk.V2.Proto.AgentControl),
      stream(ZentinelAgentSdk.V2.Proto.ProxyControl)
    )

    rpc(
      :ProcessEvent,
      ZentinelAgentSdk.V2.Proto.ProxyToAgent,
      ZentinelAgentSdk.V2.Proto.AgentToProxy
    )
  end

  defmodule Server do
    @moduledoc false
    use GRPC.Server, service: ZentinelAgentSdk.V2.GrpcServer.Service

    alias ZentinelAgentSdk.V2.GrpcServer

    def process_stream(requests, stream), do: GrpcServer.process_stream(requests, stream)
    def control_stream(requests, _stream), do: Enum.each(requests, fn _ -> :ok end)
    def process_event(request, _stream), do: GrpcServer.process_event(request)
  end

  # ==========================================================================
  # Lifecycle
  # ==========================================================================

  @doc """
  Start the gRPC server on `address` (`"host:port"`), serving `handler`.

  Returns `{:ok, pid}` of the server's supervisor. The handler is shared by
  every stream; only one gRPC agent can run per BEAM node.
  """
  @spec start_link(GenServer.server(), String.t()) :: Supervisor.on_start()
  def start_link(handler, address) do
    {ip, port} = parse_address(address)
    :persistent_term.put({__MODULE__, :handler}, handler)

    GRPC.Server.Supervisor.start_link(
      servers: [Server],
      port: port,
      start_server: true,
      adapter_opts: [ip: ip]
    )
  end

  @doc false
  @spec parse_address(String.t()) :: {:inet.ip_address(), :inet.port_number()}
  def parse_address(address) do
    {host, port} =
      case Regex.run(~r/^\[?(.*?)\]?:(\d+)$/, address) do
        [_, host, port] -> {host, String.to_integer(port)}
        _ -> raise ArgumentError, "gRPC address must be host:port, got #{inspect(address)}"
      end

    ip =
      case host do
        "" ->
          {0, 0, 0, 0}

        "localhost" ->
          {127, 0, 0, 1}

        host ->
          case :inet.parse_address(String.to_charlist(host)) do
            {:ok, ip} -> ip
            {:error, _} -> raise ArgumentError, "not an IP address: #{inspect(host)}"
          end
      end

    {ip, port}
  end

  defp handler, do: :persistent_term.get({__MODULE__, :handler})

  # ==========================================================================
  # ProcessStream
  # ==========================================================================

  @doc false
  def process_stream(requests, stream) do
    # The proxy waits for the response headers before it sends the
    # handshake; without this they would be held back until the first reply.
    GRPC.Server.send_headers(stream, %{})
    handler = handler()

    tasks =
      Enum.reduce_while(requests, [], fn msg, tasks ->
        tasks = Enum.reject(tasks, &done?/1)

        case msg.message do
          {:handshake, req} ->
            GRPC.Server.send_reply(stream, handshake(handler, req))
            {:cont, tasks}

          {:configure, ev} ->
            # Handled in order: the Ping that follows must not be answered
            # before the configuration is applied.
            if configure(handler, ev) do
              {:cont, tasks}
            else
              Logger.error("Configuration rejected; ending the stream")
              {:halt, tasks}
            end

          {:ping, ping} ->
            GRPC.Server.send_reply(stream, pong(ping))
            {:cont, tasks}

          {kind, ev} when is_map_key(@event_kinds, kind) ->
            task =
              Task.async(fn -> GRPC.Server.send_reply(stream, event(handler, kind, ev)) end)

            {:cont, [task | tasks]}

          _ ->
            {:cont, tasks}
        end
      end)

    Enum.each(tasks, &Task.await(&1, :infinity))
    stream
  end

  defp done?(%Task{} = task) do
    case Task.yield(task, 0) do
      nil -> false
      _ -> true
    end
  end

  @doc false
  def process_event(request) do
    handler = handler()

    case request.message do
      {:handshake, req} -> handshake(handler, req)
      {:ping, ping} -> pong(ping)
      {:configure, ev} -> tap(%Proto.AgentToProxy{}, fn _ -> configure(handler, ev) end)
      {kind, ev} when is_map_key(@event_kinds, kind) -> event(handler, kind, ev)
      _ -> %Proto.AgentToProxy{}
    end
  end

  defp handshake(handler, %Proto.HandshakeRequest{} = req) do
    caps = Handler.get_capabilities(handler)
    ok = @protocol_version in req.supported_versions

    %Proto.AgentToProxy{
      message:
        {:handshake,
         %Proto.HandshakeResponse{
           protocol_version: @protocol_version,
           capabilities: capabilities_to_proto(caps),
           success: ok,
           error:
             if(ok,
               do: nil,
               else: "protocol v2 not offered (proxy supports #{inspect(req.supported_versions)})"
             )
         }}
    }
  end

  defp configure(handler, %Proto.ConfigureEvent{} = ev) do
    case decode_config(ev.config_json) do
      {:ok, config} ->
        response =
          Handler.dispatch(handler, "configure", %{
            "config" => config,
            "config_version" => ev.config_version
          })

        response["decision"] == "allow"

      {:error, reason} ->
        Logger.error("Configuration is not valid JSON: #{inspect(reason)}")
        false
    end
  end

  defp decode_config(nil), do: {:ok, %{}}
  defp decode_config(""), do: {:ok, %{}}
  defp decode_config(json), do: Jason.decode(json)

  defp pong(%Proto.Ping{} = ping) do
    %Proto.AgentToProxy{
      message:
        {:pong,
         %Proto.Pong{
           sequence: ping.sequence,
           ping_timestamp_ms: ping.timestamp_ms,
           timestamp_ms: System.system_time(:millisecond)
         }}
    }
  end

  defp event(handler, kind, ev) do
    payload = event_to_map(kind, ev)
    response = Handler.dispatch(handler, Map.fetch!(@event_kinds, kind), payload)
    cid = payload["correlation_id"] || get_in(payload, ["metadata", "correlation_id"]) || ""
    %Proto.AgentToProxy{message: {:response, response_to_proto(cid, response)}}
  end

  # ==========================================================================
  # Conversions
  # ==========================================================================

  @doc false
  @spec capabilities_to_proto(AgentCapabilities.t()) :: Proto.AgentCapabilities.t()
  def capabilities_to_proto(%AgentCapabilities{} = caps) do
    f = AgentCapabilities.features(caps)
    l = AgentCapabilities.limits(caps)

    %Proto.AgentCapabilities{
      protocol_version: @protocol_version,
      agent_id: caps.agent_name,
      name: caps.agent_name,
      version: caps.agent_version,
      supported_events:
        caps
        |> AgentCapabilities.supported_events()
        |> Enum.map(&Map.fetch!(@grpc_event_numbers, &1)),
      features: %Proto.AgentFeatures{
        streaming_body: f["streaming_body"],
        websocket: f["websocket"],
        guardrails: f["guardrails"],
        config_push: f["config_push"],
        metrics_export: f["metrics_export"],
        concurrent_requests: f["concurrent_requests"],
        cancellation: f["cancellation"],
        flow_control: f["flow_control"],
        health_reporting: f["health_reporting"]
      },
      limits: %Proto.AgentLimits{
        max_body_size: l["max_body_size"],
        max_concurrency: l["max_concurrency"],
        preferred_chunk_size: l["preferred_chunk_size"]
      },
      health_config: %Proto.HealthConfig{report_interval_ms: 30_000}
    }
  end

  defp headers_map(headers) do
    Enum.reduce(headers, %{}, fn %{name: name, value: value}, acc ->
      Map.update(acc, name, [value], &(&1 ++ [value]))
    end)
  end

  @doc "Convert a `ProxyToAgent` event to the handler's JSON shape."
  @spec event_to_map(atom(), struct()) :: map()
  def event_to_map(:request_headers, ev) do
    md = ev.metadata || %Proto.RequestMetadata{}

    %{
      "metadata" => %{
        "correlation_id" => md.correlation_id,
        "request_id" => md.request_id,
        "client_ip" => md.client_ip,
        "client_port" => md.client_port,
        "server_name" => md.server_name,
        "protocol" => md.protocol,
        "tls_version" => md.tls_version,
        "route_id" => md.route_id,
        "upstream_id" => md.upstream_id,
        "timestamp" => Integer.to_string(md.timestamp_ms),
        "traceparent" => md.traceparent
      },
      "method" => ev.method,
      "uri" => ev.uri,
      "headers" => headers_map(ev.headers)
    }
  end

  def event_to_map(kind, ev) when kind in [:request_body_chunk, :response_body_chunk] do
    key = if kind == :request_body_chunk, do: "bytes_received", else: "bytes_sent"

    %{
      "correlation_id" => ev.correlation_id,
      "data" => Base.encode64(ev.data),
      "is_last" => ev.is_last,
      "total_size" => ev.total_size,
      "chunk_index" => ev.chunk_index,
      key => ev.bytes_transferred
    }
  end

  def event_to_map(:response_headers, ev) do
    %{
      "correlation_id" => ev.correlation_id,
      "status" => ev.status_code,
      "headers" => headers_map(ev.headers)
    }
  end

  def event_to_map(:request_complete, ev) do
    %{
      "correlation_id" => ev.correlation_id,
      "status" => ev.status_code,
      "duration_ms" => ev.duration_ms,
      "request_body_size" => ev.bytes_received,
      "response_body_size" => ev.bytes_sent,
      "error" => ev.error
    }
  end

  def event_to_map(:guardrail, ev) do
    %{
      "correlation_id" => ev.correlation_id,
      "content" => ev.content,
      "model" => ev.model,
      "inspection_type" => "prompt_injection"
    }
  end

  def event_to_map(:websocket_frame, ev) do
    %{
      "correlation_id" => ev.correlation_id,
      "data" => Base.encode64(ev.payload),
      "client_to_server" => ev.client_to_server
    }
  end

  defp header_op(%{"set" => %{"name" => name} = h}),
    do: %Proto.HeaderOp{operation: {:set, %Proto.Header{name: name, value: h["value"] || ""}}}

  defp header_op(%{"add" => %{"name" => name} = h}),
    do: %Proto.HeaderOp{operation: {:add, %Proto.Header{name: name, value: h["value"] || ""}}}

  defp header_op(%{"remove" => %{"name" => name}}),
    do: %Proto.HeaderOp{operation: {:remove, name}}

  defp header_op(_), do: nil

  defp header_ops(ops), do: (ops || []) |> Enum.map(&header_op/1) |> Enum.reject(&is_nil/1)

  defp decision_to_proto(%{"block" => b}) do
    {:block,
     %Proto.BlockDecision{
       status: b["status"] || 403,
       body: b["body"],
       headers:
         Enum.map(b["headers"] || %{}, fn {k, v} -> %Proto.Header{name: k, value: "#{v}"} end)
     }}
  end

  defp decision_to_proto(%{"redirect" => r}),
    do: {:redirect, %Proto.RedirectDecision{url: r["url"], status: r["status"] || 302}}

  defp decision_to_proto(%{"challenge" => c}) do
    {:challenge,
     %Proto.ChallengeDecision{
       challenge_type: c["challenge_type"] || "",
       params: Map.new(c["params"] || %{}, fn {k, v} -> {k, "#{v}"} end)
     }}
  end

  defp decision_to_proto(_), do: {:allow, %Proto.AllowDecision{}}

  defp audit_to_proto(audit) when is_map(audit) and map_size(audit) > 0 do
    %Proto.AuditMetadata{
      tags: audit["tags"] || [],
      rule_ids: audit["rule_ids"] || [],
      reason_codes: audit["reason_codes"] || [],
      confidence: audit["confidence"] && audit["confidence"] / 1,
      custom:
        Map.new(audit["custom"] || %{}, fn
          {k, v} when is_binary(v) -> {k, v}
          {k, v} -> {k, Jason.encode!(v)}
        end)
    }
  end

  defp audit_to_proto(_), do: nil

  @doc "Convert an `AgentResponse` map to the protobuf message."
  @spec response_to_proto(String.t(), map()) :: Proto.AgentResponse.t()
  def response_to_proto(correlation_id, response) do
    %Proto.AgentResponse{
      correlation_id: correlation_id,
      decision: decision_to_proto(response["decision"]),
      request_headers: header_ops(response["request_headers"]),
      response_headers: header_ops(response["response_headers"]),
      audit: audit_to_proto(response["audit"]),
      needs_more: response["needs_more"] == true
    }
  end
end
