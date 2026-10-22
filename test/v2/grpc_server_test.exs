defmodule ZentinelAgentSdk.V2.GrpcServerTest do
  @moduledoc """
  Conversions between the proxy's protobuf messages and the handler's JSON
  shapes. The stream itself (headers on open, handshake, Configure + Ping,
  events, reconnect) is checked against a real proxy by the conformance
  harness (test/integration/conformance_test.exs, and CI).
  """

  use ExUnit.Case, async: true

  alias ZentinelAgentSdk.Decision
  alias ZentinelAgentSdk.V2.GrpcServer
  alias ZentinelAgentSdk.V2.Proto
  alias ZentinelAgentSdk.V2.Types.AgentCapabilities

  test "parses host:port addresses" do
    assert GrpcServer.parse_address("127.0.0.1:50051") == {{127, 0, 0, 1}, 50051}
    assert GrpcServer.parse_address("0.0.0.0:1") == {{0, 0, 0, 0}, 1}
    assert GrpcServer.parse_address("localhost:2") == {{127, 0, 0, 1}, 2}
    assert GrpcServer.parse_address("[::1]:3") == {{0, 0, 0, 0, 0, 0, 0, 1}, 3}
    assert_raise ArgumentError, fn -> GrpcServer.parse_address("/tmp/agent.sock") end
  end

  test "converts request headers to the handler's shape" do
    ev = %Proto.RequestHeadersEvent{
      metadata: %Proto.RequestMetadata{correlation_id: "c1", client_ip: "10.0.0.1"},
      method: "POST",
      uri: "/x?y=1",
      headers: [
        %Proto.Header{name: "a", value: "1"},
        %Proto.Header{name: "a", value: "2"},
        %Proto.Header{name: "b", value: "3"}
      ]
    }

    map = GrpcServer.event_to_map(:request_headers, ev)
    assert map["metadata"]["correlation_id"] == "c1"
    assert map["method"] == "POST"
    assert map["headers"] == %{"a" => ["1", "2"], "b" => ["3"]}
  end

  test "body chunks are base64 in the handler's shape" do
    ev = %Proto.BodyChunkEvent{correlation_id: "c", data: "hi", is_last: true}
    map = GrpcServer.event_to_map(:request_body_chunk, ev)
    assert Base.decode64!(map["data"]) == "hi"
    assert map["is_last"]
  end

  test "converts a block response with header mutations" do
    response =
      Decision.block(403)
      |> Decision.with_body("no")
      |> Decision.add_request_header("X-A", "1")
      |> Decision.add_response_header("X-B", "2")
      |> Decision.remove_request_header("X-C")
      |> Decision.with_tag("t")
      |> Decision.to_map()

    proto = GrpcServer.response_to_proto("cid", response)
    assert proto.correlation_id == "cid"
    assert {:block, %Proto.BlockDecision{status: 403, body: "no"}} = proto.decision

    assert [
             %Proto.HeaderOp{operation: {:set, %Proto.Header{name: "X-A", value: "1"}}},
             %Proto.HeaderOp{operation: {:remove, "X-C"}}
           ] = proto.request_headers

    assert [%Proto.HeaderOp{operation: {:set, %Proto.Header{name: "X-B"}}}] =
             proto.response_headers

    assert proto.audit.tags == ["t"]
    # Encodes as a valid AgentToProxy message.
    assert is_binary(Proto.AgentToProxy.encode(%Proto.AgentToProxy{message: {:response, proto}}))
  end

  test "an allow response becomes AllowDecision" do
    proto = GrpcServer.response_to_proto("c", Decision.allow() |> Decision.to_map())
    assert {:allow, %Proto.AllowDecision{}} = proto.decision
    assert proto.audit == nil
  end

  test "capabilities use the gRPC event numbers" do
    caps =
      AgentCapabilities.new()
      |> AgentCapabilities.with_name("n")
      |> AgentCapabilities.handles_request_body()

    proto = GrpcServer.capabilities_to_proto(caps)
    assert proto.protocol_version == 2
    assert proto.agent_id == "n"
    assert 1 in proto.supported_events
    assert 2 in proto.supported_events
    assert proto.limits.max_body_size > 0
  end
end
