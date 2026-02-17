defmodule ProtocolConformanceTest do
  @moduledoc """
  Protocol conformance tests for Zentinel Agent SDK.

  These tests verify that the Elixir SDK produces JSON that is compatible
  with the Rust protocol implementation in zentinel-agent-protocol.
  """

  use ExUnit.Case

  alias ZentinelAgentSdk.Decision
  alias ZentinelAgentSdk.Protocol
  alias ZentinelAgentSdk.Protocol.{
    HeaderOp,
    RequestBodyChunkEvent,
    RequestHeadersEvent,
    ResponseHeadersEvent
  }

  describe "Protocol Version" do
    test "protocol version is 1" do
      assert Protocol.protocol_version() == 1
    end
  end

  describe "Decision Serialization" do
    test "allow decision serializes to string 'allow'" do
      response = Decision.allow() |> Decision.build()
      data = Protocol.AgentResponse.to_map(response)
      assert data["decision"] == "allow"
    end

    test "block decision uses nested object format" do
      response = Decision.block(403) |> Decision.build()
      data = Protocol.AgentResponse.to_map(response)
      # Rust: Decision::Block { status: 403, body: None, headers: None }
      # Serde: {"block": {"status": 403}}
      assert data["decision"] == %{"block" => %{"status" => 403}}
    end

    test "block with body includes body field" do
      response = Decision.block(403) |> Decision.with_body("Forbidden") |> Decision.build()
      data = Protocol.AgentResponse.to_map(response)
      assert data["decision"]["block"]["status"] == 403
      assert data["decision"]["block"]["body"] == "Forbidden"
    end

    test "block with headers includes headers map" do
      response =
        Decision.block(403)
        |> Decision.with_body("Forbidden")
        |> Decision.with_block_header("X-Reason", "policy")
        |> Decision.build()

      data = Protocol.AgentResponse.to_map(response)
      assert data["decision"]["block"]["headers"] == %{"X-Reason" => "policy"}
    end

    test "redirect decision uses nested object format" do
      response = Decision.redirect("/login", 302) |> Decision.build()
      data = Protocol.AgentResponse.to_map(response)
      # Rust: Decision::Redirect { url: "/login", status: 302 }
      assert data["decision"] == %{"redirect" => %{"url" => "/login", "status" => 302}}
    end

    test "challenge decision uses nested object format" do
      response = Decision.challenge("captcha", %{"site_key" => "abc123"}) |> Decision.build()
      data = Protocol.AgentResponse.to_map(response)
      # Rust: Decision::Challenge { challenge_type: "captcha", params: {...} }
      assert data["decision"]["challenge"]["challenge_type"] == "captcha"
      assert data["decision"]["challenge"]["params"] == %{"site_key" => "abc123"}
    end
  end

  describe "HeaderOp Serialization" do
    test "set header uses nested object format" do
      op = HeaderOp.set("X-Custom", "value")
      data = HeaderOp.to_map(op)
      # Rust: HeaderOp::Set { name: "X-Custom", value: "value" }
      assert data == %{"set" => %{"name" => "X-Custom", "value" => "value"}}
    end

    test "add header uses nested object format" do
      op = HeaderOp.add("X-Custom", "value")
      data = HeaderOp.to_map(op)
      assert data == %{"add" => %{"name" => "X-Custom", "value" => "value"}}
    end

    test "remove header uses nested object format" do
      op = HeaderOp.remove("X-Custom")
      data = HeaderOp.to_map(op)
      # Rust: HeaderOp::Remove { name: "X-Custom" }
      assert data == %{"remove" => %{"name" => "X-Custom"}}
    end
  end

  describe "AgentResponse Serialization" do
    test "response has all expected fields" do
      response = Decision.allow() |> Decision.build()
      data = Protocol.AgentResponse.to_map(response)

      # Required fields per Rust AgentResponse
      assert Map.has_key?(data, "version")
      assert Map.has_key?(data, "decision")
      assert Map.has_key?(data, "request_headers")
      assert Map.has_key?(data, "response_headers")
      assert Map.has_key?(data, "routing_metadata")
      assert Map.has_key?(data, "audit")
      assert Map.has_key?(data, "needs_more")
      assert Map.has_key?(data, "request_body_mutation")
      assert Map.has_key?(data, "response_body_mutation")
      assert Map.has_key?(data, "websocket_decision")
    end

    test "response version must be protocol version" do
      response = Decision.allow() |> Decision.build()
      data = Protocol.AgentResponse.to_map(response)
      assert data["version"] == Protocol.protocol_version()
    end

    test "response includes header operations" do
      response =
        Decision.allow()
        |> Decision.add_request_header("X-Forwarded-By", "zentinel")
        |> Decision.remove_request_header("X-Internal")
        |> Decision.add_response_header("X-Cache", "HIT")
        |> Decision.build()

      data = Protocol.AgentResponse.to_map(response)

      assert length(data["request_headers"]) == 2

      assert Enum.at(data["request_headers"], 0) == %{
               "set" => %{"name" => "X-Forwarded-By", "value" => "zentinel"}
             }

      assert Enum.at(data["request_headers"], 1) == %{"remove" => %{"name" => "X-Internal"}}
      assert length(data["response_headers"]) == 1
    end

    test "response includes audit metadata" do
      response =
        Decision.deny()
        |> Decision.with_tag("security")
        |> Decision.with_tags(["blocked", "waf"])
        |> Decision.with_rule_id("RULE-001")
        |> Decision.with_confidence(0.95)
        |> Decision.with_reason_code("SQL_INJECTION")
        |> Decision.with_metadata("matched_pattern", "SELECT.*FROM")
        |> Decision.build()

      data = Protocol.AgentResponse.to_map(response)
      audit = data["audit"]

      assert audit["tags"] == ["security", "blocked", "waf"]
      assert audit["rule_ids"] == ["RULE-001"]
      assert audit["confidence"] == 0.95
      assert audit["reason_codes"] == ["SQL_INJECTION"]
      assert audit["custom"]["matched_pattern"] == "SELECT.*FROM"
    end
  end

  describe "Event Deserialization" do
    test "parse RequestHeadersEvent from Rust format" do
      # This is what Rust would send
      rust_json = %{
        "metadata" => %{
          "correlation_id" => "req-123",
          "request_id" => "internal-456",
          "client_ip" => "192.168.1.1",
          "client_port" => 54321,
          "server_name" => "api.example.com",
          "protocol" => "HTTP/2",
          "tls_version" => "TLSv1.3",
          "tls_cipher" => "TLS_AES_256_GCM_SHA384",
          "route_id" => "api-route",
          "upstream_id" => "backend-pool",
          "timestamp" => "2024-01-15T10:30:00Z",
          "traceparent" => "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        },
        "method" => "POST",
        "uri" => "/api/users?include=profile",
        "headers" => %{
          "content-type" => ["application/json"],
          "accept" => ["application/json", "text/plain"],
          "x-request-id" => ["abc123"]
        }
      }

      event = RequestHeadersEvent.from_map(rust_json)

      assert event.metadata.correlation_id == "req-123"
      assert event.metadata.client_ip == "192.168.1.1"
      assert event.metadata.client_port == 54321
      assert event.metadata.tls_version == "TLSv1.3"
      assert event.metadata.traceparent != nil
      assert event.method == "POST"
      assert event.uri == "/api/users?include=profile"
      assert event.headers["content-type"] == ["application/json"]
      assert length(event.headers["accept"]) == 2
    end

    test "parse RequestBodyChunkEvent with base64 data" do
      body_data = ~s({"name": "test"})

      rust_json = %{
        "correlation_id" => "req-123",
        "data" => Base.encode64(body_data),
        "is_last" => true,
        "total_size" => 16,
        "chunk_index" => 0,
        "bytes_received" => 16
      }

      event = RequestBodyChunkEvent.from_map(rust_json)

      assert event.correlation_id == "req-123"
      assert event.data == body_data
      assert event.is_last == true
      assert event.chunk_index == 0
    end

    test "parse ResponseHeadersEvent from Rust format" do
      rust_json = %{
        "correlation_id" => "req-123",
        "status" => 200,
        "headers" => %{
          "content-type" => ["application/json"],
          "cache-control" => ["max-age=3600"]
        }
      }

      event = ResponseHeadersEvent.from_map(rust_json)

      assert event.correlation_id == "req-123"
      assert event.status == 200
      assert event.headers["content-type"] == ["application/json"]
    end
  end

  describe "AgentRequest Envelope" do
    test "request envelope structure" do
      # This is what the proxy sends to agents
      envelope = %{
        "version" => 1,
        "event_type" => "request_headers",
        "payload" => %{
          "metadata" => %{
            "correlation_id" => "req-123",
            "request_id" => "internal-456",
            "client_ip" => "127.0.0.1",
            "client_port" => 12345,
            "protocol" => "HTTP/1.1",
            "timestamp" => "2024-01-15T10:30:00Z"
          },
          "method" => "GET",
          "uri" => "/health",
          "headers" => %{}
        }
      }

      assert envelope["version"] == Protocol.protocol_version()
      assert envelope["event_type"] == "request_headers"
      assert Map.has_key?(envelope, "payload")
    end

    test "event types use snake_case" do
      valid_event_types = [
        "configure",
        "request_headers",
        "request_body_chunk",
        "response_headers",
        "response_body_chunk",
        "request_complete",
        "websocket_frame"
      ]

      # These match the Rust EventType enum with #[serde(rename_all = "snake_case")]
      for event_type <- valid_event_types do
        assert String.contains?(event_type, "_") or event_type == "configure"
      end
    end
  end

  describe "Wire Format Round-Trip" do
    test "response JSON roundtrip" do
      response =
        Decision.block(403)
        |> Decision.with_body("Access denied")
        |> Decision.with_tag("security")
        |> Decision.add_request_header("X-Blocked", "true")
        |> Decision.build()

      # Serialize to JSON (what we send to proxy)
      json_str = response |> Protocol.AgentResponse.to_map() |> Jason.encode!()

      # Parse back (simulating what Rust would receive)
      parsed = Jason.decode!(json_str)

      # Verify structure matches Rust expectations
      assert parsed["version"] == 1
      assert parsed["decision"]["block"]["status"] == 403
      assert parsed["decision"]["block"]["body"] == "Access denied"
      assert parsed["audit"]["tags"] == ["security"]
      assert Enum.at(parsed["request_headers"], 0)["set"]["name"] == "X-Blocked"
    end
  end

  describe "Body Mutation Format" do
    test "body mutation has data and chunk_index fields" do
      response =
        Decision.allow()
        |> Decision.with_request_body_mutation("modified content", 0)
        |> Decision.build()

      data = Protocol.AgentResponse.to_map(response)
      mutation = data["request_body_mutation"]

      assert mutation != nil
      assert Map.has_key?(mutation, "data")
      assert Map.has_key?(mutation, "chunk_index")
      assert mutation["chunk_index"] == 0
      # Data should be base64 encoded
      assert mutation["data"] == Base.encode64("modified content")
    end

    test "pass-through mutation has nil data" do
      # In Rust: BodyMutation { data: None, chunk_index: 0 }
      # This means "use original chunk unchanged"
      response = Decision.allow() |> Decision.build()
      data = Protocol.AgentResponse.to_map(response)
      # No mutation = pass through
      assert data["request_body_mutation"] == nil
    end
  end
end
