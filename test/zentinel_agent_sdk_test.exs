defmodule ZentinelAgentSdkTest do
  use ExUnit.Case
  doctest ZentinelAgentSdk

  alias ZentinelAgentSdk.{Decision, Request, Response}
  alias ZentinelAgentSdk.Protocol.{RequestHeadersEvent, RequestMetadata, ResponseHeadersEvent}

  describe "Decision" do
    test "allow returns allow decision" do
      decision = Decision.allow()
      assert decision.decision == "allow"
    end

    test "deny returns 403 block decision" do
      decision = Decision.deny()
      assert decision.decision == %{"block" => %{"status" => 403}}
    end

    test "block returns block decision with custom status" do
      decision = Decision.block(500)
      assert decision.decision == %{"block" => %{"status" => 500}}
    end

    test "unauthorized returns 401 block decision" do
      decision = Decision.unauthorized()
      assert decision.decision == %{"block" => %{"status" => 401}}
    end

    test "rate_limited returns 429 block decision" do
      decision = Decision.rate_limited()
      assert decision.decision == %{"block" => %{"status" => 429}}
    end

    test "redirect returns redirect decision" do
      decision = Decision.redirect("https://example.com")

      assert decision.decision == %{
               "redirect" => %{"url" => "https://example.com", "status" => 302}
             }
    end

    test "redirect_permanent returns 301 redirect decision" do
      decision = Decision.redirect_permanent("https://example.com")

      assert decision.decision == %{
               "redirect" => %{"url" => "https://example.com", "status" => 301}
             }
    end

    test "with_body adds body to block decision" do
      decision =
        Decision.deny()
        |> Decision.with_body("Access denied")

      assert decision.decision == %{"block" => %{"status" => 403, "body" => "Access denied"}}
    end

    test "with_json_body adds JSON body and content-type header" do
      decision =
        Decision.deny()
        |> Decision.with_json_body(%{"error" => "forbidden"})

      assert decision.decision["block"]["body"] == ~s({"error":"forbidden"})
      assert decision.decision["block"]["headers"]["Content-Type"] == "application/json"
    end

    test "add_request_header adds header operation" do
      decision =
        Decision.allow()
        |> Decision.add_request_header("X-Custom", "value")

      assert length(decision.request_headers) == 1
      [header] = decision.request_headers
      assert header.operation == :set
      assert header.name == "X-Custom"
      assert header.value == "value"
    end

    test "remove_request_header adds remove operation" do
      decision =
        Decision.allow()
        |> Decision.remove_request_header("X-Remove")

      assert length(decision.request_headers) == 1
      [header] = decision.request_headers
      assert header.operation == :remove
      assert header.name == "X-Remove"
    end

    test "with_tag adds audit tag" do
      decision =
        Decision.allow()
        |> Decision.with_tag("security")

      assert decision.audit.tags == ["security"]
    end

    test "with_tags adds multiple audit tags" do
      decision =
        Decision.allow()
        |> Decision.with_tags(["security", "blocked"])

      assert decision.audit.tags == ["security", "blocked"]
    end

    test "with_rule_id adds rule id" do
      decision =
        Decision.allow()
        |> Decision.with_rule_id("RULE_001")

      assert decision.audit.rule_ids == ["RULE_001"]
    end

    test "with_confidence sets confidence" do
      decision =
        Decision.allow()
        |> Decision.with_confidence(0.95)

      assert decision.audit.confidence == 0.95
    end

    test "with_metadata adds custom metadata" do
      decision =
        Decision.allow()
        |> Decision.with_metadata("user_id", "123")

      assert decision.audit.custom["user_id"] == "123"
    end

    test "needs_more_data sets needs_more flag" do
      decision =
        Decision.allow()
        |> Decision.needs_more_data()

      assert decision.needs_more == true
    end

    test "chaining multiple operations" do
      decision =
        Decision.deny()
        |> Decision.with_body("Blocked")
        |> Decision.with_tag("security")
        |> Decision.with_rule_id("BLOCK_ADMIN")
        |> Decision.with_confidence(1.0)
        |> Decision.add_response_header("X-Blocked", "true")

      assert decision.decision["block"]["body"] == "Blocked"
      assert decision.audit.tags == ["security"]
      assert decision.audit.rule_ids == ["BLOCK_ADMIN"]
      assert decision.audit.confidence == 1.0
      assert length(decision.response_headers) == 1
    end

    test "to_map converts decision to serializable map" do
      decision =
        Decision.deny()
        |> Decision.with_body("Blocked")
        |> Decision.with_tag("security")

      map = Decision.to_map(decision)

      assert map["version"] == 1
      assert map["decision"] == %{"block" => %{"status" => 403, "body" => "Blocked"}}
      assert map["audit"]["tags"] == ["security"]
    end
  end

  describe "Request" do
    setup do
      metadata = %RequestMetadata{
        correlation_id: "test-123",
        request_id: "req-456",
        client_ip: "192.168.1.1",
        client_port: 54321,
        server_name: "api.example.com",
        protocol: "HTTP/1.1"
      }

      event = %RequestHeadersEvent{
        metadata: metadata,
        method: "GET",
        uri: "/api/users?page=1&limit=10",
        headers: %{
          "host" => ["api.example.com"],
          "user-agent" => ["Mozilla/5.0"],
          "content-type" => ["application/json"],
          "x-custom" => ["value1", "value2"]
        }
      }

      request = Request.new(event)

      {:ok, request: request}
    end

    test "method returns HTTP method", %{request: request} do
      assert Request.method(request) == "GET"
    end

    test "is_get? returns true for GET request", %{request: request} do
      assert Request.is_get?(request) == true
      assert Request.is_post?(request) == false
    end

    test "uri returns full URI", %{request: request} do
      assert Request.uri(request) == "/api/users?page=1&limit=10"
    end

    test "path_only returns path without query string", %{request: request} do
      assert Request.path_only(request) == "/api/users"
    end

    test "query_string returns raw query string", %{request: request} do
      assert Request.query_string(request) == "page=1&limit=10"
    end

    test "query returns single query parameter", %{request: request} do
      assert Request.query(request, "page") == "1"
      assert Request.query(request, "limit") == "10"
      assert Request.query(request, "nonexistent") == nil
    end

    test "path_starts_with? checks path prefix", %{request: request} do
      assert Request.path_starts_with?(request, "/api") == true
      assert Request.path_starts_with?(request, "/admin") == false
    end

    test "path_equals? checks exact path match", %{request: request} do
      assert Request.path_equals?(request, "/api/users") == true
      assert Request.path_equals?(request, "/api") == false
    end

    test "header returns single header value", %{request: request} do
      assert Request.header(request, "host") == "api.example.com"
      assert Request.header(request, "HOST") == "api.example.com"
      assert Request.header(request, "nonexistent") == nil
    end

    test "header_all returns all header values", %{request: request} do
      assert Request.header_all(request, "x-custom") == ["value1", "value2"]
      assert Request.header_all(request, "nonexistent") == []
    end

    test "has_header? checks header existence", %{request: request} do
      assert Request.has_header?(request, "host") == true
      assert Request.has_header?(request, "nonexistent") == false
    end

    test "host returns host header", %{request: request} do
      assert Request.host(request) == "api.example.com"
    end

    test "user_agent returns user-agent header", %{request: request} do
      assert Request.user_agent(request) == "Mozilla/5.0"
    end

    test "content_type returns content-type header", %{request: request} do
      assert Request.content_type(request) == "application/json"
    end

    test "is_json? checks if content type is JSON", %{request: request} do
      assert Request.is_json?(request) == true
    end

    test "client_ip returns client IP", %{request: request} do
      assert Request.client_ip(request) == "192.168.1.1"
    end

    test "correlation_id returns correlation ID", %{request: request} do
      assert Request.correlation_id(request) == "test-123"
    end

    test "body returns empty by default", %{request: request} do
      assert Request.body(request) == <<>>
    end

    test "with_body creates new request with body", %{request: request} do
      new_request = Request.with_body(request, "test body")
      assert Request.body(new_request) == "test body"
      assert Request.body_str(new_request) == "test body"
    end

    test "body_json parses JSON body", %{request: request} do
      new_request = Request.with_body(request, ~s({"key": "value"}))
      assert Request.body_json(new_request) == %{"key" => "value"}
    end
  end

  describe "Response" do
    setup do
      event = %ResponseHeadersEvent{
        correlation_id: "test-123",
        status: 200,
        headers: %{
          "content-type" => ["application/json"],
          "x-custom" => ["value"]
        }
      }

      response = Response.new(event)

      {:ok, response: response}
    end

    test "status_code returns HTTP status", %{response: response} do
      assert Response.status_code(response) == 200
    end

    test "is_success? returns true for 2xx status", %{response: response} do
      assert Response.is_success?(response) == true
    end

    test "is_error? returns false for 2xx status", %{response: response} do
      assert Response.is_error?(response) == false
    end

    test "header returns single header value", %{response: response} do
      assert Response.header(response, "content-type") == "application/json"
    end

    test "is_json? checks if content type is JSON", %{response: response} do
      assert Response.is_json?(response) == true
    end

    test "correlation_id returns correlation ID", %{response: response} do
      assert Response.correlation_id(response) == "test-123"
    end

    test "error status codes" do
      error_event = %ResponseHeadersEvent{correlation_id: "test", status: 404, headers: %{}}
      error_response = Response.new(error_event)

      assert Response.is_client_error?(error_response) == true
      assert Response.is_error?(error_response) == true
      assert Response.is_success?(error_response) == false
    end

    test "redirect status codes" do
      redirect_event = %ResponseHeadersEvent{
        correlation_id: "test",
        status: 302,
        headers: %{"location" => ["https://example.com"]}
      }

      redirect_response = Response.new(redirect_event)

      assert Response.is_redirect?(redirect_response) == true
      assert Response.location(redirect_response) == "https://example.com"
    end
  end

  describe "Protocol" do
    alias ZentinelAgentSdk.Protocol

    test "encode_message creates length-prefixed message" do
      {:ok, encoded} = Protocol.encode_message(%{"test" => "value"})

      # First 4 bytes should be the length
      <<length::big-unsigned-32, json::binary>> = encoded
      assert length == byte_size(json)
      assert Jason.decode!(json) == %{"test" => "value"}
    end

    test "decode_message parses length-prefixed message" do
      message = %{"test" => "value"}
      {:ok, encoded} = Protocol.encode_message(message)
      {:ok, decoded} = Protocol.decode_message(encoded)

      assert decoded == message
    end

    test "encode_message rejects too large messages" do
      # Create a large message
      large_value = String.duplicate("x", 11 * 1024 * 1024)
      {:error, reason} = Protocol.encode_message(%{"data" => large_value})
      assert reason =~ "exceeds maximum"
    end

    test "parse_event_type converts string to atom" do
      assert Protocol.parse_event_type("request_headers") == :request_headers
      assert Protocol.parse_event_type("request_body_chunk") == :request_body_chunk
      assert Protocol.parse_event_type("response_headers") == :response_headers
      assert Protocol.parse_event_type("configure") == :configure
    end

    test "RequestMetadata.from_map parses metadata" do
      data = %{
        "correlation_id" => "test-123",
        "request_id" => "req-456",
        "client_ip" => "127.0.0.1",
        "client_port" => 12345
      }

      metadata = Protocol.RequestMetadata.from_map(data)

      assert metadata.correlation_id == "test-123"
      assert metadata.request_id == "req-456"
      assert metadata.client_ip == "127.0.0.1"
      assert metadata.client_port == 12345
    end

    test "HeaderOp.to_map serializes operations correctly" do
      set_op = Protocol.HeaderOp.set("X-Custom", "value")

      assert Protocol.HeaderOp.to_map(set_op) == %{
               "set" => %{"name" => "X-Custom", "value" => "value"}
             }

      remove_op = Protocol.HeaderOp.remove("X-Remove")
      assert Protocol.HeaderOp.to_map(remove_op) == %{"remove" => %{"name" => "X-Remove"}}
    end
  end
end
