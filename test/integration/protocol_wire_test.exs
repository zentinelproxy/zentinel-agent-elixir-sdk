defmodule Integration.ProtocolWireTest do
  @moduledoc """
  Wire protocol integration tests.

  These tests verify that the SDK correctly handles the wire protocol
  by testing handler functionality with simulated proxy events.
  """

  use ExUnit.Case

  alias ZentinelAgentSdk.{Decision, Request}
  alias ZentinelAgentSdk.Protocol
  alias ZentinelAgentSdk.Runner.Handler

  # Simple test agent module
  defmodule SimpleTestAgent do
    use ZentinelAgentSdk.Agent

    @impl true
    def name, do: "test-agent"

    @impl true
    def on_request(request) do
      if Request.path_starts_with?(request, "/block") do
        Decision.deny()
        |> Decision.with_body("Blocked")
        |> Decision.with_tag("blocked")
      else
        Decision.allow()
        |> Decision.add_response_header("X-Test", "value")
        |> Decision.with_tag("allowed")
      end
    end
  end

  defp create_handler do
    config = %ZentinelAgentSdk.Runner.Config{
      socket_path: "/tmp/test.sock",
      name: "test-agent",
      json_logs: false,
      log_level: :info
    }

    Handler.new(SimpleTestAgent, config)
  end

  describe "Wire Protocol Round-Trip" do
    test "request headers event handling" do
      handler = create_handler()

      # Simulate what Zentinel sends
      request_event = %{
        "version" => Protocol.protocol_version(),
        "event_type" => "request_headers",
        "payload" => %{
          "metadata" => %{
            "correlation_id" => "test-corr-123",
            "request_id" => "req-456",
            "client_ip" => "192.168.1.100",
            "client_port" => 54321,
            "server_name" => "api.example.com",
            "protocol" => "HTTP/1.1",
            "timestamp" => "2024-01-15T10:30:00Z"
          },
          "method" => "GET",
          "uri" => "/allowed/path?foo=bar",
          "headers" => %{
            "host" => ["api.example.com"],
            "user-agent" => ["test-client/1.0"],
            "accept" => ["application/json"]
          }
        }
      }

      # Handle the event
      {response, _handler} = Handler.handle_event(handler, request_event)

      # Verify response format
      assert response["version"] == Protocol.protocol_version()
      assert response["decision"] == "allow"

      # Check that X-Test header was added
      response_headers = response["response_headers"]

      assert Enum.any?(response_headers, fn h ->
               h["set"]["name"] == "X-Test" and h["set"]["value"] == "value"
             end)

      assert "allowed" in response["audit"]["tags"]
    end

    test "block decision wire format" do
      handler = create_handler()

      request_event = %{
        "version" => Protocol.protocol_version(),
        "event_type" => "request_headers",
        "payload" => %{
          "metadata" => %{
            "correlation_id" => "test-block-123",
            "request_id" => "req-789",
            "client_ip" => "10.0.0.1",
            "client_port" => 12345,
            "protocol" => "HTTP/1.1",
            "timestamp" => "2024-01-15T10:30:00Z"
          },
          "method" => "GET",
          "uri" => "/block/this",
          "headers" => %{}
        }
      }

      {response, _handler} = Handler.handle_event(handler, request_event)

      # Verify block response format
      assert response["version"] == Protocol.protocol_version()
      assert is_map(response["decision"])
      assert Map.has_key?(response["decision"], "block")
      assert response["decision"]["block"]["status"] == 403
      assert response["decision"]["block"]["body"] == "Blocked"
      assert "blocked" in response["audit"]["tags"]
    end

    test "configure event handling" do
      handler = create_handler()

      config_event = %{
        "version" => Protocol.protocol_version(),
        "event_type" => "configure",
        "payload" => %{
          "agent_id" => "test-agent",
          "config" => %{"key" => "value"}
        }
      }

      {response, _handler} = Handler.handle_event(handler, config_event)
      assert response["success"] == true
    end

    test "response headers event handling" do
      handler = create_handler()

      # First, send request headers to cache the request
      request_event = %{
        "version" => Protocol.protocol_version(),
        "event_type" => "request_headers",
        "payload" => %{
          "metadata" => %{
            "correlation_id" => "test-resp-123",
            "request_id" => "req-101",
            "client_ip" => "127.0.0.1",
            "client_port" => 11111,
            "protocol" => "HTTP/1.1",
            "timestamp" => "2024-01-15T10:30:00Z"
          },
          "method" => "GET",
          "uri" => "/test",
          "headers" => %{}
        }
      }

      {_response, handler} = Handler.handle_event(handler, request_event)

      # Now send response headers
      response_event = %{
        "version" => Protocol.protocol_version(),
        "event_type" => "response_headers",
        "payload" => %{
          "correlation_id" => "test-resp-123",
          "status" => 200,
          "headers" => %{
            "content-type" => ["application/json"]
          }
        }
      }

      {response, _handler} = Handler.handle_event(handler, response_event)

      assert response["version"] == Protocol.protocol_version()
      assert response["decision"] == "allow"
    end

    test "request complete event handling" do
      handler = create_handler()

      # First, cache a request
      request_event = %{
        "version" => Protocol.protocol_version(),
        "event_type" => "request_headers",
        "payload" => %{
          "metadata" => %{
            "correlation_id" => "test-complete-123",
            "request_id" => "req-202",
            "client_ip" => "127.0.0.1",
            "client_port" => 22222,
            "protocol" => "HTTP/1.1",
            "timestamp" => "2024-01-15T10:30:00Z"
          },
          "method" => "GET",
          "uri" => "/test",
          "headers" => %{}
        }
      }

      {_response, handler} = Handler.handle_event(handler, request_event)

      # Send request complete
      complete_event = %{
        "version" => Protocol.protocol_version(),
        "event_type" => "request_complete",
        "payload" => %{
          "correlation_id" => "test-complete-123",
          "status" => 200,
          "duration_ms" => 50,
          "request_size" => 0,
          "response_size" => 1024
        }
      }

      {response, _handler} = Handler.handle_event(handler, complete_event)
      assert response["success"] == true
    end

    test "request body chunk handling" do
      handler = create_handler()

      # First, send request headers
      request_event = %{
        "version" => Protocol.protocol_version(),
        "event_type" => "request_headers",
        "payload" => %{
          "metadata" => %{
            "correlation_id" => "test-body-123",
            "request_id" => "req-303",
            "client_ip" => "127.0.0.1",
            "client_port" => 33333,
            "protocol" => "HTTP/1.1",
            "timestamp" => "2024-01-15T10:30:00Z"
          },
          "method" => "POST",
          "uri" => "/api/data",
          "headers" => %{
            "content-type" => ["application/json"]
          }
        }
      }

      {_response, handler} = Handler.handle_event(handler, request_event)

      # Send body chunk (non-final)
      body_chunk_1 = %{
        "version" => Protocol.protocol_version(),
        "event_type" => "request_body_chunk",
        "payload" => %{
          "correlation_id" => "test-body-123",
          "data" => Base.encode64("{\"name\":"),
          "chunk_index" => 0,
          "is_last" => false,
          "bytes_received" => 8
        }
      }

      {response, handler} = Handler.handle_event(handler, body_chunk_1)
      # Non-final chunk should return needs_more
      assert response["needs_more"] == true

      # Send final body chunk
      body_chunk_2 = %{
        "version" => Protocol.protocol_version(),
        "event_type" => "request_body_chunk",
        "payload" => %{
          "correlation_id" => "test-body-123",
          "data" => Base.encode64("\"test\"}"),
          "chunk_index" => 1,
          "is_last" => true,
          "bytes_received" => 15
        }
      }

      {response, _handler} = Handler.handle_event(handler, body_chunk_2)
      # Final chunk should return actual decision
      assert response["decision"] == "allow"
    end
  end

  describe "Message Encoding" do
    test "length prefix encoding" do
      data = %{"test" => "value"}
      {:ok, encoded} = Protocol.encode_message(data)

      # First 4 bytes are length
      <<length::big-unsigned-32, json_part::binary>> = encoded

      assert length == byte_size(json_part)
      assert Jason.decode!(json_part) == data
    end

    test "max message size check" do
      max_size = Protocol.max_message_size()

      # Create message that would exceed limit
      large_data = %{"data" => String.duplicate("x", max_size + 1)}

      {:error, reason} = Protocol.encode_message(large_data)
      assert String.contains?(reason, "exceeds maximum")
    end

    test "header ops format matches Rust serde" do
      response =
        Decision.allow()
        |> Decision.add_request_header("X-Add", "value")
        |> Decision.remove_request_header("X-Remove")
        |> Decision.build()

      data = Protocol.AgentResponse.to_map(response)

      # Find the set operation
      set_op = Enum.find(data["request_headers"], fn h -> Map.has_key?(h, "set") end)
      assert set_op == %{"set" => %{"name" => "X-Add", "value" => "value"}}

      # Find the remove operation
      remove_op = Enum.find(data["request_headers"], fn h -> Map.has_key?(h, "remove") end)
      assert remove_op == %{"remove" => %{"name" => "X-Remove"}}
    end
  end

  describe "Handler State Management" do
    test "request is cached for response correlation" do
      handler = create_handler()

      # Send request headers
      request_event = %{
        "version" => Protocol.protocol_version(),
        "event_type" => "request_headers",
        "payload" => %{
          "metadata" => %{
            "correlation_id" => "cache-test-123",
            "request_id" => "req-cache",
            "client_ip" => "127.0.0.1",
            "client_port" => 44444,
            "protocol" => "HTTP/1.1",
            "timestamp" => "2024-01-15T10:30:00Z"
          },
          "method" => "GET",
          "uri" => "/cached",
          "headers" => %{}
        }
      }

      {_response, handler} = Handler.handle_event(handler, request_event)

      # Verify request is cached
      assert Map.has_key?(handler.requests, "cache-test-123")

      # Send request complete to clean up
      complete_event = %{
        "version" => Protocol.protocol_version(),
        "event_type" => "request_complete",
        "payload" => %{
          "correlation_id" => "cache-test-123",
          "status" => 200,
          "duration_ms" => 10,
          "request_size" => 0,
          "response_size" => 100
        }
      }

      {_response, handler} = Handler.handle_event(handler, complete_event)

      # Verify request is cleaned up
      refute Map.has_key?(handler.requests, "cache-test-123")
    end

    test "unknown event type returns allow decision" do
      handler = create_handler()

      unknown_event = %{
        "version" => Protocol.protocol_version(),
        "event_type" => "unknown_event",
        "payload" => %{}
      }

      {response, _handler} = Handler.handle_event(handler, unknown_event)
      assert response["decision"] == "allow"
    end
  end
end
