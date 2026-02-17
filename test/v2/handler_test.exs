defmodule ZentinelAgentSdk.V2.HandlerTest do
  use ExUnit.Case, async: true

  alias ZentinelAgentSdk.V2.Handler

  alias ZentinelAgentSdk.V2.Types.{
    AgentCapabilities,
    HandshakeResponse,
    HealthStatus
  }

  # Test agent module
  defmodule TestAgentV2 do
    use ZentinelAgentSdk.V2.Agent

    @impl true
    def name, do: "test-agent-v2"

    @impl true
    def version, do: "1.0.0"

    @impl true
    def capabilities do
      AgentCapabilities.new()
      |> AgentCapabilities.with_name(name())
      |> AgentCapabilities.with_version(version())
      |> AgentCapabilities.handles_request_headers()
      |> AgentCapabilities.handles_request_body()
      |> AgentCapabilities.supports_cancellation()
    end

    @impl true
    def on_request(request) do
      path = ZentinelAgentSdk.Request.path_only(request)

      if String.starts_with?(path, "/blocked") do
        ZentinelAgentSdk.Decision.deny()
        |> ZentinelAgentSdk.Decision.with_body("Blocked")
      else
        ZentinelAgentSdk.Decision.allow()
      end
    end

    @impl true
    def health_check do
      HealthStatus.healthy()
      |> HealthStatus.with_message("Test agent healthy")
    end
  end

  describe "Handler initialization" do
    test "starts with agent module" do
      {:ok, handler} = Handler.start_link(TestAgentV2)
      assert is_pid(handler)
      GenServer.stop(handler)
    end

    test "extracts capabilities from agent" do
      {:ok, handler} = Handler.start_link(TestAgentV2)
      caps = Handler.get_capabilities(handler)

      assert caps.agent_name == "test-agent-v2"
      assert caps.agent_version == "1.0.0"
      assert caps.handles_request_headers == true
      assert caps.handles_request_body == true
      assert caps.supports_cancellation == true

      GenServer.stop(handler)
    end
  end

  describe "Health check" do
    test "returns health status from agent" do
      {:ok, handler} = Handler.start_link(TestAgentV2)
      health = Handler.get_health(handler)

      assert health.status == :healthy
      assert health.message == "Test agent healthy"

      GenServer.stop(handler)
    end
  end

  describe "Handshake" do
    test "generates handshake request" do
      {:ok, handler} = Handler.start_link(TestAgentV2)
      request = Handler.get_handshake_request(handler, "test-token")

      assert request.capabilities.agent_name == "test-agent-v2"
      assert request.auth_token == "test-token"

      GenServer.stop(handler)
    end

    test "processes accepted handshake response" do
      {:ok, handler} = Handler.start_link(TestAgentV2)

      response =
        HandshakeResponse.accepted()
        |> HandshakeResponse.with_agent_id("agent-123")

      result = Handler.handle_handshake_response(handler, response)
      assert result == :ok

      GenServer.stop(handler)
    end

    test "processes rejected handshake response" do
      {:ok, handler} = Handler.start_link(TestAgentV2)

      response = HandshakeResponse.rejected("Invalid token")

      result = Handler.handle_handshake_response(handler, response)
      assert result == {:error, "Invalid token"}

      GenServer.stop(handler)
    end
  end

  describe "Event handling" do
    test "handles request_headers event" do
      {:ok, handler} = Handler.start_link(TestAgentV2)

      event = %{
        "event_type" => "request_headers",
        "payload" => %{
          "metadata" => %{
            "correlation_id" => "test-123",
            "request_id" => "req-456",
            "client_ip" => "127.0.0.1",
            "client_port" => 12345
          },
          "method" => "GET",
          "uri" => "/api/test",
          "headers" => %{}
        }
      }

      response = Handler.handle_event(handler, event)

      assert response["decision"] == "allow"

      GenServer.stop(handler)
    end

    test "handles blocked request" do
      {:ok, handler} = Handler.start_link(TestAgentV2)

      event = %{
        "event_type" => "request_headers",
        "payload" => %{
          "metadata" => %{
            "correlation_id" => "test-123",
            "request_id" => "req-456",
            "client_ip" => "127.0.0.1",
            "client_port" => 12345
          },
          "method" => "GET",
          "uri" => "/blocked/path",
          "headers" => %{}
        }
      }

      response = Handler.handle_event(handler, event)

      assert response["decision"]["block"]["status"] == 403
      assert response["decision"]["block"]["body"] == "Blocked"

      GenServer.stop(handler)
    end

    test "handles health_check event" do
      {:ok, handler} = Handler.start_link(TestAgentV2)

      event = %{
        "event_type" => "health_check",
        "payload" => %{}
      }

      response = Handler.handle_event(handler, event)

      assert response["status"] == "healthy"
      assert response["message"] == "Test agent healthy"

      GenServer.stop(handler)
    end

    test "handles cancel event" do
      {:ok, handler} = Handler.start_link(TestAgentV2)

      # First send a request
      request_event = %{
        "event_type" => "request_headers",
        "payload" => %{
          "metadata" => %{
            "correlation_id" => "cancel-test",
            "request_id" => "req-789",
            "client_ip" => "127.0.0.1",
            "client_port" => 12345
          },
          "method" => "GET",
          "uri" => "/api/slow",
          "headers" => %{}
        }
      }

      Handler.handle_event(handler, request_event)

      # Then cancel it
      cancel_event = %{
        "event_type" => "cancel",
        "payload" => %{
          "request_id" => 789,
          "correlation_id" => "cancel-test",
          "reason" => "Client disconnected"
        }
      }

      response = Handler.handle_event(handler, cancel_event)

      assert response["success"] == true

      GenServer.stop(handler)
    end

    test "handles drain event" do
      {:ok, handler} = Handler.start_link(TestAgentV2)

      event = %{
        "event_type" => "drain",
        "payload" => %{
          "timeout_ms" => 30_000,
          "reason" => "Rolling restart"
        }
      }

      response = Handler.handle_event(handler, event)

      assert response["success"] == true

      GenServer.stop(handler)
    end

    test "handles unknown event" do
      {:ok, handler} = Handler.start_link(TestAgentV2)

      event = %{
        "event_type" => "unknown_event",
        "payload" => %{}
      }

      response = Handler.handle_event(handler, event)

      # Should return allow decision for unknown events
      assert response["decision"] == "allow"

      GenServer.stop(handler)
    end
  end

  describe "Drain mode" do
    test "rejects new requests when draining" do
      {:ok, handler} = Handler.start_link(TestAgentV2)

      # Start draining
      Handler.drain(handler, 30_000, "test")

      # Try to send a new request
      event = %{
        "event_type" => "request_headers",
        "payload" => %{
          "metadata" => %{
            "correlation_id" => "drain-test",
            "request_id" => "req-drain",
            "client_ip" => "127.0.0.1",
            "client_port" => 12345
          },
          "method" => "GET",
          "uri" => "/api/test",
          "headers" => %{}
        }
      }

      response = Handler.handle_event(handler, event)

      # Should be blocked with 503
      assert response["decision"]["block"]["status"] == 503

      GenServer.stop(handler)
    end
  end
end
