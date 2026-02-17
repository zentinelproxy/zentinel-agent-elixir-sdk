defmodule ZentinelAgentSdk.V2.TypesTest do
  use ExUnit.Case, async: true

  alias ZentinelAgentSdk.V2.Types.{
    AgentCapabilities,
    CancelRequest,
    DrainRequest,
    HandshakeRequest,
    HandshakeResponse,
    HealthStatus,
    MetricsReport
  }

  describe "HealthStatus" do
    test "creates healthy status" do
      status = HealthStatus.healthy()
      assert status.status == :healthy
      assert HealthStatus.healthy?(status)
      assert HealthStatus.can_process?(status)
    end

    test "creates degraded status" do
      status = HealthStatus.degraded()
      assert status.status == :degraded
      refute HealthStatus.healthy?(status)
      assert HealthStatus.can_process?(status)
    end

    test "creates unhealthy status" do
      status = HealthStatus.unhealthy()
      assert status.status == :unhealthy
      refute HealthStatus.healthy?(status)
      refute HealthStatus.can_process?(status)
    end

    test "adds message" do
      status =
        HealthStatus.healthy()
        |> HealthStatus.with_message("All good")

      assert status.message == "All good"
    end

    test "adds metadata" do
      status =
        HealthStatus.healthy()
        |> HealthStatus.with_metadata("cpu", 50)
        |> HealthStatus.with_metadata("memory", 60)

      assert status.metadata["cpu"] == 50
      assert status.metadata["memory"] == 60
    end

    test "serializes to map" do
      status =
        HealthStatus.healthy()
        |> HealthStatus.with_message("OK")
        |> HealthStatus.with_metadata("key", "value")

      map = HealthStatus.to_map(status)

      assert map["status"] == "healthy"
      assert map["message"] == "OK"
      assert map["metadata"]["key"] == "value"
      assert is_binary(map["timestamp"])
    end

    test "deserializes from map" do
      map = %{
        "status" => "degraded",
        "message" => "High load",
        "metadata" => %{"load" => 0.9}
      }

      status = HealthStatus.from_map(map)

      assert status.status == :degraded
      assert status.message == "High load"
      assert status.metadata["load"] == 0.9
    end
  end

  describe "AgentCapabilities" do
    test "creates with defaults" do
      caps = AgentCapabilities.new()

      assert caps.agent_name == "unnamed-agent"
      assert caps.protocol_version == 2
      assert caps.handles_request_headers == true
      assert caps.handles_request_body == false
    end

    test "sets name and version" do
      caps =
        AgentCapabilities.new()
        |> AgentCapabilities.with_name("my-agent")
        |> AgentCapabilities.with_version("1.0.0")

      assert caps.agent_name == "my-agent"
      assert caps.agent_version == "1.0.0"
    end

    test "enables handlers" do
      caps =
        AgentCapabilities.new()
        |> AgentCapabilities.handles_request_body()
        |> AgentCapabilities.handles_response_headers()
        |> AgentCapabilities.handles_response_body()
        |> AgentCapabilities.handles_websocket_frames()
        |> AgentCapabilities.handles_guardrail_inspect()

      assert caps.handles_request_body == true
      assert caps.handles_response_headers == true
      assert caps.handles_response_body == true
      assert caps.handles_websocket_frames == true
      assert caps.handles_guardrail_inspect == true
    end

    test "sets features" do
      caps =
        AgentCapabilities.new()
        |> AgentCapabilities.with_max_concurrent_requests(100)
        |> AgentCapabilities.supports_streaming()
        |> AgentCapabilities.supports_cancellation()
        |> AgentCapabilities.supports_metrics()

      assert caps.max_concurrent_requests == 100
      assert caps.supports_streaming == true
      assert caps.supports_cancellation == true
      assert caps.supports_metrics == true
    end

    test "adds custom metadata" do
      caps =
        AgentCapabilities.new()
        |> AgentCapabilities.with_custom("waf_version", "3.0")
        |> AgentCapabilities.with_custom("rules_count", 150)

      assert caps.custom["waf_version"] == "3.0"
      assert caps.custom["rules_count"] == 150
    end

    test "serializes to map" do
      caps =
        AgentCapabilities.new()
        |> AgentCapabilities.with_name("test")
        |> AgentCapabilities.handles_request_body()
        |> AgentCapabilities.with_max_concurrent_requests(50)

      map = AgentCapabilities.to_map(caps)

      assert map["agent_name"] == "test"
      assert map["handles_request_body"] == true
      assert map["max_concurrent_requests"] == 50
    end

    test "deserializes from map" do
      map = %{
        "agent_name" => "waf",
        "agent_version" => "2.0",
        "handles_request_body" => true,
        "max_concurrent_requests" => 100
      }

      caps = AgentCapabilities.from_map(map)

      assert caps.agent_name == "waf"
      assert caps.agent_version == "2.0"
      assert caps.handles_request_body == true
      assert caps.max_concurrent_requests == 100
    end
  end

  describe "HandshakeRequest" do
    test "creates from capabilities" do
      caps = AgentCapabilities.new() |> AgentCapabilities.with_name("test")
      request = HandshakeRequest.new(caps)

      assert request.capabilities.agent_name == "test"
    end

    test "adds auth token" do
      caps = AgentCapabilities.new()

      request =
        HandshakeRequest.new(caps)
        |> HandshakeRequest.with_auth_token("secret123")

      assert request.auth_token == "secret123"
    end

    test "adds metadata" do
      caps = AgentCapabilities.new()

      request =
        HandshakeRequest.new(caps)
        |> HandshakeRequest.with_metadata("hostname", "agent-1")

      assert request.metadata["hostname"] == "agent-1"
    end

    test "serializes to map" do
      caps = AgentCapabilities.new() |> AgentCapabilities.with_name("test")

      request =
        HandshakeRequest.new(caps)
        |> HandshakeRequest.with_auth_token("token")

      map = HandshakeRequest.to_map(request)

      assert map["capabilities"]["agent_name"] == "test"
      assert map["auth_token"] == "token"
    end
  end

  describe "HandshakeResponse" do
    test "creates accepted response" do
      response =
        HandshakeResponse.accepted()
        |> HandshakeResponse.with_agent_id("agent-123")

      assert HandshakeResponse.accepted?(response)
      assert response.agent_id == "agent-123"
    end

    test "creates rejected response" do
      response = HandshakeResponse.rejected("Invalid token")

      refute HandshakeResponse.accepted?(response)
      assert response.error == "Invalid token"
    end

    test "adds config" do
      response =
        HandshakeResponse.accepted()
        |> HandshakeResponse.with_config(%{"rate_limit" => 100})

      assert response.config["rate_limit"] == 100
    end

    test "deserializes from map" do
      map = %{
        "accepted" => true,
        "agent_id" => "waf-1",
        "config" => %{"enabled" => true}
      }

      response = HandshakeResponse.from_map(map)

      assert HandshakeResponse.accepted?(response)
      assert response.agent_id == "waf-1"
      assert response.config["enabled"] == true
    end
  end

  describe "MetricsReport" do
    test "creates empty report" do
      report = MetricsReport.new()
      assert report.metrics == []
    end

    test "adds counter metric" do
      report =
        MetricsReport.new()
        |> MetricsReport.counter("requests", 100)

      assert length(report.metrics) == 1
      metric = hd(report.metrics)
      assert metric.name == "requests"
      assert metric.type == :counter
      assert metric.value == 100
    end

    test "adds gauge metric" do
      report =
        MetricsReport.new()
        |> MetricsReport.gauge("connections", 42)

      metric = hd(report.metrics)
      assert metric.type == :gauge
      assert metric.value == 42
    end

    test "adds histogram metric" do
      report =
        MetricsReport.new()
        |> MetricsReport.histogram("latency", [1, 2, 5, 10, 50])

      metric = hd(report.metrics)
      assert metric.type == :histogram
      assert metric.value == [1, 2, 5, 10, 50]
    end

    test "adds labels to metrics" do
      report =
        MetricsReport.new()
        |> MetricsReport.counter("requests", 100, %{"agent" => "waf"})

      metric = hd(report.metrics)
      assert metric.labels["agent"] == "waf"
    end

    test "adds global labels" do
      report =
        MetricsReport.new()
        |> MetricsReport.with_labels(%{"version" => "1.0"})

      assert report.labels["version"] == "1.0"
    end

    test "serializes to map" do
      report =
        MetricsReport.new()
        |> MetricsReport.counter("requests", 100)
        |> MetricsReport.gauge("active", 5)

      map = MetricsReport.to_map(report)

      assert length(map["metrics"]) == 2
      assert is_binary(map["timestamp"])
    end
  end

  describe "CancelRequest" do
    test "creates cancel request" do
      request = CancelRequest.new(123)
      assert request.request_id == 123
    end

    test "adds correlation id" do
      request =
        CancelRequest.new(123)
        |> CancelRequest.with_correlation_id("corr-456")

      assert request.correlation_id == "corr-456"
    end

    test "adds reason" do
      request =
        CancelRequest.new(123)
        |> CancelRequest.with_reason("Client disconnected")

      assert request.reason == "Client disconnected"
    end
  end

  describe "DrainRequest" do
    test "creates with default timeout" do
      request = DrainRequest.new()
      assert request.timeout_ms == 30_000
    end

    test "creates with custom timeout" do
      request = DrainRequest.new(60_000)
      assert request.timeout_ms == 60_000
    end

    test "adds reason" do
      request =
        DrainRequest.new()
        |> DrainRequest.with_reason("Rolling restart")

      assert request.reason == "Rolling restart"
    end
  end
end
