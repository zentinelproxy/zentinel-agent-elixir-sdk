defmodule ZentinelAgentSdk.V2.UdsWireTest do
  @moduledoc """
  The v2 UDS server against a client that speaks the proxy's side of the
  wire protocol (`zentinel_agent_protocol::v2::uds`): framing, handshake
  schema, Configure, correlation ids, Ping/Pong, concurrency.

  Before 0.3 both runners read v1 framing (no type byte) and the proxy's
  handshake failed with `Failed to decode JSON message`.
  """

  use ExUnit.Case, async: false

  alias ZentinelAgentSdk.V2.UDS

  defmodule WireAgent do
    use ZentinelAgentSdk.V2.Agent

    @impl true
    def name, do: "wire-agent"

    @impl true
    def on_configure(%{"reject" => true}), do: {:error, "rejected by test"}

    def on_configure(config) do
      :persistent_term.put({__MODULE__, :config}, config)
      :ok
    end

    @impl true
    def on_request(request) do
      if Request.path_starts_with?(request, "/slow"), do: Process.sleep(500)

      Decision.allow()
      |> Decision.add_request_header("X-Path", Request.path(request))
      |> Decision.add_request_header(
        "X-Config",
        inspect(:persistent_term.get({__MODULE__, :config}, nil))
      )
    end

    @impl true
    def on_request_body(request) do
      Decision.block(403)
      |> Decision.with_body("#{Request.path(request)}:#{Request.body(request)}")
    end
  end

  setup do
    path =
      Path.join(System.tmp_dir!(), "zentinel-wire-#{System.unique_integer([:positive])}.sock")

    :persistent_term.erase({WireAgent, :config})
    {:ok, runner} = ZentinelAgentSdk.V2.start_link(WireAgent, socket: path, log_level: :warning)
    wait_for_socket(path, 100)

    on_exit(fn ->
      Process.exit(runner, :kill)
      File.rm(path)
    end)

    %{path: path}
  end

  defp wait_for_socket(_path, 0), do: flunk("agent did not listen")

  defp wait_for_socket(path, n) do
    case :gen_tcp.connect({:local, String.to_charlist(path)}, 0, [:binary, active: false]) do
      {:ok, s} ->
        :gen_tcp.close(s)

      _ ->
        Process.sleep(20)
        wait_for_socket(path, n - 1)
    end
  end

  defp connect(path) do
    {:ok, s} =
      :gen_tcp.connect({:local, String.to_charlist(path)}, 0, [:binary, active: false], 1000)

    s
  end

  defp send_frame(s, type, payload) when is_map(payload),
    do: send_frame(s, type, Jason.encode!(payload))

  defp send_frame(s, type, payload) do
    # The proxy's framing: the length counts the type byte.
    :ok = :gen_tcp.send(s, <<byte_size(payload) + 1::32, type>> <> payload)
  end

  defp recv_frame(s) do
    {:ok, <<len::32>>} = :gen_tcp.recv(s, 4, 2000)
    {:ok, <<type, payload::binary>>} = :gen_tcp.recv(s, len, 2000)
    {type, payload}
  end

  defp recv_json(s, want_type) do
    {type, payload} = recv_frame(s)
    assert type == want_type
    Jason.decode!(payload)
  end

  defp handshake(s) do
    send_frame(s, 0x01, %{
      "supported_versions" => [2],
      "proxy_id" => "test-proxy",
      "proxy_version" => "0.0.0",
      "config" => nil
    })

    recv_json(s, 0x02)
  end

  defp configure(s, config, cid \\ "zentinel-configure-test") do
    send_frame(s, 0x17, %{"config" => config, "config_version" => nil, "correlation_id" => cid})
    recv_json(s, 0x20)
  end

  defp request_headers(s, cid, uri) do
    send_frame(s, 0x10, %{
      "metadata" => %{
        "correlation_id" => cid,
        "request_id" => cid,
        "client_ip" => "127.0.0.1",
        "client_port" => 1234,
        "protocol" => "HTTP/1.1",
        "timestamp" => "2026-10-22T00:00:00Z"
      },
      "method" => "GET",
      "uri" => uri,
      "headers" => %{}
    })
  end

  defp correlation_id(response), do: response["audit"]["custom"]["correlation_id"]

  describe "framing" do
    test "the length counts the type byte" do
      {:ok, frame} = UDS.encode_frame(:agent_response, "{}")
      assert IO.iodata_to_binary(frame) == <<0, 0, 0, 3, 0x20, "{}">>
    end

    test "decode_frame splits frames and waits for partial ones" do
      data = <<0, 0, 0, 3, 0x41, "ab", 0, 0, 0, 2, 0x42>>
      assert {:ok, 0x41, "ab", rest} = UDS.decode_frame(data)
      assert :more = UDS.decode_frame(rest)
      assert {:ok, 0x42, "x", ""} = UDS.decode_frame(rest <> "x")
      assert {:error, _} = UDS.decode_frame(<<0, 0, 0, 0>>)
      assert {:error, _} = UDS.decode_frame(<<0xFF, 0xFF, 0xFF, 0xFF, 1>>)
    end
  end

  describe "handshake" do
    test "answers with the proxy's UdsHandshakeResponse schema", %{path: path} do
      s = connect(path)
      response = handshake(s)

      assert response["protocol_version"] == 2
      assert response["success"] == true
      assert response["error"] == nil
      assert response["encoding"] == "json"

      caps = response["capabilities"]
      assert caps["agent_id"] == "wire-agent"
      assert caps["name"] == "wire-agent"
      assert is_binary(caps["version"])
      assert Enum.all?(caps["supported_events"], &is_integer/1)
      assert 1 in caps["supported_events"]

      # Every field is required by the proxy and must not be null.
      for key <-
            ~w(streaming_body websocket guardrails config_push metrics_export
               concurrent_requests cancellation flow_control health_reporting) do
        assert Map.has_key?(caps["features"], key), "features.#{key} missing"
        refute is_nil(caps["features"][key])
      end

      for key <- ~w(max_body_size max_concurrency preferred_chunk_size) do
        assert is_integer(caps["limits"][key]), "limits.#{key} missing"
      end
    end

    test "refuses a proxy that does not offer v2", %{path: path} do
      s = connect(path)

      send_frame(s, 0x01, %{
        "supported_versions" => [1],
        "proxy_id" => "old",
        "proxy_version" => "0",
        "config" => nil
      })

      response = recv_json(s, 0x02)
      assert response["success"] == false
      assert response["error"] =~ "v2"
      assert {:error, :closed} = :gen_tcp.recv(s, 0, 1000)
    end
  end

  describe "events" do
    test "Configure is applied and answered with its correlation id", %{path: path} do
      s = connect(path)
      handshake(s)

      response = configure(s, %{"nested" => %{"value" => "x"}}, "cfg-1")
      assert response["decision"] == "allow"
      assert correlation_id(response) == "cfg-1"

      request_headers(s, "req-1", "/after-config")
      response = recv_json(s, 0x20)
      assert correlation_id(response) == "req-1"

      assert %{"set" => %{"value" => config}} =
               Enum.find(response["request_headers"], &(&1["set"]["name"] == "X-Config"))

      assert config =~ "nested"
    end

    test "a rejected configuration is answered with a block", %{path: path} do
      s = connect(path)
      handshake(s)

      response = configure(s, %{"reject" => true})
      assert %{"block" => %{"status" => 500, "body" => body}} = response["decision"]
      assert body =~ "rejected by test"
    end

    test "Ping is answered with a Pong carrying the same payload", %{path: path} do
      s = connect(path)
      handshake(s)

      send_frame(s, 0x41, ~s({"sequence":7,"timestamp_ms":1}))
      assert {0x42, ~s({"sequence":7,"timestamp_ms":1})} = recv_frame(s)
    end

    test "events on one connection are handled concurrently", %{path: path} do
      s = connect(path)
      handshake(s)
      configure(s, %{})

      request_headers(s, "slow", "/slow")
      request_headers(s, "fast", "/fast")

      first = recv_json(s, 0x20)
      second = recv_json(s, 0x20)
      assert correlation_id(first) == "fast"
      assert correlation_id(second) == "slow"
    end

    test "request state is shared between connections", %{path: path} do
      a = connect(path)
      b = connect(path)
      handshake(a)
      handshake(b)
      configure(a, %{})
      configure(b, %{})

      request_headers(a, "shared", "/upload")
      assert correlation_id(recv_json(a, 0x20)) == "shared"

      send_frame(b, 0x11, %{
        "correlation_id" => "shared",
        "data" => Base.encode64("hello"),
        "is_last" => true,
        "total_size" => 5,
        "chunk_index" => 0,
        "bytes_received" => 5
      })

      response = recv_json(b, 0x20)
      assert correlation_id(response) == "shared"
      assert response["decision"]["block"]["body"] == "/upload:hello"
    end

    test "a closed connection does not stop the server", %{path: path} do
      s = connect(path)
      handshake(s)
      :gen_tcp.close(s)
      Process.sleep(1100)

      s = connect(path)
      assert handshake(s)["success"] == true
    end
  end
end
