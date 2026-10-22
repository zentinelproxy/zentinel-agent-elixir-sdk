defmodule ZentinelAgentSdk.MixProject do
  use Mix.Project

  def project do
    [
      app: :zentinel_agent_sdk,
      version: "0.3.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      name: "Zentinel Agent SDK",
      description: "Elixir SDK for building Zentinel proxy agents",
      package: package(),
      docs: docs(),
      aliases: aliases()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:jason, "~> 1.4"},
      # gRPC transport (zentinel.agent.v2.AgentServiceV2)
      {:grpc_server, "~> 1.0"},
      {:protobuf, "~> 0.17"},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      files: ~w(lib priv mix.exs README.md LICENSE .formatter.exs),
      links: %{"GitHub" => "https://github.com/zentinelproxy/zentinel-agent-elixir-sdk"}
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "LICENSE"]
    ]
  end

  defp aliases do
    [
      lint: ["format --check-formatted", "dialyzer"],
      "lint.fix": ["format"]
    ]
  end
end
