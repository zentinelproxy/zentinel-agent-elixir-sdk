# Quickstart Guide

This guide will help you create your first Sentinel agent in under 5 minutes.

## Prerequisites

- Elixir 1.17+
- Erlang 27+
- Sentinel proxy (for testing with real traffic)

## Step 1: Create a New Project

```bash
mix new my_agent
cd my_agent
```

## Step 2: Add the SDK

Add the SDK to your `mix.exs`:

```elixir
defp deps do
  [
    {:sentinel_agent_sdk, github: "raskell-io/sentinel-agent-elixir-sdk"}
  ]
end
```

Fetch dependencies:

```bash
mix deps.get
```

## Step 3: Create Your Agent

Create `lib/my_agent.ex`:

```elixir
defmodule MyAgent do
  @moduledoc "My first Sentinel agent."

  use SentinelAgentSdk.Agent

  alias SentinelAgentSdk.{Decision, Request}

  @impl true
  def name, do: "my-agent"

  @impl true
  def on_request(request) do
    # Log the request
    IO.puts("Processing: #{Request.method(request)} #{Request.path_only(request)}")

    # Block requests to sensitive paths
    if Request.path_starts_with?(request, "/admin") do
      Decision.deny()
      |> Decision.with_body("Access denied")
      |> Decision.with_tag("blocked")
    else
      # Allow with a custom header
      Decision.allow()
      |> Decision.add_request_header("X-Processed-By", "my-agent")
    end
  end
end
```

## Step 4: Create an Entry Point

Create `lib/my_agent/application.ex`:

```elixir
defmodule MyAgent.Application do
  use Application

  @impl true
  def start(_type, _args) do
    socket = System.get_env("SOCKET_PATH", "/tmp/my-agent.sock")

    children = [
      {Task, fn -> SentinelAgentSdk.run(MyAgent, socket: socket) end}
    ]

    opts = [strategy: :one_for_one, name: MyAgent.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
```

Update `mix.exs` to add the application:

```elixir
def application do
  [
    mod: {MyAgent.Application, []},
    extra_applications: [:logger]
  ]
end
```

## Step 5: Run the Agent

```bash
SOCKET_PATH=/tmp/my-agent.sock mix run --no-halt
```

You should see:

```
[info] Agent 'my-agent' listening on /tmp/my-agent.sock
```

## Step 6: Configure Sentinel

Add the agent to your Sentinel configuration (`sentinel.kdl`):

```kdl
agents {
    agent "my-agent" type="custom" {
        unix-socket path="/tmp/my-agent.sock"
        events "request_headers"
        timeout-ms 100
        failure-mode "open"
    }
}

filters {
    filter "my-filter" {
        type "agent"
        agent "my-agent"
        timeout-ms 100
        failure-mode "open"
    }
}

routes {
    route "api" {
        matches {
            path-prefix "/api/"
        }
        upstream "backend"
        filters "my-filter"
    }
}
```

## Step 7: Test It

With Sentinel running, send a test request:

```bash
# This should pass through
curl http://localhost:8080/api/users

# This should be blocked
curl http://localhost:8080/api/admin/settings
```

## Runner Options

The `SentinelAgentSdk.run/2` function supports these options:

| Option | Description | Default |
|--------|-------------|---------|
| `:socket` | Unix socket path | `/tmp/sentinel-agent.sock` |
| `:log_level` | Log level (`:debug`, `:info`, `:warning`, `:error`) | `:info` |
| `:json_logs` | Enable JSON log format | `false` |

## Next Steps

- Read the [API Reference](api.md) for complete documentation
- See [Examples](examples.md) for common patterns
- Learn about [Sentinel Configuration](configuration.md) options
