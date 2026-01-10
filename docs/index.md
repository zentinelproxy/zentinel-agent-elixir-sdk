# Sentinel Agent Elixir SDK

An Elixir SDK for building agents that integrate with the [Sentinel](https://github.com/raskell-io/sentinel) reverse proxy.

## Overview

Sentinel agents are external processors that can inspect and modify HTTP traffic passing through the Sentinel proxy. They communicate with Sentinel over Unix sockets using a length-prefixed JSON protocol.

Agents can:

- **Inspect requests** - Examine headers, paths, query parameters, and body content
- **Block requests** - Return custom error responses (403, 401, 429, etc.)
- **Redirect requests** - Send clients to different URLs
- **Modify headers** - Add, remove, or modify request/response headers
- **Add audit metadata** - Attach tags, rule IDs, and custom data for logging

## Installation

Add `sentinel_agent_sdk` to your dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:sentinel_agent_sdk, github: "raskell-io/sentinel-agent-elixir-sdk"}
  ]
end
```

Then fetch dependencies:

```bash
mix deps.get
```

## Quick Example

```elixir
defmodule MyAgent do
  use SentinelAgentSdk.Agent

  alias SentinelAgentSdk.{Decision, Request}

  @impl true
  def name, do: "my-agent"

  @impl true
  def on_request(request) do
    # Block requests to /admin
    if Request.path_starts_with?(request, "/admin") do
      Decision.deny() |> Decision.with_body("Access denied")
    else
      # Allow everything else
      Decision.allow()
    end
  end
end

# Run the agent
SentinelAgentSdk.run(MyAgent, socket: "/tmp/my-agent.sock")
```

Run the agent:

```bash
mix run --no-halt -e 'SentinelAgentSdk.run(MyAgent, socket: "/tmp/my-agent.sock")'
```

## Documentation

- [Quickstart Guide](quickstart.md) - Get up and running in 5 minutes
- [API Reference](api.md) - Complete API documentation
- [Examples](examples.md) - Common patterns and use cases
- [Sentinel Configuration](configuration.md) - How to configure Sentinel to use agents

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│   Client    │────▶│   Sentinel   │────▶│   Upstream   │
└─────────────┘     └──────────────┘     └──────────────┘
                           │
                           │ Unix Socket
                           ▼
                    ┌──────────────┐
                    │    Agent     │
                    │   (Elixir)   │
                    └──────────────┘
```

1. Client sends request to Sentinel
2. Sentinel forwards request headers to agent via Unix socket
3. Agent returns a decision (allow, block, redirect)
4. Sentinel applies the decision and forwards to upstream (if allowed)
5. Agent can also process response headers

## Protocol

The SDK implements version 1 of the Sentinel Agent Protocol:

- **Transport**: Unix domain sockets
- **Encoding**: Length-prefixed JSON (4-byte big-endian length prefix)
- **Max message size**: 10MB

## License

Apache 2.0
