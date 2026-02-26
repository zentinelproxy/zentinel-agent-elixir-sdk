# Zentinel Agent Elixir SDK

An Elixir SDK for building agents that integrate with the [Zentinel](https://github.com/zentinelproxy/zentinel) reverse proxy.

## Overview

Zentinel agents are external processors that can inspect and modify HTTP traffic passing through the Zentinel proxy. They communicate with Zentinel over Unix sockets (UDS) or gRPC using the v2 agent protocol.

Agents can:

- **Inspect requests** - Examine headers, paths, query parameters, and body content
- **Block requests** - Return custom error responses (403, 401, 429, etc.)
- **Redirect requests** - Send clients to different URLs
- **Modify headers** - Add, remove, or modify request/response headers
- **Add audit metadata** - Attach tags, rule IDs, and custom data for logging

## Installation

Add `zentinel_agent_sdk` to your dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:zentinel_agent_sdk, github: "zentinelproxy/zentinel-agent-elixir-sdk"}
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
  use ZentinelAgentSdk.Agent

  alias ZentinelAgentSdk.{Decision, Request}

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
ZentinelAgentSdk.run(MyAgent, socket: "/tmp/my-agent.sock")
```

Run the agent:

```bash
mix run --no-halt -e 'ZentinelAgentSdk.run(MyAgent, socket: "/tmp/my-agent.sock")'
```

## Documentation

- [Quickstart Guide](quickstart.md) - Get up and running in 5 minutes
- [API Reference](api.md) - Complete API documentation
- [Examples](examples.md) - Common patterns and use cases
- [Zentinel Configuration](configuration.md) - How to configure Zentinel to use agents

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│   Client    │────▶│   Zentinel   │────▶│   Upstream   │
└─────────────┘     └──────────────┘     └──────────────┘
                           │
                           │ Unix Socket
                           ▼
                    ┌──────────────┐
                    │    Agent     │
                    │   (Elixir)   │
                    └──────────────┘
```

1. Client sends request to Zentinel
2. Zentinel forwards request headers to agent via Unix socket
3. Agent returns a decision (allow, block, redirect)
4. Zentinel applies the decision and forwards to upstream (if allowed)
5. Agent can also process response headers

## Protocol

The SDK implements version 2 of the Zentinel Agent Protocol:

- **Transport**: Unix domain sockets (UDS) or gRPC
- **Encoding**: Length-prefixed binary (4-byte big-endian length + 1-byte type prefix) for UDS
- **Max message size**: 16 MB (UDS) / 10 MB (gRPC)

For the canonical protocol specification, including wire format details, event types, and architectural diagrams, see the [Zentinel Agent Protocol documentation](https://github.com/zentinelproxy/zentinel/tree/main/crates/agent-protocol).

## License

Apache 2.0
