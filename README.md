<div align="center">

<h1 align="center">
  Zentinel Agent Elixir SDK
</h1>

<p align="center">
  <em>Build agents that extend Zentinel's security and policy capabilities.</em><br>
  <em>Inspect, block, redirect, and transform HTTP traffic.</em>
</p>

<p align="center">
  <a href="https://elixir-lang.org/">
    <img alt="Elixir" src="https://img.shields.io/badge/Elixir-1.17+-4b275f?logo=elixir&logoColor=white&style=for-the-badge">
  </a>
  <a href="https://github.com/zentinelproxy/zentinel">
    <img alt="Zentinel" src="https://img.shields.io/badge/Built%20for-Zentinel-f5a97f?style=for-the-badge">
  </a>
  <a href="LICENSE">
    <img alt="License" src="https://img.shields.io/badge/License-Apache--2.0-c6a0f6?style=for-the-badge">
  </a>
</p>

<p align="center">
  <a href="docs/index.md">Documentation</a> •
  <a href="docs/quickstart.md">Quickstart</a> •
  <a href="docs/api.md">API Reference</a> •
  <a href="docs/examples.md">Examples</a>
</p>

</div>

---

The Zentinel Agent Elixir SDK provides a simple, behaviour-based API for building agents that integrate with the [Zentinel](https://github.com/zentinelproxy/zentinel) reverse proxy. Agents can inspect requests and responses, block malicious traffic, add headers, and attach audit metadata—all from Elixir.

## Quick Start

Add `zentinel_agent_sdk` to your dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:zentinel_agent_sdk, github: "zentinelproxy/zentinel-agent-elixir-sdk"}
  ]
end
```

Create `my_agent.ex`:

```elixir
defmodule MyAgent do
  use ZentinelAgentSdk.Agent

  alias ZentinelAgentSdk.{Decision, Request}

  @impl true
  def name, do: "my-agent"

  @impl true
  def on_request(request) do
    if Request.path_starts_with?(request, "/admin") do
      Decision.deny() |> Decision.with_body("Access denied")
    else
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

## Features

| Feature | Description |
|---------|-------------|
| **Simple Agent API** | Implement `on_request`, `on_response`, and other hooks via behaviours |
| **Fluent Decision Builder** | Pipe operators: `Decision.deny() \|> Decision.with_body(...) \|> Decision.with_tag(...)` |
| **Request/Response Wrappers** | Ergonomic access to headers, body, query params, metadata |
| **Typed Configuration** | `ConfigurableAgent` behaviour with struct-based config support |
| **OTP Native** | Built on OTP for reliable, concurrent processing |
| **Protocol Compatible** | Full compatibility with Zentinel agent protocol v2 |

## Why Agents?

Zentinel's agent system moves complex logic **out of the proxy core** and into isolated, testable, independently deployable processes:

- **Security isolation** — WAF engines, auth validation, and custom logic run in separate processes
- **Language flexibility** — Write agents in Elixir, Python, Rust, Go, or any language
- **Independent deployment** — Update agent logic without restarting the proxy
- **Failure boundaries** — Agent crashes don't take down the dataplane

Agents communicate with Zentinel over Unix sockets using a simple length-prefixed JSON protocol.

## Architecture

```
┌─────────────┐         ┌──────────────┐         ┌──────────────┐
│   Client    │────────▶│   Zentinel   │────────▶│   Upstream   │
└─────────────┘         └──────────────┘         └──────────────┘
                               │
                               │ Unix Socket (JSON)
                               ▼
                        ┌──────────────┐
                        │    Agent     │
                        │   (Elixir)   │
                        └──────────────┘
```

1. Client sends request to Zentinel
2. Zentinel forwards request headers to agent
3. Agent returns decision (allow, block, redirect) with optional header mutations
4. Zentinel applies the decision
5. Agent can also inspect response headers before they reach the client

---

## Core Concepts

### Agent

The `Agent` behaviour defines the hooks you can implement:

```elixir
defmodule MyAgent do
  use ZentinelAgentSdk.Agent

  alias ZentinelAgentSdk.{Decision, Request, Response}

  @impl true
  def name, do: "my-agent"

  @impl true
  def on_request(request) do
    # Called when request headers arrive
    Decision.allow()
  end

  @impl true
  def on_request_body(request) do
    # Called when request body is available (if body inspection enabled)
    Decision.allow()
  end

  @impl true
  def on_response(request, response) do
    # Called when response headers arrive from upstream
    Decision.allow()
  end

  @impl true
  def on_response_body(request, response) do
    # Called when response body is available (if body inspection enabled)
    Decision.allow()
  end

  @impl true
  def on_request_complete(request, status, duration_ms) do
    # Called when request processing completes. Use for logging/metrics.
    :ok
  end
end
```

### Request

Access HTTP request data with convenience functions:

```elixir
def on_request(request) do
  alias ZentinelAgentSdk.Request

  # Path matching
  if Request.path_starts_with?(request, "/api/"), do: # ...
  if Request.path_equals?(request, "/health"), do: Decision.allow()

  # Headers (case-insensitive)
  auth = Request.header(request, "authorization")
  unless Request.has_header?(request, "x-api-key") do
    Decision.unauthorized()
  end

  # Common headers as functions
  host = Request.host(request)
  user_agent = Request.user_agent(request)
  content_type = Request.content_type(request)

  # Query parameters
  page = Request.query(request, "page") || "1"

  # Request metadata
  client_ip = Request.client_ip(request)
  correlation_id = Request.correlation_id(request)

  # Body (when body inspection is enabled)
  if Request.body(request) != <<>> do
    data = Request.body_str(request)
  end

  Decision.allow()
end
```

### Response

Inspect upstream responses before they reach the client:

```elixir
def on_response(request, response) do
  alias ZentinelAgentSdk.Response

  # Status code
  if Response.status_code(response) >= 500 do
    Decision.allow() |> Decision.with_tag("upstream-error")
  end

  # Headers
  content_type = Response.header(response, "content-type")

  # Add security headers to all responses
  Decision.allow()
  |> Decision.add_response_header("X-Frame-Options", "DENY")
  |> Decision.add_response_header("X-Content-Type-Options", "nosniff")
  |> Decision.remove_response_header("Server")
end
```

### Decision

Build responses with a fluent API using the pipe operator:

```elixir
alias ZentinelAgentSdk.Decision

# Allow the request
Decision.allow()

# Block with common status codes
Decision.deny()           # 403 Forbidden
Decision.unauthorized()   # 401 Unauthorized
Decision.rate_limited()   # 429 Too Many Requests
Decision.block(503)       # Custom status

# Block with response body
Decision.deny() |> Decision.with_body("Access denied")
Decision.block(400) |> Decision.with_json_body(%{"error" => "Invalid request"})

# Redirect
Decision.redirect("/login")                    # 302 temporary
Decision.redirect("/new-path", 301)            # 301 permanent
Decision.redirect_permanent("/new-path")       # 301 permanent

# Modify headers
Decision.allow()
|> Decision.add_request_header("X-User-ID", user_id)
|> Decision.remove_request_header("Cookie")
|> Decision.add_response_header("X-Cache", "HIT")
|> Decision.remove_response_header("X-Powered-By")

# Audit metadata (appears in Zentinel logs)
Decision.deny()
|> Decision.with_tag("blocked")
|> Decision.with_rule_id("SQLI-001")
|> Decision.with_confidence(0.95)
|> Decision.with_metadata("matched_pattern", pattern)
```

### ConfigurableAgent

For agents with typed configuration:

```elixir
defmodule RateLimitConfig do
  defstruct requests_per_minute: 60, enabled: true
end

defmodule RateLimitAgent do
  use ZentinelAgentSdk.ConfigurableAgent

  alias ZentinelAgentSdk.{Decision, Request}

  @impl true
  def name, do: "rate-limiter"

  @impl true
  def default_config, do: %RateLimitConfig{}

  @impl true
  def parse_config(config_map) do
    %RateLimitConfig{
      requests_per_minute: Map.get(config_map, "requests_per_minute", 60),
      enabled: Map.get(config_map, "enabled", true)
    }
  end

  @impl true
  def on_config_applied(config) do
    IO.puts("Rate limit set to #{config.requests_per_minute}/min")
    :ok
  end

  @impl true
  def on_request(request, config) do
    if not config.enabled do
      Decision.allow()
    else
      # Use config.requests_per_minute...
      Decision.allow()
    end
  end
end
```

---

## Running Agents

### Programmatic

```elixir
# Simple usage
ZentinelAgentSdk.run(MyAgent, socket: "/tmp/my-agent.sock")

# With options
ZentinelAgentSdk.run(MyAgent,
  socket: "/tmp/my-agent.sock",
  log_level: :debug,
  json_logs: true
)
```

| Option | Description | Default |
|--------|-------------|---------|
| `:socket` | Unix socket path | `/tmp/zentinel-agent.sock` |
| `:log_level` | `:debug`, `:info`, `:warning`, `:error` | `:info` |
| `:json_logs` | Output logs as JSON | `false` |

### As a Script

```bash
# Run example agent
elixir examples/simple_agent.exs

# With custom socket
elixir -e 'ZentinelAgentSdk.run(MyAgent, socket: "/tmp/custom.sock")'
```

---

## Zentinel Configuration

Configure Zentinel to connect to your agent:

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

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `unix-socket path="..."` | Path to agent's Unix socket | required |
| `events` | Events to send: `request_headers`, `request_body`, `response_headers`, `response_body` | `request_headers` |
| `timeout-ms` | Timeout for agent calls | `1000` |
| `failure-mode` | `"open"` (allow on failure) or `"closed"` (block on failure) | `"open"` |

See [docs/configuration.md](docs/configuration.md) for complete configuration reference.

---

## Examples

The `examples/` directory contains complete, runnable examples:

| Example | Description |
|---------|-------------|
| [`simple_agent.exs`](examples/simple_agent.exs) | Basic request blocking and header modification |
| [`configurable_agent.exs`](examples/configurable_agent.exs) | Rate limiting with typed configuration |
| [`body_inspection_agent.exs`](examples/body_inspection_agent.exs) | Request and response body inspection |

See [docs/examples.md](docs/examples.md) for more patterns: authentication, rate limiting, IP filtering, header transformation, and more.

---

## Development

This project uses [mise](https://mise.jdx.dev/) for tool management.

```bash
# Install tools
mise install

# Install dependencies
mix deps.get

# Run tests
mix test

# Run tests with coverage
mix test --cover

# Type checking
mix dialyzer

# Lint
mix format --check-formatted

# Format code
mix format
```

### Without mise

```bash
# Ensure Elixir 1.17+ and Erlang 27+ are installed
mix deps.get
mix test
```

### Project Structure

```
zentinel-agent-elixir-sdk/
├── lib/zentinel_agent_sdk/
│   ├── agent.ex         # Agent and ConfigurableAgent behaviours
│   ├── decision.ex      # Decision builder
│   ├── protocol.ex      # Wire protocol types and encoding
│   ├── request.ex       # Request wrapper
│   ├── response.ex      # Response wrapper
│   └── runner.ex        # Runner and socket handling
├── test/
│   ├── zentinel_agent_sdk_test.exs     # Unit tests
│   ├── protocol_conformance_test.exs   # Protocol compatibility tests
│   └── integration/                    # Integration tests
├── examples/                           # Example agents
└── docs/                               # Documentation
```

---

## Protocol

This SDK implements Zentinel Agent Protocol v2:

- **Transport**: Unix domain sockets (UDS) or gRPC
- **Encoding**: Length-prefixed JSON (4-byte big-endian length prefix) for UDS
- **Max message size**: 10 MB
- **Events**: `configure`, `request_headers`, `request_body_chunk`, `response_headers`, `response_body_chunk`, `request_complete`, `websocket_frame`, `guardrail_inspect`
- **Decisions**: `allow`, `block`, `redirect`, `challenge`

The protocol is designed for low latency and high throughput, with support for streaming body inspection.

For the canonical protocol specification, see the [Zentinel Agent Protocol documentation](https://github.com/zentinelproxy/zentinel/tree/main/crates/agent-protocol).

---

## Community

- [Issues](https://github.com/zentinelproxy/zentinel-agent-elixir-sdk/issues) — Bug reports and feature requests
- [Zentinel Discussions](https://github.com/zentinelproxy/zentinel/discussions) — Questions and ideas
- [Zentinel Documentation](https://zentinelproxy.io/docs) — Proxy documentation

Contributions welcome. Please open an issue to discuss significant changes before submitting a PR.

---

## License

Apache 2.0 — See [LICENSE](LICENSE).
