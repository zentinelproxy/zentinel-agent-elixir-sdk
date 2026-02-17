# Zentinel Configuration

How to configure Zentinel to use your Elixir agents.

## Agent Definition

Define your agent in the `agents` block of your Zentinel configuration:

```kdl
agents {
    agent "my-agent" type="custom" {
        unix-socket path="/tmp/my-agent.sock"
        events "request_headers"
        timeout-ms 100
        failure-mode "open"
    }
}
```

### Agent Options

| Option | Description | Default |
|--------|-------------|---------|
| `type` | Agent type: `custom`, `auth`, `waf`, `rate_limit` | required |
| `unix-socket path="..."` | Path to Unix socket | required |
| `events` | Events to subscribe to (see below) | `request_headers` |
| `timeout-ms` | Timeout for agent calls in milliseconds | `1000` |
| `failure-mode` | What to do on agent failure: `open` or `closed` | `open` |
| `max-concurrent-calls` | Max concurrent calls to agent | `100` |

### Event Types

Specify which events your agent receives:

```kdl
agent "my-agent" type="custom" {
    unix-socket path="/tmp/my-agent.sock"
    events "request_headers" "request_body" "response_headers"
}
```

Available events:

| Event | Description |
|-------|-------------|
| `request_headers` | When request headers are received |
| `request_body` | When request body is available |
| `response_headers` | When response headers are received |
| `response_body` | When response body is available |

## Filter Definition

Create a filter that uses your agent:

```kdl
filters {
    filter "my-filter" {
        type "agent"
        agent "my-agent"
        timeout-ms 100
        failure-mode "open"
    }
}
```

### Filter Options

| Option | Description | Default |
|--------|-------------|---------|
| `type` | Must be `"agent"` for agent-based filters | required |
| `agent` | Name of the agent to call | required |
| `timeout-ms` | Timeout for this filter | inherits from agent |
| `failure-mode` | Override failure mode | inherits from agent |
| `inspect-body` | Enable body inspection | `false` |

## Route Configuration

Apply the filter to routes:

```kdl
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

### Multiple Filters

Filters are executed in order:

```kdl
routes {
    route "secure-api" {
        matches {
            path-prefix "/api/"
        }
        upstream "backend"
        filters "auth-filter" "rate-limit-filter" "logging-filter"
    }
}
```

## Complete Example

A complete configuration with an agent:

```kdl
system {
    worker-threads 4
    max-connections 10000
}

listeners {
    listener "http" {
        address "0.0.0.0:8080"
        protocol "http"
    }
}

agents {
    agent "auth-agent" type="auth" {
        unix-socket path="/tmp/auth-agent.sock"
        events "request_headers"
        timeout-ms 50
        failure-mode "closed"
    }

    agent "rate-limit" type="rate_limit" {
        unix-socket path="/tmp/rate-limit.sock"
        events "request_headers"
        timeout-ms 10
        failure-mode "open"
    }
}

filters {
    filter "auth" {
        type "agent"
        agent "auth-agent"
        failure-mode "closed"
    }

    filter "rate-limit" {
        type "agent"
        agent "rate-limit"
        failure-mode "open"
    }
}

routes {
    route "api" {
        priority "high"
        matches {
            path-prefix "/api/"
        }
        upstream "api-backend"
        filters "auth" "rate-limit"
    }

    route "public" {
        matches {
            path-prefix "/"
        }
        upstream "web-backend"
        filters "rate-limit"
    }
}

upstreams {
    upstream "api-backend" {
        target "127.0.0.1:3000"
        load-balancing "round_robin"
    }

    upstream "web-backend" {
        target "127.0.0.1:3001"
        load-balancing "round_robin"
    }
}
```

## Failure Modes

### `failure-mode "open"`

If the agent fails (timeout, crash, error), the request is **allowed** to proceed.

Use for:
- Rate limiting
- Logging
- Non-critical checks

### `failure-mode "closed"`

If the agent fails, the request is **blocked** with a 503 error.

Use for:
- Authentication
- Authorization
- Security-critical checks

## Body Inspection

To inspect request or response bodies, enable body inspection:

```kdl
agents {
    agent "body-inspector" type="custom" {
        unix-socket path="/tmp/body-agent.sock"
        events "request_headers" "request_body"
        timeout-ms 200
        failure-mode "open"
        max-request-body-bytes 1048576  // 1MB limit
    }
}
```

### Body Inspection Options

| Option | Description | Default |
|--------|-------------|---------|
| `max-request-body-bytes` | Max request body size to buffer | `1048576` (1MB) |
| `max-response-body-bytes` | Max response body size to buffer | `1048576` (1MB) |

## Circuit Breaker

Configure circuit breaker for agent failures:

```kdl
agent "my-agent" type="custom" {
    unix-socket path="/tmp/my-agent.sock"
    events "request_headers"
    timeout-ms 100
    failure-mode "open"

    circuit-breaker {
        failure-threshold 5
        success-threshold 2
        timeout-seconds 30
        half-open-max-requests 3
    }
}
```

| Option | Description | Default |
|--------|-------------|---------|
| `failure-threshold` | Failures before opening circuit | `5` |
| `success-threshold` | Successes to close circuit | `2` |
| `timeout-seconds` | Time circuit stays open | `30` |
| `half-open-max-requests` | Test requests in half-open state | `3` |

## Debugging

Enable debug logging to see agent communication:

```kdl
observability {
    logging {
        level "debug"
    }
}
```

This will log:
- Agent connections
- Request/response timings
- Decision outcomes
- Errors and timeouts
