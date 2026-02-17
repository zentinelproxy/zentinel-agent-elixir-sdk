# API Reference

## Agent

The behaviour for all Zentinel agents.

```elixir
use ZentinelAgentSdk.Agent
```

### Required Callbacks

#### `name/0`

```elixir
@callback name() :: String.t()
```

Returns the agent identifier used for logging.

### Event Handlers

#### `on_configure/1`

```elixir
@callback on_configure(config :: map()) :: :ok | {:error, String.t()}
```

Called when the agent receives configuration from the proxy. Override to validate and store configuration.

**Default**: Returns `:ok`

#### `on_request/1`

```elixir
@callback on_request(request :: Request.t()) :: Decision.t()
```

Called when request headers are received. This is the main entry point for request processing.

**Default**: Returns `Decision.allow()`

#### `on_request_body/1`

```elixir
@callback on_request_body(request :: Request.t()) :: Decision.t()
```

Called when the request body is available (requires body inspection to be enabled in Zentinel).

**Default**: Returns `Decision.allow()`

#### `on_response/2`

```elixir
@callback on_response(request :: Request.t(), response :: Response.t()) :: Decision.t()
```

Called when response headers are received from the upstream server.

**Default**: Returns `Decision.allow()`

#### `on_response_body/2`

```elixir
@callback on_response_body(request :: Request.t(), response :: Response.t()) :: Decision.t()
```

Called when the response body is available (requires body inspection to be enabled).

**Default**: Returns `Decision.allow()`

#### `on_request_complete/3`

```elixir
@callback on_request_complete(request :: Request.t(), status :: integer(), duration_ms :: integer()) :: :ok
```

Called when request processing is complete. Use for logging or metrics.

**Default**: Returns `:ok`

---

## ConfigurableAgent

A behaviour for agents with typed configuration support.

```elixir
use ZentinelAgentSdk.ConfigurableAgent
```

### Additional Callbacks

#### `default_config/0`

```elixir
@callback default_config() :: term()
```

Returns the default configuration struct.

#### `parse_config/1`

```elixir
@callback parse_config(config_map :: map()) :: term()
```

Parse configuration map into typed config struct.

#### `on_config_applied/1`

```elixir
@callback on_config_applied(config :: term()) :: :ok
```

Called after new configuration is applied.

### Example

```elixir
defmodule MyConfig do
  defstruct rate_limit: 100, enabled: true
end

defmodule MyAgent do
  use ZentinelAgentSdk.ConfigurableAgent

  @impl true
  def name, do: "my-agent"

  @impl true
  def default_config, do: %MyConfig{}

  @impl true
  def parse_config(config_map) do
    %MyConfig{
      rate_limit: Map.get(config_map, "rate_limit", 100),
      enabled: Map.get(config_map, "enabled", true)
    }
  end

  @impl true
  def on_request(request, config) do
    if not config.enabled do
      Decision.allow()
    else
      # Use config.rate_limit...
      Decision.allow()
    end
  end
end
```

---

## Decision

Fluent builder for agent decisions.

```elixir
alias ZentinelAgentSdk.Decision
```

### Factory Functions

#### `Decision.allow/0`

Create an allow decision (pass request through).

```elixir
Decision.allow()
```

#### `Decision.block/1`

Create a block decision with a status code.

```elixir
Decision.block(403)
Decision.block(500)
```

#### `Decision.deny/0`

Shorthand for `Decision.block(403)`.

```elixir
Decision.deny()
```

#### `Decision.unauthorized/0`

Shorthand for `Decision.block(401)`.

```elixir
Decision.unauthorized()
```

#### `Decision.rate_limited/0`

Shorthand for `Decision.block(429)`.

```elixir
Decision.rate_limited()
```

#### `Decision.redirect/2`

Create a redirect decision.

```elixir
Decision.redirect("https://example.com/login")
Decision.redirect("https://example.com/new-path", 301)
```

#### `Decision.redirect_permanent/1`

Shorthand for `Decision.redirect(url, 301)`.

```elixir
Decision.redirect_permanent("https://example.com/new-path")
```

#### `Decision.challenge/2`

Create a challenge decision (e.g., CAPTCHA).

```elixir
Decision.challenge("captcha", %{"site_key" => "..."})
```

### Chaining Functions

All functions return the decision for chaining with the pipe operator.

#### `with_body/2`

Set the response body for block decisions.

```elixir
Decision.deny() |> Decision.with_body("Access denied")
```

#### `with_json_body/2`

Set a JSON response body. Automatically sets `Content-Type: application/json`.

```elixir
Decision.block(400) |> Decision.with_json_body(%{"error" => "Invalid request"})
```

#### `with_block_header/3`

Add a header to the block response.

```elixir
Decision.deny() |> Decision.with_block_header("X-Blocked-By", "my-agent")
```

#### `add_request_header/3`

Add a header to the upstream request.

```elixir
Decision.allow() |> Decision.add_request_header("X-User-ID", "123")
```

#### `remove_request_header/2`

Remove a header from the upstream request.

```elixir
Decision.allow() |> Decision.remove_request_header("Cookie")
```

#### `add_response_header/3`

Add a header to the client response.

```elixir
Decision.allow() |> Decision.add_response_header("X-Frame-Options", "DENY")
```

#### `remove_response_header/2`

Remove a header from the client response.

```elixir
Decision.allow() |> Decision.remove_response_header("Server")
```

### Audit Functions

#### `with_tag/2`

Add an audit tag.

```elixir
Decision.deny() |> Decision.with_tag("security")
```

#### `with_tags/2`

Add multiple audit tags.

```elixir
Decision.deny() |> Decision.with_tags(["blocked", "rate-limit"])
```

#### `with_rule_id/2`

Add a rule ID for audit logging.

```elixir
Decision.deny() |> Decision.with_rule_id("SQLI-001")
```

#### `with_confidence/2`

Set a confidence score (0.0 to 1.0).

```elixir
Decision.deny() |> Decision.with_confidence(0.95)
```

#### `with_reason_code/2`

Add a reason code.

```elixir
Decision.deny() |> Decision.with_reason_code("IP_BLOCKED")
```

#### `with_metadata/3`

Add custom audit metadata.

```elixir
Decision.deny() |> Decision.with_metadata("blocked_ip", "192.168.1.100")
```

### Advanced Functions

#### `needs_more_data/1`

Indicate that more data is needed before deciding.

```elixir
Decision.allow() |> Decision.needs_more_data()
```

#### `with_routing_metadata/3`

Add routing metadata for upstream selection.

```elixir
Decision.allow() |> Decision.with_routing_metadata("upstream", "backend-v2")
```

#### `with_request_body_mutation/3`

Set a mutation for the request body.

```elixir
Decision.allow() |> Decision.with_request_body_mutation("modified body", 0)
```

#### `with_response_body_mutation/3`

Set a mutation for the response body.

```elixir
Decision.allow() |> Decision.with_response_body_mutation("modified body", 0)
```

---

## Request

Represents an incoming HTTP request.

```elixir
alias ZentinelAgentSdk.Request
```

### Path and URI

#### `method/1`

The HTTP method (GET, POST, etc.).

```elixir
Request.method(request)  # "GET"
```

#### `uri/1`

The full URI including query string.

```elixir
Request.uri(request)  # "/api/users?page=1"
```

#### `path_only/1`

The request path without query string.

```elixir
Request.path_only(request)  # "/api/users"
```

#### `query_string/1`

The raw query string.

```elixir
Request.query_string(request)  # "page=1&limit=10"
```

#### `path_starts_with?/2`

Check if the path starts with a prefix.

```elixir
Request.path_starts_with?(request, "/api/")  # true
```

#### `path_equals?/2`

Check if the path exactly matches.

```elixir
Request.path_equals?(request, "/health")  # true
```

### Method Checks

```elixir
Request.is_get?(request)
Request.is_post?(request)
Request.is_put?(request)
Request.is_delete?(request)
Request.is_patch?(request)
```

### Headers

#### `header/2`

Get a single header value (case-insensitive).

```elixir
Request.header(request, "authorization")  # "Bearer ..."
```

#### `header_all/2`

Get all values for a header.

```elixir
Request.header_all(request, "accept")  # ["application/json", "text/plain"]
```

#### `has_header?/2`

Check if a header exists.

```elixir
Request.has_header?(request, "Authorization")  # true
```

### Common Headers

```elixir
Request.host(request)          # Host header
Request.user_agent(request)    # User-Agent header
Request.content_type(request)  # Content-Type header
Request.authorization(request) # Authorization header
```

### Query Parameters

#### `query/2`

Get a single query parameter value.

```elixir
Request.query(request, "page")  # "1"
```

#### `query_all/2`

Get all values for a query parameter.

```elixir
Request.query_all(request, "tag")  # ["elixir", "sdk"]
```

### Body

#### `body/1`

Get the request body as binary.

```elixir
Request.body(request)  # <<...>>
```

#### `body_str/1`

Get the request body as string.

```elixir
Request.body_str(request)  # "{\"name\": \"test\"}"
```

#### `body_json/1`

Parse the body as JSON.

```elixir
Request.body_json(request)  # %{"name" => "test"}
```

### Metadata

```elixir
Request.correlation_id(request)  # Request correlation ID
Request.request_id(request)      # Unique request ID
Request.client_ip(request)       # Client IP address
Request.client_port(request)     # Client port
Request.server_name(request)     # Server name
Request.protocol(request)        # HTTP protocol version
```

### Content Type Checks

```elixir
Request.is_json?(request)
Request.is_form?(request)
Request.is_multipart?(request)
```

---

## Response

Represents an HTTP response from the upstream.

```elixir
alias ZentinelAgentSdk.Response
```

### Status

#### `status_code/1`

The HTTP status code.

```elixir
Response.status_code(response)  # 200
```

#### Status Checks

```elixir
Response.is_success?(response)       # 2xx
Response.is_redirect?(response)      # 3xx
Response.is_client_error?(response)  # 4xx
Response.is_server_error?(response)  # 5xx
Response.is_error?(response)         # 4xx or 5xx
```

### Headers

#### `header/2`

Get a single header value.

```elixir
Response.header(response, "content-type")
```

#### `header_all/2`

Get all values for a header.

```elixir
Response.header_all(response, "set-cookie")
```

#### `has_header?/2`

Check if a header exists.

```elixir
Response.has_header?(response, "content-type")
```

### Common Headers

```elixir
Response.content_type(response)
Response.location(response)  # For redirects
```

### Content Type Checks

```elixir
Response.is_json?(response)
Response.is_html?(response)
```

### Body

```elixir
Response.body(response)       # Raw bytes
Response.body_str(response)   # As string
Response.body_json(response)  # Parsed JSON
```

---

## Runner

The `ZentinelAgentSdk` module provides the runner functions.

### `ZentinelAgentSdk.run/2`

Run an agent with options.

```elixir
ZentinelAgentSdk.run(MyAgent,
  socket: "/tmp/my-agent.sock",
  log_level: :debug,
  json_logs: true
)
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `:socket` | Unix socket path | `/tmp/zentinel-agent.sock` |
| `:log_level` | Log level | `:info` |
| `:json_logs` | Enable JSON logs | `false` |
