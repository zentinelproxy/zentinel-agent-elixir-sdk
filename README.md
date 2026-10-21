<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">Elixir agent SDK</h3>

<p align="center">Write Zentinel agents in Elixir, speaking agent protocol v2 over a Unix socket.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-elixir-sdk/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-elixir-sdk/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&labelColor=1f161e">
  <img alt="Agent protocol: v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&labelColor=1f161e">
  <img alt="Elixir 1.15+" src="https://img.shields.io/badge/elixir-1.15%2B-f68d31?style=flat&labelColor=1f161e&logo=elixir&logoColor=white">
</p>

<p align="center">
  <a href="https://docs.zentinelproxy.io/agents/v2/">Agent protocol</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

The SDK gives you an agent behaviour with one callback per event, a pipeable
`Decision` builder, typed configuration, and in `ZentinelAgentSdk.V2` a runner
with Unix socket and reverse (agent dials the proxy) transports, health and
metrics reporting, and supervision via `child_spec`. There is no gRPC
transport. It is not on Hex; use it as a GitHub dependency.

> **Status (checked on 2026-10-21 against Zentinel 0.6.50): agents built with this SDK do not connect to Zentinel.**
> Both runners (`ZentinelAgentSdk.run` and `ZentinelAgentSdk.V2.run`) read the
> v1 framing (length plus JSON, no message-type byte), so the proxy's v2
> handshake fails with `Failed to decode JSON message`. Unit tests pass in CI.
> The quick start shows the intended shape.

## Quick start

Create `hello_agent.exs`:

```elixir
Mix.install([{:zentinel_agent_sdk, github: "zentinelproxy/zentinel-agent-elixir-sdk"}])

defmodule HelloAgent do
  use ZentinelAgentSdk.V2.Agent

  @impl true
  def name, do: "hello"

  @impl true
  def on_request(_request) do
    Decision.allow() |> Decision.add_request_header("X-Hello", "from-agent")
  end
end

ZentinelAgentSdk.V2.run(HelloAgent, socket: "/tmp/hello.sock")
```

Run it with `elixir hello_agent.exs`. It listens on `/tmp/hello.sock`.

Then point Zentinel at the socket. This assumes your config already defines a
listener and an upstream named `backend`:

```kdl
agents {
    agent "hello" type="custom" {
        unix-socket "/tmp/hello.sock"
        events "request_headers"
        timeout-ms 100
    }
}

filters {
    filter "hello" {
        type "agent"
        agent "hello"
        failure-mode "closed"
    }
}

routes {
    route "default" {
        matches {
            path-prefix "/"
        }
        upstream "backend"
        filters "hello"
    }
}
```

Check the file with `zentinel test -c zentinel.kdl` and start Zentinel. Every
request on the route then reaches `backend` with `X-Hello: from-agent`.
`failure-mode "closed"` on the filter turns an unreachable agent into a 503
instead of letting requests through unprocessed, so a wiring mistake shows up
on the first request.

With this SDK as it is today, that 503 is what you get: see the status note
above.

## Install

In `mix.exs`:

```elixir
def deps do
  [
    {:zentinel_agent_sdk, github: "zentinelproxy/zentinel-agent-elixir-sdk"}
  ]
end
```

or `Mix.install/1` with the same tuple in a script, as above. Elixir 1.15 or
later (`mix.exs`). The package is not on Hex.

## API overview

- **`ZentinelAgentSdk.Agent`** (`use` it): `name/0`, `on_request/1`,
  `on_request_body/1`, `on_response/2`, `on_response_body/2`,
  `on_request_complete/3`, `on_configure/1`, `on_guardrail_inspect/1`, with
  allow-everything defaults.
- **`ZentinelAgentSdk.V2.Agent`**: adds `capabilities/0`, `version/0`,
  `health_check/0`, `metrics/0`, `on_cancel`, `on_drain`, `on_shutdown`,
  `on_stream_closed`. `ZentinelAgentSdk.V2.run/2` takes `transport:`
  (`:uds` or `:reverse`), `socket:`, `log_level:`, `json_logs:`.
- **`Request` / `Response`**: header, path, query, client IP and body functions.
- **`Decision`**: `allow()`, `deny()`, `unauthorized()`, `rate_limited()`,
  `block(status)`, `redirect(url)`, `challenge(..)`, then pipe into
  `add_request_header`, `remove_request_header`, `add_response_header`,
  `with_body`, `with_json_body`, `with_tag`, `with_rule_id`, `with_confidence`,
  `with_metadata`, `with_routing_metadata`, body mutations.

Examples are in [`examples/`](examples/).

## Development

```bash
mise install        # Erlang 27, Elixir 1.17
mix deps.get
mix compile
mix test
mix format --check-formatted
```

CI runs on Elixir 1.15 / OTP 26.

## Related

- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Agent configuration](https://docs.zentinelproxy.io/configuration/agents/)
- [Guides in this repository](docs/index.md): quickstart, API, configuration, examples
- [Other SDKs](https://github.com/zentinelproxy?q=sdk)
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
