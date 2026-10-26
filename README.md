<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">Elixir agent SDK</h3>

<p align="center">Write Zentinel agents in Elixir, speaking agent protocol v2 over a Unix socket or gRPC.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-elixir-sdk/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-elixir-sdk/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&labelColor=1f161e">
  <img alt="Agent protocol: v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&labelColor=1f161e">
  <img alt="Elixir 1.18+" src="https://img.shields.io/badge/elixir-1.18%2B-f68d31?style=flat&labelColor=1f161e&logo=elixir&logoColor=white">
</p>

<p align="center">
  <a href="https://docs.zentinelproxy.io/agents/v2/">Agent protocol</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

The SDK gives you an agent behaviour with one callback per event, a pipeable
`Decision` builder, typed configuration, and in `ZentinelAgentSdk.V2` a runner
with Unix socket and gRPC transports and supervision via `child_spec`. It is
not on Hex; use it as a GitHub dependency.

> **Status (0.3.0, checked on 2026-10-22 against Zentinel 26.10_8):** agents
> built with this SDK pass the [SDK conformance harness][harness] over both
> the Unix socket and gRPC: handshake, configuration delivery, request and
> response header mutations, blocking, request body inspection, and
> reconnecting after the agent restarts. CI runs the harness on every change.
> Before 0.3.0 both runners spoke the v1 framing and could not complete a
> handshake (zentinel#600).
>
> Configuration delivery (an agent's `config { }` block reaching
> `on_configure/1`) needs Zentinel 26.10_8 or later, which sends the block
> on every connection (zentinel#603); releases up to 0.6.50 (26.10_7) never
> did, so there the agent runs unconfigured.

[harness]: https://github.com/zentinelproxy/zentinel/tree/main/sdk-conformance

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
([`examples/hello_agent.exs`](examples/hello_agent.exs) is this agent; CI runs
it through the conformance harness.)

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

### gRPC

The same agent serves gRPC (`zentinel.agent.v2.AgentServiceV2`) with

```elixir
ZentinelAgentSdk.V2.run(HelloAgent, transport: :grpc, grpc_address: "127.0.0.1:50051")
```

and `grpc "http://127.0.0.1:50051"` in place of `unix-socket` in the agent
block. `transport: :both` with `socket:` and `grpc_address:` serves both.

## Install

In `mix.exs`:

```elixir
def deps do
  [
    {:zentinel_agent_sdk, github: "zentinelproxy/zentinel-agent-elixir-sdk"}
  ]
end
```

or `Mix.install/1` with the same tuple in a script, as above. Elixir 1.18 or
later (`mix.exs`; the gRPC dependencies need it). The package is not on Hex.

## API overview

- **`ZentinelAgentSdk.Agent`** (`use` it): `name/0`, `on_request/1`,
  `on_request_body/1`, `on_response/2`, `on_response_body/2`,
  `on_request_complete/3`, `on_configure/1`, `on_guardrail_inspect/1`, with
  allow-everything defaults.
- **`ZentinelAgentSdk.V2.Agent`**: adds `capabilities/0`, `version/0`,
  `health_check/0`, `metrics/0`, `on_cancel`, `on_drain`, `on_shutdown`,
  `on_stream_closed`. `ZentinelAgentSdk.V2.run/2` takes `transport:`
  (`:uds`, `:grpc`, `:both`, or `:reverse`), `socket:`, `grpc_address:`,
  `log_level:`, `json_logs:`. `:reverse` (the agent dials the proxy) follows
  the protocol crate's registration handshake, but the `zentinel` binary does
  not open a reverse-connection listener, so it is untested against it.
- **`ZentinelAgentSdk.run/2`** serves a `ZentinelAgentSdk.Agent` on the Unix
  socket, through the same v2 server.
- **`Request` / `Response`**: header, path, query, client IP and body functions.
- **`Decision`**: `allow()`, `deny()`, `unauthorized()`, `rate_limited()`,
  `block(status)`, `redirect(url)`, `challenge(..)`, then pipe into
  `add_request_header`, `remove_request_header`, `add_response_header`,
  `with_body`, `with_json_body`, `with_tag`, `with_rule_id`, `with_confidence`,
  `with_metadata`, `with_routing_metadata`, body mutations.

Examples are in [`examples/`](examples/).

## Development

```bash
mise install        # Erlang 27, Elixir 1.18
mix deps.get
mix compile --warnings-as-errors
mix test
mix format --check-formatted
```

CI runs on Elixir 1.18 / OTP 27. To run the agents behind a real proxy, build
`zentinel` from a checkout of zentinelproxy/zentinel
(`cargo build -p zentinel-proxy --bin zentinel`) and run the harness:

```bash
python3 ../zentinel/sdk-conformance/run.py --zentinel-bin ../zentinel/target/debug/zentinel \
  --agent-cmd 'mix run examples/conformance_agent.exs --socket {socket}' \
  --grpc-agent-cmd 'mix run examples/conformance_agent.exs --grpc {grpc}'
```

or `ZENTINEL_BIN=... ZENTINEL_CONFORMANCE_HARNESS=.../run.py mix test --only zentinel`.
The gRPC message modules are generated from the proxy's proto by
`scripts/gen_proto.sh`.

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
