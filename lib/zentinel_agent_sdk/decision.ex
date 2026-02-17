defmodule ZentinelAgentSdk.Decision do
  @moduledoc """
  Fluent builder for agent decisions.

  Provides a chainable API for building agent responses with
  decisions, header mutations, and audit metadata.

  ## Example

      Decision.deny()
      |> Decision.with_body("Access denied")
      |> Decision.with_tag("blocked")
      |> Decision.with_rule_id("block-admin-paths")

  ## Decision Types

  - `allow/0` - Pass the request through
  - `deny/0` - Block with 403 Forbidden
  - `unauthorized/0` - Block with 401 Unauthorized
  - `rate_limited/0` - Block with 429 Too Many Requests
  - `block/1` - Block with custom status code
  - `redirect/2` - Redirect to URL
  - `redirect_permanent/1` - 301 redirect
  - `challenge/2` - Challenge (e.g., CAPTCHA)
  """

  alias ZentinelAgentSdk.Protocol.{AgentResponse, AuditMetadata, HeaderOp}

  @type t :: %__MODULE__{
          decision: String.t() | map(),
          request_headers: [HeaderOp.t()],
          response_headers: [HeaderOp.t()],
          routing_metadata: map(),
          audit: AuditMetadata.t(),
          needs_more: boolean(),
          request_body_mutation: map() | nil,
          response_body_mutation: map() | nil
        }

  defstruct decision: "allow",
            request_headers: [],
            response_headers: [],
            routing_metadata: %{},
            audit: %AuditMetadata{},
            needs_more: false,
            request_body_mutation: nil,
            response_body_mutation: nil

  @doc """
  Create an allow decision (pass request through).
  """
  @spec allow() :: t()
  def allow, do: %__MODULE__{decision: "allow"}

  @doc """
  Create a block decision (reject with status).
  """
  @spec block(integer()) :: t()
  def block(status \\ 403), do: %__MODULE__{decision: %{"block" => %{"status" => status}}}

  @doc """
  Create a deny decision (block with 403).
  """
  @spec deny() :: t()
  def deny, do: block(403)

  @doc """
  Create an unauthorized decision (block with 401).
  """
  @spec unauthorized() :: t()
  def unauthorized, do: block(401)

  @doc """
  Create a rate limited decision (block with 429).
  """
  @spec rate_limited() :: t()
  def rate_limited, do: block(429)

  @doc """
  Create a redirect decision.
  """
  @spec redirect(String.t(), integer()) :: t()
  def redirect(url, status \\ 302) do
    %__MODULE__{decision: %{"redirect" => %{"url" => url, "status" => status}}}
  end

  @doc """
  Create a permanent redirect decision (301).
  """
  @spec redirect_permanent(String.t()) :: t()
  def redirect_permanent(url), do: redirect(url, 301)

  @doc """
  Create a challenge decision (e.g., CAPTCHA).
  """
  @spec challenge(String.t(), map() | nil) :: t()
  def challenge(challenge_type, params \\ nil) do
    challenge_data = %{"challenge_type" => challenge_type}
    challenge_data = if params, do: Map.put(challenge_data, "params", params), else: challenge_data
    %__MODULE__{decision: %{"challenge" => challenge_data}}
  end

  @doc """
  Set the response body for block decisions.
  """
  @spec with_body(t(), String.t()) :: t()
  def with_body(%__MODULE__{decision: %{"block" => block_data}} = decision, body) do
    %{decision | decision: %{"block" => Map.put(block_data, "body", body)}}
  end

  def with_body(decision, _body), do: decision

  @doc """
  Set a JSON response body for block decisions.

  Automatically sets Content-Type header to application/json.
  """
  @spec with_json_body(t(), term()) :: t()
  def with_json_body(%__MODULE__{decision: %{"block" => block_data}} = decision, value) do
    block_data =
      block_data
      |> Map.put("body", Jason.encode!(value))
      |> Map.update("headers", %{"Content-Type" => "application/json"}, fn headers ->
        Map.put(headers, "Content-Type", "application/json")
      end)

    %{decision | decision: %{"block" => block_data}}
  end

  def with_json_body(decision, _value), do: decision

  @doc """
  Add a header to the block response.
  """
  @spec with_block_header(t(), String.t(), String.t()) :: t()
  def with_block_header(%__MODULE__{decision: %{"block" => block_data}} = decision, name, value) do
    block_data =
      Map.update(block_data, "headers", %{name => value}, fn headers ->
        Map.put(headers, name, value)
      end)

    %{decision | decision: %{"block" => block_data}}
  end

  def with_block_header(decision, _name, _value), do: decision

  @doc """
  Add a header to the upstream request.
  """
  @spec add_request_header(t(), String.t(), String.t()) :: t()
  def add_request_header(%__MODULE__{request_headers: headers} = decision, name, value) do
    %{decision | request_headers: headers ++ [HeaderOp.set(name, value)]}
  end

  @doc """
  Remove a header from the upstream request.
  """
  @spec remove_request_header(t(), String.t()) :: t()
  def remove_request_header(%__MODULE__{request_headers: headers} = decision, name) do
    %{decision | request_headers: headers ++ [HeaderOp.remove(name)]}
  end

  @doc """
  Add a header to the client response.
  """
  @spec add_response_header(t(), String.t(), String.t()) :: t()
  def add_response_header(%__MODULE__{response_headers: headers} = decision, name, value) do
    %{decision | response_headers: headers ++ [HeaderOp.set(name, value)]}
  end

  @doc """
  Remove a header from the client response.
  """
  @spec remove_response_header(t(), String.t()) :: t()
  def remove_response_header(%__MODULE__{response_headers: headers} = decision, name) do
    %{decision | response_headers: headers ++ [HeaderOp.remove(name)]}
  end

  @doc """
  Add routing metadata.
  """
  @spec with_routing_metadata(t(), String.t(), String.t()) :: t()
  def with_routing_metadata(%__MODULE__{routing_metadata: metadata} = decision, key, value) do
    %{decision | routing_metadata: Map.put(metadata, key, value)}
  end

  @doc """
  Add a single audit tag.
  """
  @spec with_tag(t(), String.t()) :: t()
  def with_tag(%__MODULE__{audit: audit} = decision, tag) do
    %{decision | audit: %{audit | tags: audit.tags ++ [tag]}}
  end

  @doc """
  Add multiple audit tags.
  """
  @spec with_tags(t(), [String.t()]) :: t()
  def with_tags(%__MODULE__{audit: audit} = decision, tags) do
    %{decision | audit: %{audit | tags: audit.tags ++ tags}}
  end

  @doc """
  Add a rule ID to audit metadata.
  """
  @spec with_rule_id(t(), String.t()) :: t()
  def with_rule_id(%__MODULE__{audit: audit} = decision, rule_id) do
    %{decision | audit: %{audit | rule_ids: audit.rule_ids ++ [rule_id]}}
  end

  @doc """
  Set the confidence score.
  """
  @spec with_confidence(t(), float()) :: t()
  def with_confidence(%__MODULE__{audit: audit} = decision, confidence)
      when confidence >= 0.0 and confidence <= 1.0 do
    %{decision | audit: %{audit | confidence: confidence}}
  end

  @doc """
  Add a reason code.
  """
  @spec with_reason_code(t(), String.t()) :: t()
  def with_reason_code(%__MODULE__{audit: audit} = decision, code) do
    %{decision | audit: %{audit | reason_codes: audit.reason_codes ++ [code]}}
  end

  @doc """
  Add custom audit metadata.
  """
  @spec with_metadata(t(), String.t(), term()) :: t()
  def with_metadata(%__MODULE__{audit: audit} = decision, key, value) do
    %{decision | audit: %{audit | custom: Map.put(audit.custom, key, value)}}
  end

  @doc """
  Indicate that the agent needs more data (body chunks).
  """
  @spec needs_more_data(t()) :: t()
  def needs_more_data(%__MODULE__{} = decision) do
    %{decision | needs_more: true}
  end

  @doc """
  Set request body mutation.
  """
  @spec with_request_body_mutation(t(), binary() | nil, integer()) :: t()
  def with_request_body_mutation(%__MODULE__{} = decision, data, chunk_index \\ 0) do
    mutation = %{
      "data" => if(data != nil, do: Base.encode64(data), else: nil),
      "chunk_index" => chunk_index
    }

    %{decision | request_body_mutation: mutation}
  end

  @doc """
  Set response body mutation.
  """
  @spec with_response_body_mutation(t(), binary() | nil, integer()) :: t()
  def with_response_body_mutation(%__MODULE__{} = decision, data, chunk_index \\ 0) do
    mutation = %{
      "data" => if(data != nil, do: Base.encode64(data), else: nil),
      "chunk_index" => chunk_index
    }

    %{decision | response_body_mutation: mutation}
  end

  @doc """
  Build the AgentResponse.
  """
  @spec build(t()) :: AgentResponse.t()
  def build(%__MODULE__{} = decision) do
    %AgentResponse{
      decision: decision.decision,
      request_headers: decision.request_headers,
      response_headers: decision.response_headers,
      routing_metadata: decision.routing_metadata,
      audit: decision.audit,
      needs_more: decision.needs_more,
      request_body_mutation: decision.request_body_mutation,
      response_body_mutation: decision.response_body_mutation
    }
  end

  @doc """
  Convert decision to a map for serialization.
  """
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = decision) do
    decision |> build() |> AgentResponse.to_map()
  end
end

defmodule ZentinelAgentSdk.Decisions do
  @moduledoc """
  Shorthand functions for common decisions.

  ## Example

      import ZentinelAgentSdk.Decisions

      def on_request(request) do
        if blocked?(request), do: deny(), else: allow()
      end
  """

  alias ZentinelAgentSdk.Decision

  @doc "Create an allow decision."
  @spec allow() :: Decision.t()
  def allow, do: Decision.allow()

  @doc "Create a deny decision (403)."
  @spec deny() :: Decision.t()
  def deny, do: Decision.deny()

  @doc "Create an unauthorized decision (401)."
  @spec unauthorized() :: Decision.t()
  def unauthorized, do: Decision.unauthorized()

  @doc "Create a rate limited decision (429)."
  @spec rate_limited() :: Decision.t()
  def rate_limited, do: Decision.rate_limited()

  @doc "Create a block decision with optional body."
  @spec block(integer(), String.t() | nil) :: Decision.t()
  def block(status, body \\ nil) do
    d = Decision.block(status)
    if body, do: Decision.with_body(d, body), else: d
  end

  @doc "Create a redirect decision."
  @spec redirect(String.t(), boolean()) :: Decision.t()
  def redirect(url, permanent \\ false) do
    if permanent, do: Decision.redirect_permanent(url), else: Decision.redirect(url)
  end
end
