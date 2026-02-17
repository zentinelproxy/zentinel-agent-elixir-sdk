defmodule ZentinelAgentSdk.Request do
  @moduledoc """
  Ergonomic wrapper around HTTP request data.

  Provides convenient functions for accessing request properties,
  headers, query parameters, and body content.

  ## Example

      def on_request(request) do
        if Request.path_starts_with?(request, "/api") do
          case Request.header(request, "authorization") do
            nil -> Decision.unauthorized()
            _token -> Decision.allow()
          end
        else
          Decision.allow()
        end
      end
  """

  alias ZentinelAgentSdk.Protocol.{RequestHeadersEvent, RequestMetadata}

  @type t :: %__MODULE__{
          event: RequestHeadersEvent.t(),
          body: binary(),
          parsed_uri: URI.t(),
          query_params: %{String.t() => [String.t()]} | nil
        }

  defstruct [:event, :body, :parsed_uri, :query_params]

  @doc """
  Create a new Request from a RequestHeadersEvent.
  """
  @spec new(RequestHeadersEvent.t(), binary()) :: t()
  def new(%RequestHeadersEvent{} = event, body \\ <<>>) do
    %__MODULE__{
      event: event,
      body: body,
      parsed_uri: URI.parse(event.uri),
      query_params: nil
    }
  end

  @doc """
  Get the request metadata.
  """
  @spec metadata(t()) :: RequestMetadata.t()
  def metadata(%__MODULE__{event: event}), do: event.metadata

  @doc """
  Get the correlation ID for request tracing.
  """
  @spec correlation_id(t()) :: String.t()
  def correlation_id(%__MODULE__{event: event}), do: event.metadata.correlation_id

  @doc """
  Get the client IP address.
  """
  @spec client_ip(t()) :: String.t()
  def client_ip(%__MODULE__{event: event}), do: event.metadata.client_ip

  @doc """
  Get the HTTP method.
  """
  @spec method(t()) :: String.t()
  def method(%__MODULE__{event: event}), do: event.method

  @doc "Check if this is a GET request."
  @spec is_get?(t()) :: boolean()
  def is_get?(%__MODULE__{event: event}), do: String.upcase(event.method) == "GET"

  @doc "Check if this is a POST request."
  @spec is_post?(t()) :: boolean()
  def is_post?(%__MODULE__{event: event}), do: String.upcase(event.method) == "POST"

  @doc "Check if this is a PUT request."
  @spec is_put?(t()) :: boolean()
  def is_put?(%__MODULE__{event: event}), do: String.upcase(event.method) == "PUT"

  @doc "Check if this is a DELETE request."
  @spec is_delete?(t()) :: boolean()
  def is_delete?(%__MODULE__{event: event}), do: String.upcase(event.method) == "DELETE"

  @doc "Check if this is a PATCH request."
  @spec is_patch?(t()) :: boolean()
  def is_patch?(%__MODULE__{event: event}), do: String.upcase(event.method) == "PATCH"

  @doc """
  Get the full URI including query string.
  """
  @spec uri(t()) :: String.t()
  def uri(%__MODULE__{event: event}), do: event.uri

  @doc """
  Get the full path including query string.
  """
  @spec path(t()) :: String.t()
  def path(%__MODULE__{event: event}), do: event.uri

  @doc """
  Get just the path without query string.
  """
  @spec path_only(t()) :: String.t()
  def path_only(%__MODULE__{parsed_uri: uri}), do: uri.path || "/"

  @doc """
  Get the raw query string.
  """
  @spec query_string(t()) :: String.t()
  def query_string(%__MODULE__{parsed_uri: uri}), do: uri.query || ""

  @doc """
  Get a single query parameter value.

  Returns the first value for the parameter, or nil if not present.
  """
  @spec query(t(), String.t()) :: String.t() | nil
  def query(%__MODULE__{} = request, name) do
    params = get_query_params(request)

    case Map.get(params, name) do
      [value | _] -> value
      _ -> nil
    end
  end

  @doc """
  Get all values for a query parameter.

  Returns all values for the parameter, or empty list if not present.
  """
  @spec query_all(t(), String.t()) :: [String.t()]
  def query_all(%__MODULE__{} = request, name) do
    params = get_query_params(request)
    Map.get(params, name, [])
  end

  defp get_query_params(%__MODULE__{query_params: params}) when is_map(params), do: params

  defp get_query_params(%__MODULE__{parsed_uri: uri}) do
    case uri.query do
      nil -> %{}
      query -> URI.decode_query(query) |> decode_multi_values()
    end
  end

  defp decode_multi_values(params) do
    Enum.map(params, fn {k, v} -> {k, [v]} end) |> Map.new()
  end

  @doc """
  Check if the path starts with the given prefix.
  """
  @spec path_starts_with?(t(), String.t()) :: boolean()
  def path_starts_with?(%__MODULE__{} = request, prefix) do
    String.starts_with?(path_only(request), prefix)
  end

  @doc """
  Check if the path exactly matches.
  """
  @spec path_equals?(t(), String.t()) :: boolean()
  def path_equals?(%__MODULE__{} = request, expected_path) do
    path_only(request) == expected_path
  end

  @doc """
  Get all headers as a map.
  """
  @spec headers(t()) :: %{String.t() => [String.t()]}
  def headers(%__MODULE__{event: event}), do: event.headers

  @doc """
  Get a single header value (case-insensitive).

  Returns the first value for the header, or nil if not present.
  """
  @spec header(t(), String.t()) :: String.t() | nil
  def header(%__MODULE__{event: event}, name) do
    name_lower = String.downcase(name)

    Enum.find_value(event.headers, fn {key, values} ->
      if String.downcase(key) == name_lower and values != [] do
        List.first(values)
      end
    end)
  end

  @doc """
  Get all values for a header (case-insensitive).

  Returns all values for the header, or empty list if not present.
  """
  @spec header_all(t(), String.t()) :: [String.t()]
  def header_all(%__MODULE__{event: event}, name) do
    name_lower = String.downcase(name)

    Enum.find_value(event.headers, [], fn {key, values} ->
      if String.downcase(key) == name_lower, do: values
    end)
  end

  @doc """
  Check if a header exists (case-insensitive).
  """
  @spec has_header?(t(), String.t()) :: boolean()
  def has_header?(%__MODULE__{event: event}, name) do
    name_lower = String.downcase(name)
    Enum.any?(event.headers, fn {key, _} -> String.downcase(key) == name_lower end)
  end

  @doc "Get the Host header value."
  @spec host(t()) :: String.t() | nil
  def host(%__MODULE__{} = request), do: header(request, "host")

  @doc "Get the User-Agent header value."
  @spec user_agent(t()) :: String.t() | nil
  def user_agent(%__MODULE__{} = request), do: header(request, "user-agent")

  @doc "Get the Content-Type header value."
  @spec content_type(t()) :: String.t() | nil
  def content_type(%__MODULE__{} = request), do: header(request, "content-type")

  @doc "Get the Authorization header value."
  @spec authorization(t()) :: String.t() | nil
  def authorization(%__MODULE__{} = request), do: header(request, "authorization")

  @doc "Get the Content-Length header value as an integer."
  @spec content_length(t()) :: integer() | nil
  def content_length(%__MODULE__{} = request) do
    case header(request, "content-length") do
      nil -> nil
      value -> String.to_integer(value)
    end
  rescue
    ArgumentError -> nil
  end

  @doc "Check if the content type indicates JSON."
  @spec is_json?(t()) :: boolean()
  def is_json?(%__MODULE__{} = request) do
    case content_type(request) do
      nil -> false
      ct -> String.contains?(String.downcase(ct), "application/json")
    end
  end

  @doc "Get the raw body bytes."
  @spec body(t()) :: binary()
  def body(%__MODULE__{body: body}), do: body

  @doc "Get the body as a UTF-8 string."
  @spec body_str(t()) :: String.t()
  def body_str(%__MODULE__{body: body}) do
    case :unicode.characters_to_binary(body, :utf8) do
      {:error, _, _} -> :unicode.characters_to_binary(body, :latin1)
      {:incomplete, _, _} -> :unicode.characters_to_binary(body, :latin1)
      result -> result
    end
  end

  @doc """
  Parse the body as JSON.

  Raises on invalid JSON.
  """
  @spec body_json(t()) :: term()
  def body_json(%__MODULE__{body: body}), do: Jason.decode!(body)

  @doc """
  Parse the body as JSON, returning {:ok, value} or {:error, reason}.
  """
  @spec body_json!(t()) :: {:ok, term()} | {:error, term()}
  def body_json!(%__MODULE__{body: body}), do: Jason.decode(body)

  @doc """
  Create a new Request with the given body.
  """
  @spec with_body(t(), binary()) :: t()
  def with_body(%__MODULE__{event: event}, body) do
    new(event, body)
  end

  defimpl Inspect do
    def inspect(%ZentinelAgentSdk.Request{event: event}, _opts) do
      "#Request<#{event.method} #{event.uri}>"
    end
  end
end
