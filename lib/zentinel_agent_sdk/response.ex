defmodule ZentinelAgentSdk.Response do
  @moduledoc """
  Ergonomic wrapper around HTTP response data.

  Provides convenient functions for accessing response properties,
  headers, and body content.

  ## Example

      def on_response(request, response) do
        if Response.is_error?(response) do
          # Log error responses
          Decision.allow()
          |> Decision.with_tag("error-response")
        else
          Decision.allow()
        end
      end
  """

  alias ZentinelAgentSdk.Protocol.ResponseHeadersEvent

  @type t :: %__MODULE__{
          event: ResponseHeadersEvent.t(),
          body: binary()
        }

  defstruct [:event, :body]

  @doc """
  Create a new Response from a ResponseHeadersEvent.
  """
  @spec new(ResponseHeadersEvent.t(), binary()) :: t()
  def new(%ResponseHeadersEvent{} = event, body \\ <<>>) do
    %__MODULE__{
      event: event,
      body: body
    }
  end

  @doc """
  Get the correlation ID for request tracing.
  """
  @spec correlation_id(t()) :: String.t()
  def correlation_id(%__MODULE__{event: event}), do: event.correlation_id

  @doc """
  Get the HTTP status code.
  """
  @spec status_code(t()) :: integer()
  def status_code(%__MODULE__{event: event}), do: event.status

  @doc "Check if the status code indicates success (2xx)."
  @spec is_success?(t()) :: boolean()
  def is_success?(%__MODULE__{event: event}), do: event.status >= 200 and event.status < 300

  @doc "Check if the status code indicates redirect (3xx)."
  @spec is_redirect?(t()) :: boolean()
  def is_redirect?(%__MODULE__{event: event}), do: event.status >= 300 and event.status < 400

  @doc "Check if the status code indicates client error (4xx)."
  @spec is_client_error?(t()) :: boolean()
  def is_client_error?(%__MODULE__{event: event}), do: event.status >= 400 and event.status < 500

  @doc "Check if the status code indicates server error (5xx)."
  @spec is_server_error?(t()) :: boolean()
  def is_server_error?(%__MODULE__{event: event}), do: event.status >= 500 and event.status < 600

  @doc "Check if the status code indicates any error (4xx or 5xx)."
  @spec is_error?(t()) :: boolean()
  def is_error?(%__MODULE__{event: event}), do: event.status >= 400

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

  @doc "Get the Content-Type header value."
  @spec content_type(t()) :: String.t() | nil
  def content_type(%__MODULE__{} = response), do: header(response, "content-type")

  @doc "Get the Location header value (for redirects)."
  @spec location(t()) :: String.t() | nil
  def location(%__MODULE__{} = response), do: header(response, "location")

  @doc "Get the Content-Length header value as an integer."
  @spec content_length(t()) :: integer() | nil
  def content_length(%__MODULE__{} = response) do
    case header(response, "content-length") do
      nil -> nil
      value -> String.to_integer(value)
    end
  rescue
    ArgumentError -> nil
  end

  @doc "Check if the content type indicates JSON."
  @spec is_json?(t()) :: boolean()
  def is_json?(%__MODULE__{} = response) do
    case content_type(response) do
      nil -> false
      ct -> String.contains?(String.downcase(ct), "application/json")
    end
  end

  @doc "Check if the content type indicates HTML."
  @spec is_html?(t()) :: boolean()
  def is_html?(%__MODULE__{} = response) do
    case content_type(response) do
      nil -> false
      ct -> String.contains?(String.downcase(ct), "text/html")
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
  Create a new Response with the given body.
  """
  @spec with_body(t(), binary()) :: t()
  def with_body(%__MODULE__{event: event}, body) do
    new(event, body)
  end

  defimpl Inspect do
    def inspect(%ZentinelAgentSdk.Response{event: event}, _opts) do
      "#Response<#{event.status}>"
    end
  end
end
