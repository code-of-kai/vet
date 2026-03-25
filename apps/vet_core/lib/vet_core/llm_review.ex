defmodule VetCore.LLMReview do
  @moduledoc """
  Integrates LLM analysis for deep code review of flagged dependencies.

  Uses the Anthropic API to provide AI-powered security assessment
  beyond what deterministic scanning can catch.
  """

  alias VetCore.Types.{DependencyReport, ScanReport, Finding}
  alias VetCore.Checks.FileHelper

  @default_model "claude-sonnet-4-20250514"
  @api_url "https://api.anthropic.com/v1/messages"

  @type review_result :: %{
          ai_analysis: String.t(),
          model: String.t(),
          reviewed_at: DateTime.t()
        }

  @doc """
  Reviews a single dependency report using LLM analysis.

  ## Options

    * `:api_key` - Anthropic API key (required, or set ANTHROPIC_API_KEY env var)
    * `:model` - Model to use (default: #{@default_model})
    * `:max_tokens` - Max response tokens (default: 4096)
    * `:project_path` - Path to project root (needed to read source files)

  """
  @spec review(DependencyReport.t(), keyword()) :: {:ok, review_result()} | {:error, term()}
  def review(%DependencyReport{} = dep_report, opts \\ []) do
    api_key = opts[:api_key] || System.get_env("ANTHROPIC_API_KEY")

    if is_nil(api_key) or api_key == "" do
      {:error, :missing_api_key}
    else
      model = opts[:model] || @default_model
      max_tokens = opts[:max_tokens] || 4096
      project_path = opts[:project_path]

      prompt = format_prompt(dep_report, project_path)

      case call_api(api_key, model, prompt, max_tokens) do
        {:ok, response_text} ->
          {:ok,
           %{
             ai_analysis: response_text,
             model: model,
             reviewed_at: DateTime.utc_now()
           }}

        {:error, _} = err ->
          err
      end
    end
  end

  @doc """
  Reviews only dependencies in the scan report that have a risk score above
  the given threshold.

  ## Options

  Same as `review/2`, plus:

    * `:threshold` - Minimum risk score to trigger review (default: 50)

  """
  @spec review_flagged(ScanReport.t(), keyword()) ::
          {:ok, [{atom(), review_result()}]} | {:error, term()}
  def review_flagged(%ScanReport{} = scan_report, opts \\ []) do
    threshold = opts[:threshold] || 50

    flagged =
      scan_report.dependency_reports
      |> Enum.filter(fn dr -> dr.risk_score >= threshold end)

    results =
      Enum.map(flagged, fn dr ->
        case review(dr, Keyword.put(opts, :project_path, scan_report.project_path)) do
          {:ok, result} -> {dr.dependency.name, {:ok, result}}
          {:error, reason} -> {dr.dependency.name, {:error, reason}}
        end
      end)

    {:ok, results}
  end

  @doc """
  Builds a well-structured prompt for LLM security review.

  Public for testing.
  """
  @spec format_prompt(DependencyReport.t(), String.t() | nil) :: String.t()
  def format_prompt(%DependencyReport{} = dep_report, project_path \\ nil) do
    dep = dep_report.dependency
    findings = dep_report.findings

    source_snippets = build_source_snippets(dep, findings, project_path)

    """
    You are a security researcher reviewing an Elixir dependency for supply chain attack indicators.

    Package: #{dep.name} v#{dep.version || "unknown"}
    Source: #{format_source(dep.source)}

    Deterministic scan findings:
    #{format_findings(findings)}

    Source code of flagged files:
    #{source_snippets}

    Questions:
    1. Are any of these findings likely false positives? Why?
    2. Are there additional security concerns not caught by the deterministic scan?
    3. What is your overall risk assessment (low/medium/high/critical)?
    4. Recommended actions?
    """
  end

  # -- Private: API ------------------------------------------------------------

  defp call_api(api_key, _model, prompt, _max_tokens) do
    case Req.post(
           @api_url,
           headers: [
             {"x-api-key", api_key},
             {"anthropic-version", "2023-06-01"},
             {"content-type", "application/json"}
           ],
           json: %{
             model: "claude-sonnet-4-20250514",
             max_tokens: 2048,
             messages: [%{role: "user", content: prompt}]
           }
         ) do
      {:ok, %{status: 200, body: body}} ->
        parse_response(body)

      {:ok, %{status: 429}} ->
        {:error, :rate_limited}

      {:ok, %{status: status, body: body}} ->
        {:error, "API error #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "Request failed: #{inspect(reason)}"}
    end
  end

  defp parse_response(%{"content" => [%{"text" => text} | _]}), do: {:ok, text}
  defp parse_response(%{"error" => %{"message" => msg}}), do: {:error, {:api_error, msg}}
  defp parse_response(other), do: {:error, {:unexpected_response, other}}

  # -- Private: Prompt building ------------------------------------------------

  defp format_source(:hex), do: "hex.pm"
  defp format_source({:git, url}), do: "git: #{url}"
  defp format_source({:path, path}), do: "path: #{path}"
  defp format_source(nil), do: "unknown"
  defp format_source(other), do: inspect(other)

  defp format_findings([]), do: "  (none)"

  defp format_findings(findings) do
    findings
    |> Enum.with_index(1)
    |> Enum.map_join("\n", fn {%Finding{} = f, idx} ->
      ct = if f.compile_time?, do: " [COMPILE-TIME]", else: ""
      "  #{idx}. [#{f.severity}#{ct}] #{f.description}\n     File: #{shorten_path(f.file_path)}:#{f.line}"
    end)
  end

  defp build_source_snippets(_dep, _findings, nil), do: "  (source not available)"

  defp build_source_snippets(dep, findings, project_path) do
    flagged_files =
      findings
      |> Enum.map(& &1.file_path)
      |> Enum.uniq()

    if flagged_files == [] do
      "  (no flagged files)"
    else
      parsed_files = FileHelper.read_and_parse(dep.name, project_path)

      parsed_files
      |> Enum.filter(fn {path, _source, _ast} -> path in flagged_files end)
      |> Enum.map_join("\n\n", fn {path, source, _ast} ->
        truncated =
          source
          |> String.split("\n")
          |> Enum.take(200)
          |> Enum.join("\n")

        "--- #{shorten_path(path)} ---\n#{truncated}"
      end)
      |> case do
        "" -> "  (flagged files not readable)"
        content -> content
      end
    end
  end

  defp shorten_path(path) do
    case String.split(path, "/deps/") do
      [_, rest] -> "deps/" <> rest
      _ -> path
    end
  end
end
