defmodule Mix.Tasks.Vet do
  @moduledoc "Scan project dependencies for supply chain attack indicators"
  @shortdoc "Scan dependencies for security issues"

  use Mix.Task

  @impl Mix.Task
  def run(args) do
    Application.ensure_all_started(:vet_core)

    {opts, rest, _} =
      OptionParser.parse(args,
        strict: [
          path: :string,
          format: :string,
          threshold: :integer,
          skip_hex: :boolean,
          verbose: :boolean,
          ai: :boolean
        ],
        aliases: [
          p: :path,
          f: :format,
          t: :threshold,
          v: :verbose
        ]
      )

    path = opts[:path] || List.first(rest) || Mix.Project.config()[:root] || File.cwd!()

    format =
      case opts[:format] do
        "json" -> :json
        "diagnostics" -> :diagnostics
        _ -> :terminal
      end

    threshold = opts[:threshold] || 50
    scan_opts = [skip_hex: opts[:skip_hex] || false]

    case VetCore.scan(path, scan_opts) do
      {:ok, report} ->
        VetReporter.report(report, format)

        if opts[:ai] do
          run_ai_review(report, threshold)
        end

        max_score =
          report.dependency_reports
          |> Enum.map(& &1.risk_score)
          |> Enum.max(fn -> 0 end)

        if max_score >= threshold do
          Mix.raise("Vet: dependency risk score #{max_score} exceeds threshold #{threshold}")
        end

      {:error, reason} ->
        Mix.raise("Vet scan failed: #{inspect(reason)}")
    end
  end

  defp run_ai_review(report, threshold) do
    IO.puts("")
    IO.puts(IO.ANSI.bright() <> "Running AI deep review on flagged dependencies..." <> IO.ANSI.reset())

    case VetCore.LLMReview.review_flagged(report, threshold: threshold) do
      {:ok, results} ->
        Enum.each(results, fn
          {dep_name, {:ok, result}} ->
            IO.puts("")
            IO.puts(IO.ANSI.bright() <> "AI Review: #{dep_name}" <> IO.ANSI.reset())
            IO.puts(String.duplicate("-", 40))
            IO.puts(result.ai_analysis)
            IO.puts("")

          {dep_name, {:error, :missing_api_key}} ->
            IO.puts(IO.ANSI.yellow() <> "Skipped AI review for #{dep_name}: set ANTHROPIC_API_KEY" <> IO.ANSI.reset())

          {dep_name, {:error, reason}} ->
            IO.puts(IO.ANSI.yellow() <> "AI review failed for #{dep_name}: #{inspect(reason)}" <> IO.ANSI.reset())
        end)

      {:error, reason} ->
        IO.puts(IO.ANSI.yellow() <> "AI review failed: #{inspect(reason)}" <> IO.ANSI.reset())
    end
  end
end
