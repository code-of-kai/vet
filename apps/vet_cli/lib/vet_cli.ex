defmodule VetCli do
  @moduledoc false

  def main(args) do
    {opts, rest, _} =
      OptionParser.parse(args,
        strict: [
          path: :string,
          format: :string,
          threshold: :integer,
          skip_hex: :boolean,
          verbose: :boolean,
          help: :boolean,
          ai: :boolean
        ],
        aliases: [
          p: :path,
          f: :format,
          t: :threshold,
          v: :verbose,
          h: :help
        ]
      )

    if opts[:help] do
      print_help()
    else
      path = opts[:path] || List.first(rest) || File.cwd!()
      format = parse_format(opts[:format])
      threshold = opts[:threshold] || 50
      scan_opts = [skip_hex: opts[:skip_hex] || false]

      case VetCore.scan(path, scan_opts) do
        {:ok, report} ->
          VetReporter.report(report, format)

          if opts[:ai] do
            run_ai_review(report, threshold)
          end

          exit_with_threshold(report, threshold)

        {:error, reason} ->
          IO.puts(IO.ANSI.red() <> "Error: #{inspect(reason)}" <> IO.ANSI.reset())
          System.halt(1)
      end
    end
  end

  defp parse_format(nil), do: :terminal
  defp parse_format("json"), do: :json
  defp parse_format("terminal"), do: :terminal
  defp parse_format("diagnostics"), do: :diagnostics
  defp parse_format(_), do: :terminal

  defp exit_with_threshold(report, threshold) do
    max_score =
      report.dependency_reports
      |> Enum.map(& &1.risk_score)
      |> Enum.max(fn -> 0 end)

    if max_score >= threshold do
      System.halt(1)
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

  defp print_help do
    IO.puts("""
    vet — Elixir dependency security scanner

    Usage:
      vet [path]              Scan project at path (default: current directory)
      vet --help              Show this help

    Options:
      -p, --path PATH         Project path to scan
      -f, --format FORMAT     Output format: terminal, json, diagnostics (default: terminal)
      -t, --threshold N       Exit with code 1 if any dep scores >= N (default: 50)
      --skip-hex              Skip hex.pm metadata checks
      -v, --verbose           Show full AST context for findings
      --ai                    Run AI deep review on flagged dependencies
      -h, --help              Show this help
    """)
  end
end
