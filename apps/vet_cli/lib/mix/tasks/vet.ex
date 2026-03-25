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
          VetCli.run_ai_review(report, threshold)
        end

        # Optionally record scan results to vet_service if available
        if Code.ensure_loaded?(VetService) do
          for dep_report <- report.dependency_reports do
            VetService.record_scan(
              to_string(dep_report.dependency.name),
              dep_report.dependency.version,
              %{risk_score: dep_report.risk_score, findings_count: length(dep_report.findings)}
            )
          end
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

end
