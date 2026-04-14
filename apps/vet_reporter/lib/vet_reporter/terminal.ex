defmodule VetReporter.Terminal do
  @moduledoc false

  alias VetCore.Types.{ScanReport, DependencyReport, Finding}

  def render(%ScanReport{} = report) do
    IO.puts("")
    render_header(report)
    render_dependency_reports(report.dependency_reports)
    render_allowlist_notes(report.allowlist_notes)
    render_summary(report.summary)
    IO.puts("")
  end

  defp render_header(report) do
    IO.puts(
      IO.ANSI.bright() <>
        "Vet — Dependency Security Scan" <>
        IO.ANSI.reset()
    )

    IO.puts("Project: #{report.project_path}")
    IO.puts("Time:    #{DateTime.to_string(report.timestamp)}")
    IO.puts(String.duplicate("─", 60))
  end

  defp render_dependency_reports(reports) do
    reports
    |> Enum.sort_by(& &1.risk_score, :desc)
    |> Enum.each(&render_dep_report/1)
  end

  defp render_dep_report(%DependencyReport{findings: []} = report) do
    IO.puts("")

    IO.puts(
      "  #{risk_badge(report.risk_level)} #{IO.ANSI.bright()}#{report.dependency.name}#{IO.ANSI.reset()} #{report.dependency.version || "?"}#{depth_tag(report.dependency)} — score: #{report.risk_score}"
    )
  end

  defp render_dep_report(%DependencyReport{} = report) do
    IO.puts("")

    IO.puts(
      "  #{risk_badge(report.risk_level)} #{IO.ANSI.bright()}#{report.dependency.name}#{IO.ANSI.reset()} #{report.dependency.version || "?"}#{depth_tag(report.dependency)} — score: #{report.risk_score}"
    )

    Enum.each(report.findings, &render_finding/1)
  end

  defp depth_tag(%{direct?: true}), do: ""
  defp depth_tag(%{depth: d}) when d > 1, do: " #{IO.ANSI.faint()}(transitive, depth: #{d})#{IO.ANSI.reset()}"
  defp depth_tag(_), do: ""

  defp render_finding(%Finding{category: :temporal_anomaly} = f) do
    severity_color = severity_color(f.severity)

    IO.puts(
      "    #{severity_color}#{String.upcase(to_string(f.severity))}#{IO.ANSI.reset()} " <>
        "#{IO.ANSI.magenta()}[TEMPORAL]#{IO.ANSI.reset()} #{f.description}"
    )
  end

  defp render_finding(%Finding{category: :version_transition} = f) do
    severity_color = severity_color(f.severity)

    IO.puts(
      "    #{severity_color}#{String.upcase(to_string(f.severity))}#{IO.ANSI.reset()} " <>
        "#{IO.ANSI.cyan()}[VERSION DIFF]#{IO.ANSI.reset()} #{f.description}"
    )
  end

  defp render_finding(%Finding{} = f) do
    compile_tag = if f.compile_time?, do: " #{IO.ANSI.red()}[COMPILE-TIME]#{IO.ANSI.reset()}", else: ""
    severity_color = severity_color(f.severity)
    short_path = shorten_path(f.file_path)

    IO.puts(
      "    #{severity_color}#{String.upcase(to_string(f.severity))}#{IO.ANSI.reset()}#{compile_tag} #{f.description}"
    )

    IO.puts("      #{IO.ANSI.faint()}#{short_path}:#{f.line}#{IO.ANSI.reset()}")

    if f.snippet do
      IO.puts("      #{IO.ANSI.faint()}#{String.trim(f.snippet)}#{IO.ANSI.reset()}")
    end
  end

  defp render_allowlist_notes([]), do: :ok
  defp render_allowlist_notes(nil), do: :ok

  defp render_allowlist_notes(notes) do
    IO.puts("")
    IO.puts(String.duplicate("─", 60))
    IO.puts(IO.ANSI.bright() <> "Allowlist transparency" <> IO.ANSI.reset())
    IO.puts(IO.ANSI.faint() <> "  Findings in transitive deps of allowlisted packages:" <> IO.ANSI.reset())

    notes
    |> Enum.group_by(& &1.package)
    |> Enum.each(fn {package, entries} ->
      IO.puts("")
      IO.puts("  #{IO.ANSI.bright()}:#{package}#{IO.ANSI.reset()} is allowlisted, but:")

      Enum.each(entries, fn entry ->
        cats = entry.categories |> Enum.map(&to_string/1) |> Enum.join(", ")

        IO.puts(
          "    #{IO.ANSI.yellow()}→#{IO.ANSI.reset()} :#{entry.transitive_dep} has #{entry.finding_count} finding(s) (#{cats})"
        )
      end)
    end)
  end

  defp render_summary(nil), do: :ok

  defp render_summary(summary) do
    IO.puts("")
    IO.puts(String.duplicate("─", 60))
    IO.puts(IO.ANSI.bright() <> "Summary" <> IO.ANSI.reset())
    IO.puts("  Dependencies scanned: #{summary[:total_deps] || 0}")
    IO.puts("  Total findings:       #{summary[:total_findings] || 0}")

    if summary[:deps_by_risk] do
      IO.puts("")

      for {level, count} <- summary[:deps_by_risk], count > 0 do
        IO.puts("  #{risk_badge(level)} #{count} #{level}")
      end
    end
  end

  defp risk_badge(:critical), do: IO.ANSI.red_background() <> IO.ANSI.white() <> " CRIT " <> IO.ANSI.reset()
  defp risk_badge(:high), do: IO.ANSI.red() <> "▲ HIGH" <> IO.ANSI.reset()
  defp risk_badge(:medium), do: IO.ANSI.yellow() <> "● MED " <> IO.ANSI.reset()
  defp risk_badge(:low), do: IO.ANSI.green() <> "✓ LOW " <> IO.ANSI.reset()

  defp severity_color(:critical), do: IO.ANSI.red()
  defp severity_color(:warning), do: IO.ANSI.yellow()
  defp severity_color(:info), do: IO.ANSI.faint()

  defp shorten_path(path) do
    case String.split(path, "/deps/") do
      [_, rest] -> "deps/" <> rest
      _ -> path
    end
  end
end
