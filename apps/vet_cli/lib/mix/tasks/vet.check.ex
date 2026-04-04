defmodule Mix.Tasks.Vet.Check do
  @moduledoc """
  Pre-install dependency check. Run BEFORE `mix deps.get` to verify
  that declared dependencies exist on hex.pm and aren't typosquats
  or slopsquatting targets.

  Reads mix.exs directly — does not require mix.lock or fetched deps.

  ## Usage

      mix vet.check [--path PATH]

  ## Options

    * `--path`, `-p` — Path to the project root (default: current project)
  """
  @shortdoc "Pre-install check: verify dependencies before mix deps.get"

  use Mix.Task

  @impl Mix.Task
  def run(args) do
    Application.ensure_all_started(:vet_core)

    {opts, rest, _} =
      OptionParser.parse(args,
        strict: [path: :string],
        aliases: [p: :path]
      )

    path = opts[:path] || List.first(rest) || Mix.Project.config()[:root] || File.cwd!()

    Mix.shell().info("Checking dependencies in #{path}/mix.exs...")

    case VetCore.PreInstallCheck.check_deps(path) do
      {:ok, []} ->
        Mix.shell().info("All dependencies look clean.")

      {:ok, results} ->
        has_critical? =
          Enum.reduce(results, false, fn result, critical? ->
            print_result(result)
            critical? or result.phantom?
          end)

        if has_critical? do
          Mix.raise(
            "Vet: one or more dependencies do not exist on hex.pm. " <>
              "Verify package names before running mix deps.get."
          )
        end

      {:error, reason} ->
        Mix.raise("Vet pre-install check failed: #{reason}")
    end
  end

  defp print_result(result) do
    name = result.package
    severity = if result.phantom?, do: "CRITICAL", else: "WARNING"
    color = if result.phantom?, do: :red, else: :yellow

    Mix.shell().info([
      color,
      "\n[#{severity}] :#{name}",
      :reset
    ])

    Mix.shell().info("  #{result.assessment}")

    if result.metadata do
      Mix.shell().info("  Downloads: #{result.metadata.downloads || "unknown"}")
      Mix.shell().info("  Owners: #{result.metadata.owner_count || "unknown"}")
    end

    for warning <- result.typosquat_warnings do
      Mix.shell().info([:yellow, "  Typosquat: #{warning}", :reset])
    end
  end
end
