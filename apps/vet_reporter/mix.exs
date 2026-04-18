defmodule VetReporter.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/code-of-kai/vet"

  def project do
    [
      app: :vet_reporter,
      version: @version,
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      source_url: @source_url
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:vet_core, vet_core_dep()}
    ]
  end

  defp vet_core_dep do
    if System.get_env("HEX_PUBLISH"), do: "~> 0.1.0", else: [in_umbrella: true]
  end

  defp description do
    "Output formatting (terminal, JSON, diagnostics) for Vet dependency security scans."
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib mix.exs README.md LICENSE)
    ]
  end
end
