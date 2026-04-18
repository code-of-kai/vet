defmodule VetCli.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/code-of-kai/vet"

  def project do
    [
      app: :vet_cli,
      version: @version,
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      escript: [
        main_module: VetCli,
        name: "vet",
        embed_elixir: true
      ],
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
      {:vet_core, vet_core_dep()},
      {:vet_reporter, vet_reporter_dep()}
    ]
  end

  defp vet_core_dep do
    if System.get_env("HEX_PUBLISH"), do: "~> 0.1.0", else: [in_umbrella: true]
  end

  defp vet_reporter_dep do
    if System.get_env("HEX_PUBLISH"), do: "~> 0.1.0", else: [in_umbrella: true]
  end

  defp description do
    "Mix tasks (mix vet, mix vet.check) for the Vet dependency security scanner."
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib mix.exs README.md LICENSE)
    ]
  end
end
