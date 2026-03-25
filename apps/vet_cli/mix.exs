defmodule VetCli.MixProject do
  use Mix.Project

  def project do
    [
      app: :vet_cli,
      version: "0.1.0",
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
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:vet_core, in_umbrella: true},
      {:vet_reporter, in_umbrella: true}
    ]
  end
end
