defmodule VetWeb.MixProject do
  use Mix.Project

  def project do
    [
      app: :vet_web,
      version: "0.1.0",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.18",
      compilers: Mix.compilers(),
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :runtime_tools],
      mod: {VetWeb.Application, []}
    ]
  end

  defp deps do
    [
      {:vet_core, in_umbrella: true},
      {:vet_service, in_umbrella: true},
      {:vet_reporter, in_umbrella: true},
      {:phoenix, "~> 1.7"},
      {:phoenix_html, "~> 4.1"},
      {:phoenix_live_view, "~> 1.0"},
      {:phoenix_live_dashboard, "~> 0.8"},
      {:phoenix_pubsub, "~> 2.1"},
      {:jason, "~> 1.4"},
      {:plug_cowboy, "~> 2.7"},
      {:telemetry_metrics, "~> 1.0"},
      {:telemetry_poller, "~> 1.1"},
      {:tidewave, "~> 0.5", only: :dev}
    ]
  end
end
