defmodule VetCore.MixProject do
  use Mix.Project

  def project do
    [
      app: :vet_core,
      version: "0.1.0",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :inets, :ssl],
      mod: {VetCore.Application, []}
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.4"}
    ]
  end
end
