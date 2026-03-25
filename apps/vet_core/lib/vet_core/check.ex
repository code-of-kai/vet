defmodule VetCore.Check do
  @moduledoc false

  @callback init(opts :: keyword()) :: term()
  @callback run(
              dependency :: VetCore.Types.Dependency.t(),
              project_path :: String.t(),
              state :: term()
            ) :: [VetCore.Types.Finding.t()]
end
