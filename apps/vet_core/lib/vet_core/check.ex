defmodule VetCore.Check do
  @moduledoc false

  @callback run(
              dependency :: VetCore.Types.Dependency.t(),
              project_path :: String.t(),
              state :: term()
            ) :: [VetCore.Types.Finding.t()]

  defmacro __using__(_opts) do
    quote do
      @behaviour VetCore.Check
    end
  end
end
