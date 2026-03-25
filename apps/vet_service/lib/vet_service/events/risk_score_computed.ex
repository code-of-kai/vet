defmodule VetService.Events.RiskScoreComputed do
  @moduledoc "Emitted when a composite risk score is calculated."

  @derive Jason.Encoder
  defstruct [:package_name, :version, :score, :level, :factors]
end
