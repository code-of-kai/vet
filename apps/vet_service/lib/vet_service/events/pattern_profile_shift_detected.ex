defmodule VetService.Events.PatternProfileShiftDetected do
  @moduledoc "Emitted when a package's API/behavior pattern profile shifts between versions."

  @derive Jason.Encoder
  defstruct [:package_name, :from_version, :to_version, :added_categories, :removed_categories, :severity]
end
