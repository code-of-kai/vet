defmodule VetService.Events.PackageVersionPublished do
  @moduledoc "Emitted when a new package version is published on Hex."

  @derive Jason.Encoder
  defstruct [:package_name, :version, :published_at, :hex_metadata]
end
