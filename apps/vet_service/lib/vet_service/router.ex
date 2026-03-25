defmodule VetService.Router do
  @moduledoc "Commanded router — maps commands to aggregates."

  use Commanded.Commands.Router

  alias VetService.Aggregates.PackageVersion
  alias VetService.Commands.{ScanPackage, SubmitAttestation, SuppressFinding}

  identify(PackageVersion, by: :package_name)

  dispatch(ScanPackage, to: PackageVersion)
  dispatch(SubmitAttestation, to: PackageVersion)
  dispatch(SuppressFinding, to: PackageVersion)
end
