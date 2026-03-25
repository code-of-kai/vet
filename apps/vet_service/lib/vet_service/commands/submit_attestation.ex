defmodule VetService.Commands.SubmitAttestation do
  @moduledoc "Command to submit a community attestation for scan findings."

  defstruct [:package_name, :version, :attestation_id, :findings_hash, :submitter_id, :submitted_at]
end
