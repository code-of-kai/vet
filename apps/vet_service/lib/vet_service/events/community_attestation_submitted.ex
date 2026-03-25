defmodule VetService.Events.CommunityAttestationSubmitted do
  @moduledoc "Emitted when a community member submits a findings attestation."

  @derive Jason.Encoder
  defstruct [:package_name, :version, :attestation_id, :findings_hash, :submitter_id, :submitted_at]
end
