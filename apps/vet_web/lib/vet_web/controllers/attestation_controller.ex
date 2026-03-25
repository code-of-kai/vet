defmodule VetWeb.AttestationController do
  use VetWeb, :controller

  def create(conn, %{"package" => package, "version" => version} = params) do
    # TODO: Wire up to VetService.AttestationService
    attestation = %{
      id: Base.encode16(:crypto.strong_rand_bytes(8), case: :lower),
      package: package,
      version: version,
      attester: Map.get(params, "attester", "anonymous"),
      decision: Map.get(params, "decision", "approved"),
      reason: Map.get(params, "reason", ""),
      created_at: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    conn
    |> put_status(:created)
    |> render(:show, attestation: attestation)
  end

  def show(conn, %{"package" => package, "version" => version}) do
    # TODO: Wire up to VetService.AttestationService
    summary = %{
      package: package,
      version: version,
      total_attestations: 2,
      approved: 1,
      rejected: 1,
      attestations: [
        %{attester: "alice@example.com", decision: "approved", reason: "Reviewed source code", created_at: "2026-03-24T14:00:00Z"},
        %{attester: "bob@example.com", decision: "rejected", reason: "Suspicious network calls", created_at: "2026-03-25T08:00:00Z"}
      ]
    }

    render(conn, :show, attestation: summary)
  end
end
