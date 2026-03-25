defmodule VetWeb.ScanController do
  use VetWeb, :controller

  action_fallback VetWeb.FallbackController

  def create(conn, %{"project_path" => project_path}) do
    # TODO: Wire up to VetService.Scanner
    scan_id = Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

    scan = %{
      id: scan_id,
      project_path: project_path,
      status: "queued",
      started_at: DateTime.utc_now() |> DateTime.to_iso8601(),
      findings_count: 0
    }

    conn
    |> put_status(:created)
    |> render(:show, scan: scan)
  end

  def show(conn, %{"id" => id}) do
    # TODO: Wire up to VetService scan results
    scan = %{
      id: id,
      project_path: "/example/project",
      status: "completed",
      started_at: "2026-03-25T10:00:00Z",
      completed_at: "2026-03-25T10:01:30Z",
      findings_count: 3,
      findings: [
        %{package: "left-pad", version: "1.0.0", risk: "high", reason: "Deprecated maintainer"},
        %{package: "event-stream", version: "3.3.6", risk: "critical", reason: "Known malicious version"},
        %{package: "colors", version: "1.4.1", risk: "medium", reason: "Protestware incident"}
      ]
    }

    render(conn, :show, scan: scan)
  end
end
