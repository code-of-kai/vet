defmodule VetWeb.PackageController do
  use VetWeb, :controller

  def show(conn, %{"name" => name}) do
    # TODO: Wire up to VetCore.RiskEngine
    package = %{
      name: name,
      latest_version: "2.1.0",
      risk_score: 0.35,
      risk_level: "medium",
      ecosystem: "hex",
      findings: [
        %{type: "maintainer_change", severity: "medium", detail: "Primary maintainer changed in last 30 days"},
        %{type: "typosquat_candidate", severity: "low", detail: "Name similar to popular package"}
      ],
      last_scanned_at: "2026-03-25T09:00:00Z"
    }

    render(conn, :show, package: package)
  end

  def history(conn, %{"name" => name}) do
    # TODO: Wire up to VetService.RiskHistory
    history = %{
      name: name,
      entries: [
        %{version: "2.1.0", risk_score: 0.35, scanned_at: "2026-03-25T09:00:00Z"},
        %{version: "2.0.0", risk_score: 0.20, scanned_at: "2026-03-15T09:00:00Z"},
        %{version: "1.9.0", risk_score: 0.15, scanned_at: "2026-03-01T09:00:00Z"}
      ]
    }

    render(conn, :history, history: history)
  end
end
