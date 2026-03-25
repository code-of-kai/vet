defmodule VetWeb.DashboardLive do
  use VetWeb, :live_view

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:page_title, "Dashboard")
      |> assign(:stats, %{
        total_scans: 142,
        packages_monitored: 1_287,
        critical_findings: 8,
        attestations_pending: 23
      })
      |> assign(:recent_scans, [
        %{id: "a1b2c3", project: "payments-api", status: "completed", findings: 3, scanned_at: "2 minutes ago"},
        %{id: "d4e5f6", project: "user-service", status: "completed", findings: 0, scanned_at: "15 minutes ago"},
        %{id: "g7h8i9", project: "data-pipeline", status: "running", findings: nil, scanned_at: "just now"},
        %{id: "j0k1l2", project: "web-frontend", status: "completed", findings: 7, scanned_at: "1 hour ago"}
      ])
      |> assign(:risky_packages, [
        %{name: "event-stream", version: "3.3.6", risk_score: 0.95, risk_level: "critical"},
        %{name: "ua-parser-js", version: "0.7.29", risk_score: 0.82, risk_level: "high"},
        %{name: "colors", version: "1.4.1", risk_score: 0.68, risk_level: "high"},
        %{name: "node-ipc", version: "10.1.0", risk_score: 0.55, risk_level: "medium"},
        %{name: "left-pad", version: "1.0.0", risk_score: 0.40, risk_level: "medium"}
      ])

    {:ok, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <h1>Dashboard</h1>

    <div class="stats">
      <div class="stat-card">
        <div class="stat-value">{@stats.total_scans}</div>
        <div class="stat-label">Total Scans</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{@stats.packages_monitored}</div>
        <div class="stat-label">Packages Monitored</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color: #c00;">{@stats.critical_findings}</div>
        <div class="stat-label">Critical Findings</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color: #960;">{@stats.attestations_pending}</div>
        <div class="stat-label">Attestations Pending</div>
      </div>
    </div>

    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;">
      <div class="card">
        <h2>Recent Scans</h2>
        <table>
          <thead>
            <tr>
              <th>Project</th>
              <th>Status</th>
              <th>Findings</th>
              <th>When</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={scan <- @recent_scans}>
              <td>{scan.project}</td>
              <td>
                <span :if={scan.status == "completed"} class="badge badge-low">completed</span>
                <span :if={scan.status == "running"} class="badge badge-medium">running</span>
              </td>
              <td>{scan.findings || "-"}</td>
              <td style="color: #666; font-size: 0.85rem;">{scan.scanned_at}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <h2>Top Risky Packages</h2>
        <table>
          <thead>
            <tr>
              <th>Package</th>
              <th>Version</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={pkg <- @risky_packages}>
              <td><a href={"/packages/#{pkg.name}"} style="color: #1a1a2e;">{pkg.name}</a></td>
              <td style="font-family: monospace; font-size: 0.85rem;">{pkg.version}</td>
              <td>
                <span class={"badge badge-#{pkg.risk_level}"}>{pkg.risk_level} ({Float.round(pkg.risk_score * 100, 0)}%)</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
    """
  end
end
