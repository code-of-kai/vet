defmodule VetWeb.PackageLive do
  use VetWeb, :live_view

  @impl true
  def mount(%{"name" => name}, _session, socket) do
    # TODO: Wire up to VetCore.RiskEngine
    package = %{
      name: name,
      latest_version: "2.1.0",
      ecosystem: "hex",
      risk_score: 0.35,
      risk_level: "medium",
      description: "A popular utility library for #{name}.",
      maintainers: ["maintainer@example.com"],
      license: "MIT",
      last_scanned_at: "2026-03-25T09:00:00Z"
    }

    findings = [
      %{type: "maintainer_change", severity: "medium", detail: "Primary maintainer changed in last 30 days", found_at: "2026-03-25T09:00:00Z"},
      %{type: "typosquat_candidate", severity: "low", detail: "Name similar to popular package 'jason'", found_at: "2026-03-24T12:00:00Z"},
      %{type: "no_source_repo", severity: "medium", detail: "Package does not link to a source repository", found_at: "2026-03-20T08:00:00Z"}
    ]

    versions = [
      %{version: "2.1.0", risk_score: 0.35, published_at: "2026-03-20"},
      %{version: "2.0.0", risk_score: 0.20, published_at: "2026-02-15"},
      %{version: "1.9.0", risk_score: 0.15, published_at: "2026-01-10"},
      %{version: "1.8.0", risk_score: 0.10, published_at: "2025-12-01"}
    ]

    socket =
      socket
      |> assign(:page_title, "Package: #{name}")
      |> assign(:package, package)
      |> assign(:findings, findings)
      |> assign(:versions, versions)

    {:ok, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div style="margin-bottom: 1.5rem;">
      <a href="/" style="color: #666; text-decoration: none;">&larr; Back to Dashboard</a>
    </div>

    <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1.5rem;">
      <h1 style="margin-bottom: 0;">{@package.name}</h1>
      <span class={"badge badge-#{@package.risk_level}"}>{@package.risk_level}</span>
      <span style="color: #666; font-family: monospace;">v{@package.latest_version}</span>
    </div>

    <div class="stats" style="margin-bottom: 1.5rem;">
      <div class="stat-card">
        <div class="stat-value">{Float.round(@package.risk_score * 100, 1)}%</div>
        <div class="stat-label">Risk Score</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{length(@findings)}</div>
        <div class="stat-label">Active Findings</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{length(@versions)}</div>
        <div class="stat-label">Versions Tracked</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="font-size: 1rem;">{@package.ecosystem}</div>
        <div class="stat-label">Ecosystem</div>
      </div>
    </div>

    <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 1.5rem;">
      <div>
        <div class="card">
          <h2>Findings</h2>
          <table>
            <thead>
              <tr>
                <th>Type</th>
                <th>Severity</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={finding <- @findings}>
                <td style="font-family: monospace; font-size: 0.85rem;">{finding.type}</td>
                <td><span class={"badge badge-#{finding.severity}"}>{finding.severity}</span></td>
                <td>{finding.detail}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div>
        <div class="card">
          <h2>Version History</h2>
          <table>
            <thead>
              <tr>
                <th>Version</th>
                <th>Risk</th>
                <th>Published</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={v <- @versions}>
                <td style="font-family: monospace;">{v.version}</td>
                <td>{Float.round(v.risk_score * 100, 0)}%</td>
                <td style="color: #666; font-size: 0.85rem;">{v.published_at}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="card">
          <h2>Package Info</h2>
          <div style="font-size: 0.9rem;">
            <p style="margin-bottom: 0.5rem;"><strong>Description:</strong> {@package.description}</p>
            <p style="margin-bottom: 0.5rem;"><strong>License:</strong> {@package.license}</p>
            <p style="margin-bottom: 0.5rem;"><strong>Maintainers:</strong> {Enum.join(@package.maintainers, ", ")}</p>
            <p><strong>Last Scanned:</strong> {@package.last_scanned_at}</p>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
