defmodule VetWeb.SearchLive do
  use VetWeb, :live_view

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:page_title, "Search Packages")
      |> assign(:query, "")
      |> assign(:results, [])
      |> assign(:searched, false)

    {:ok, socket}
  end

  @impl true
  def handle_event("search", %{"query" => query}, socket) do
    results =
      if String.trim(query) == "" do
        []
      else
        # TODO: Wire up to VetCore.PackageRegistry search
        search_placeholder_data(query)
      end

    socket =
      socket
      |> assign(:query, query)
      |> assign(:results, results)
      |> assign(:searched, true)

    {:noreply, socket}
  end

  defp search_placeholder_data(query) do
    all_packages = [
      %{name: "jason", version: "1.4.4", ecosystem: "hex", risk_score: 0.05, risk_level: "low"},
      %{name: "phoenix", version: "1.7.18", ecosystem: "hex", risk_score: 0.02, risk_level: "low"},
      %{name: "plug", version: "1.16.1", ecosystem: "hex", risk_score: 0.03, risk_level: "low"},
      %{name: "ecto", version: "3.12.5", ecosystem: "hex", risk_score: 0.04, risk_level: "low"},
      %{name: "event-stream", version: "3.3.6", ecosystem: "npm", risk_score: 0.95, risk_level: "critical"},
      %{name: "colors", version: "1.4.1", ecosystem: "npm", risk_score: 0.68, risk_level: "high"},
      %{name: "ua-parser-js", version: "0.7.29", ecosystem: "npm", risk_score: 0.82, risk_level: "high"},
      %{name: "left-pad", version: "1.0.0", ecosystem: "npm", risk_score: 0.40, risk_level: "medium"},
      %{name: "node-ipc", version: "10.1.0", ecosystem: "npm", risk_score: 0.55, risk_level: "medium"},
      %{name: "lodash", version: "4.17.21", ecosystem: "npm", risk_score: 0.08, risk_level: "low"}
    ]

    downcased = String.downcase(query)

    Enum.filter(all_packages, fn pkg ->
      String.contains?(String.downcase(pkg.name), downcased) ||
        String.contains?(String.downcase(pkg.ecosystem), downcased)
    end)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <h1>Search Packages</h1>

    <div class="card" style="margin-bottom: 1.5rem;">
      <form phx-submit="search">
        <div style="display: flex; gap: 0.75rem; align-items: center;">
          <input
            type="search"
            name="query"
            value={@query}
            placeholder="Search packages by name or ecosystem..."
            style="flex: 1; max-width: none;"
            autofocus
          />
          <button type="submit" class="btn btn-primary">Search</button>
        </div>
      </form>
    </div>

    <div :if={@searched && @results == []} class="card" style="text-align: center; color: #666;">
      <p>No packages found matching "<strong>{@query}</strong>"</p>
    </div>

    <div :if={@results != []}>
      <p style="color: #666; margin-bottom: 0.75rem;">
        Found {length(@results)} package(s) matching "<strong>{@query}</strong>"
      </p>

      <div class="card">
        <table>
          <thead>
            <tr>
              <th>Package</th>
              <th>Version</th>
              <th>Ecosystem</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={pkg <- @results}>
              <td>
                <a href={"/packages/#{pkg.name}"} style="color: #1a1a2e; font-weight: 500;">
                  {pkg.name}
                </a>
              </td>
              <td style="font-family: monospace; font-size: 0.85rem;">{pkg.version}</td>
              <td>{pkg.ecosystem}</td>
              <td>
                <span class={"badge badge-#{pkg.risk_level}"}>
                  {pkg.risk_level} ({Float.round(pkg.risk_score * 100, 0)}%)
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div :if={!@searched} class="card" style="text-align: center; color: #666;">
      <p>Enter a package name or ecosystem to search.</p>
    </div>
    """
  end
end
