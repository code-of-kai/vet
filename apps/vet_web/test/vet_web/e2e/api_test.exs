defmodule VetWeb.E2E.ApiTest do
  use ExUnit.Case, async: true

  describe "ScanJSON rendering" do
    test "renders scan data with required fields" do
      scan = %{
        id: "abc123",
        project_path: "/test/project",
        status: "completed",
        started_at: "2026-03-25T10:00:00Z",
        completed_at: "2026-03-25T10:01:30Z",
        findings_count: 3,
        findings: [
          %{package: "left-pad", version: "1.0.0", risk: "high", reason: "Deprecated"}
        ]
      }

      result = VetWeb.ScanJSON.show(%{scan: scan})

      assert %{data: data} = result
      assert data.id == "abc123"
      assert data.project_path == "/test/project"
      assert data.status == "completed"
      assert data.started_at == "2026-03-25T10:00:00Z"
      assert data.findings_count == 3
      assert data.completed_at == "2026-03-25T10:01:30Z"
      assert is_list(data.findings)
    end

    test "omits nil fields (completed_at, findings)" do
      scan = %{
        id: "queued1",
        project_path: "/test/project",
        status: "queued",
        started_at: "2026-03-25T10:00:00Z",
        findings_count: 0
      }

      result = VetWeb.ScanJSON.show(%{scan: scan})
      data = result.data

      assert data.id == "queued1"
      assert data.status == "queued"
      refute Map.has_key?(data, :completed_at)
      refute Map.has_key?(data, :findings)
    end
  end

  describe "PackageJSON rendering" do
    test "renders package show data" do
      package = %{
        name: "jason",
        latest_version: "1.4.1",
        risk_score: 0.10,
        risk_level: "low",
        ecosystem: "hex",
        findings: [],
        last_scanned_at: "2026-03-25T09:00:00Z"
      }

      result = VetWeb.PackageJSON.show(%{package: package})

      assert %{data: data} = result
      assert data.name == "jason"
      assert data.latest_version == "1.4.1"
      assert data.risk_score == 0.10
      assert data.risk_level == "low"
      assert data.ecosystem == "hex"
      assert data.findings == []
      assert data.last_scanned_at == "2026-03-25T09:00:00Z"
    end

    test "renders package history data" do
      history = %{
        name: "phoenix",
        entries: [
          %{version: "1.7.0", risk_score: 0.20, scanned_at: "2026-03-01T09:00:00Z"},
          %{version: "1.7.1", risk_score: 0.15, scanned_at: "2026-03-15T09:00:00Z"}
        ]
      }

      result = VetWeb.PackageJSON.history(%{history: history})

      assert %{data: data} = result
      assert data.name == "phoenix"
      assert length(data.entries) == 2
    end
  end

  describe "AttestationJSON rendering" do
    test "renders created attestation" do
      attestation = %{
        id: "att123",
        package: "jason",
        version: "1.4.1",
        attester: "alice@example.com",
        decision: "approved",
        reason: "Reviewed source",
        created_at: "2026-03-25T10:00:00Z"
      }

      result = VetWeb.AttestationJSON.show(%{attestation: attestation})

      assert %{data: data} = result
      assert data.package == "jason"
      assert data.version == "1.4.1"
      assert data.id == "att123"
      assert data.attester == "alice@example.com"
      assert data.decision == "approved"
      assert data.reason == "Reviewed source"
      assert data.created_at == "2026-03-25T10:00:00Z"
    end

    test "renders attestation summary with multiple attestations" do
      summary = %{
        package: "jason",
        version: "1.4.1",
        total_attestations: 2,
        approved: 1,
        rejected: 1,
        attestations: [
          %{attester: "alice@example.com", decision: "approved", reason: "OK", created_at: "2026-03-24T14:00:00Z"},
          %{attester: "bob@example.com", decision: "rejected", reason: "Bad", created_at: "2026-03-25T08:00:00Z"}
        ]
      }

      result = VetWeb.AttestationJSON.show(%{attestation: summary})

      assert %{data: data} = result
      assert data.package == "jason"
      assert data.version == "1.4.1"
      assert data.total_attestations == 2
      assert data.approved == 1
      assert data.rejected == 1
      assert length(data.attestations) == 2
    end
  end

  describe "ErrorJSON rendering" do
    test "renders 404 error" do
      result = VetWeb.ErrorJSON.render("404.json", %{})
      assert %{errors: %{detail: detail}} = result
      assert is_binary(detail)
    end

    test "renders 422 error" do
      result = VetWeb.ErrorJSON.render("422.json", %{})
      assert %{errors: %{detail: detail}} = result
      assert is_binary(detail)
    end

    test "renders 500 error" do
      result = VetWeb.ErrorJSON.render("500.json", %{})
      assert %{errors: %{detail: detail}} = result
      assert is_binary(detail)
    end
  end

  describe "controller modules are callable" do
    test "ScanController module is loaded" do
      assert Code.ensure_loaded?(VetWeb.ScanController)
    end

    test "PackageController module is loaded" do
      assert Code.ensure_loaded?(VetWeb.PackageController)
    end

    test "AttestationController module is loaded" do
      assert Code.ensure_loaded?(VetWeb.AttestationController)
    end

    test "FallbackController module is loaded" do
      assert Code.ensure_loaded?(VetWeb.FallbackController)
    end
  end

  describe "API routes are configured" do
    setup do
      routes = Phoenix.Router.routes(VetWeb.Router)
      {:ok, routes: routes}
    end

    test "POST /api/scans exists", %{routes: routes} do
      assert Enum.any?(routes, fn r -> r.verb == :post and r.path == "/api/scans" end)
    end

    test "GET /api/scans/:id exists", %{routes: routes} do
      assert Enum.any?(routes, fn r -> r.verb == :get and r.path == "/api/scans/:id" end)
    end

    test "GET /api/packages/:name exists", %{routes: routes} do
      assert Enum.any?(routes, fn r -> r.verb == :get and r.path == "/api/packages/:name" end)
    end

    test "POST /api/attestations exists", %{routes: routes} do
      assert Enum.any?(routes, fn r -> r.verb == :post and r.path == "/api/attestations" end)
    end

    test "GET /api/attestations/:package/:version exists", %{routes: routes} do
      assert Enum.any?(routes, fn r ->
        r.verb == :get and r.path == "/api/attestations/:package/:version"
      end)
    end
  end
end
