defmodule VetWeb.Wiring.RouterTest do
  use ExUnit.Case, async: true

  describe "VetWeb.Router module" do
    test "module loads" do
      assert Code.ensure_loaded?(VetWeb.Router)
    end
  end

  describe "expected routes exist" do
    setup do
      routes = Phoenix.Router.routes(VetWeb.Router)
      {:ok, routes: routes}
    end

    @expected_routes [
      {"GET", "/"},
      {"GET", "/packages/:name"},
      {"GET", "/search"},
      {"POST", "/api/scans"},
      {"GET", "/api/scans/:id"},
      {"GET", "/api/packages/:name"},
      {"POST", "/api/attestations"}
    ]

    for {method, path} <- @expected_routes do
      test "#{method} #{path} is routed", %{routes: routes} do
        match =
          Enum.find(routes, fn route ->
            route.verb == unquote(String.downcase(method) |> String.to_atom()) &&
              route.path == unquote(path)
          end)

        assert match != nil,
               "Expected route #{unquote(method)} #{unquote(path)} not found in router"
      end
    end
  end

  describe "controller modules exist" do
    @controllers [
      VetWeb.ScanController,
      VetWeb.PackageController,
      VetWeb.AttestationController
    ]

    for controller <- @controllers do
      test "#{inspect(controller)} is loaded" do
        assert Code.ensure_loaded?(unquote(controller))
      end
    end
  end

  describe "LiveView modules exist" do
    @live_views [
      VetWeb.DashboardLive,
      VetWeb.PackageLive,
      VetWeb.SearchLive
    ]

    for lv <- @live_views do
      test "#{inspect(lv)} is loaded" do
        assert Code.ensure_loaded?(unquote(lv))
      end
    end
  end
end
