defmodule VetWeb.Router do
  use VetWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {VetWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/", VetWeb do
    pipe_through :browser

    live "/", DashboardLive, :index
    live "/packages/:name", PackageLive, :show
    live "/search", SearchLive, :index
  end

  scope "/api", VetWeb do
    pipe_through :api

    resources "/scans", ScanController, only: [:create, :show]
    get "/packages/:name", PackageController, :show
    get "/packages/:name/history", PackageController, :history
    post "/attestations", AttestationController, :create
    get "/attestations/:package/:version", AttestationController, :show
  end

  if Application.compile_env(:vet_web, :dev_routes, false) do
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through :browser
      live_dashboard "/dashboard", metrics: VetWeb.Telemetry
    end
  end
end
