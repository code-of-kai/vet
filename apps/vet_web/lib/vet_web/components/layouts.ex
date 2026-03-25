defmodule VetWeb.Layouts do
  @moduledoc """
  Layout components for VetWeb.

  Uses basic inline HTML/CSS — no asset pipeline required.
  """

  use VetWeb, :html

  def root(assigns) do
    ~H"""
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="csrf-token" content={get_csrf_token()} />
        <title>Vet - Dependency Security Scanner</title>
        <style>
          * { box-sizing: border-box; margin: 0; padding: 0; }
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }
          nav { background: #1a1a2e; color: white; padding: 1rem 2rem; display: flex; align-items: center; gap: 2rem; }
          nav a { color: #ccc; text-decoration: none; font-size: 0.9rem; }
          nav a:hover { color: white; }
          nav .brand { font-weight: bold; font-size: 1.2rem; color: white; }
          .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
          .card { background: white; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
          .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
          .badge-critical { background: #fee; color: #c00; }
          .badge-high { background: #fff0e0; color: #c60; }
          .badge-medium { background: #fff8e0; color: #960; }
          .badge-low { background: #e8f5e9; color: #2e7d32; }
          table { width: 100%; border-collapse: collapse; }
          th, td { text-align: left; padding: 0.75rem; border-bottom: 1px solid #eee; }
          th { font-weight: 600; color: #666; font-size: 0.85rem; text-transform: uppercase; }
          input[type="text"], input[type="search"] { padding: 0.5rem 1rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem; width: 100%; max-width: 400px; }
          button, .btn { padding: 0.5rem 1rem; border: none; border-radius: 4px; cursor: pointer; font-size: 0.9rem; }
          .btn-primary { background: #1a1a2e; color: white; }
          .btn-primary:hover { background: #2a2a4e; }
          h1 { font-size: 1.8rem; margin-bottom: 1rem; }
          h2 { font-size: 1.4rem; margin-bottom: 0.75rem; }
          h3 { font-size: 1.1rem; margin-bottom: 0.5rem; }
          .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
          .stat-card { background: white; border-radius: 8px; padding: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }
          .stat-value { font-size: 2rem; font-weight: bold; color: #1a1a2e; }
          .stat-label { color: #666; font-size: 0.85rem; margin-top: 0.25rem; }
        </style>
        <script defer phx-track-static src="https://cdn.jsdelivr.net/npm/phoenix@1.7.18/priv/static/phoenix.min.js">
        </script>
        <script defer phx-track-static src="https://cdn.jsdelivr.net/npm/phoenix_live_view@1.0.4/priv/static/phoenix_live_view.min.js">
        </script>
        <script>
          document.addEventListener("DOMContentLoaded", () => {
            if (window.liveSocket) return;
            let csrfToken = document.querySelector("meta[name='csrf-token']").getAttribute("content");
            let liveSocket = new window.LiveView.LiveSocket("/live", window.Phoenix.Socket, {
              params: { _csrf_token: csrfToken },
              longPollFallbackMs: 2500
            });
            liveSocket.connect();
            window.liveSocket = liveSocket;
          });
        </script>
      </head>
      <body>
        <nav>
          <a href="/" class="brand">Vet</a>
          <a href="/">Dashboard</a>
          <a href="/search">Search</a>
        </nav>
        {@inner_content}
      </body>
    </html>
    """
  end

  def app(assigns) do
    ~H"""
    <div class="container">
      <.flash_group flash={@flash} />
      {@inner_content}
    </div>
    """
  end

  defp flash_group(assigns) do
    ~H"""
    <div :if={Phoenix.Flash.get(@flash, :info)} style="background: #d4edda; color: #155724; padding: 0.75rem 1rem; border-radius: 4px; margin-bottom: 1rem;">
      {Phoenix.Flash.get(@flash, :info)}
    </div>
    <div :if={Phoenix.Flash.get(@flash, :error)} style="background: #f8d7da; color: #721c24; padding: 0.75rem 1rem; border-radius: 4px; margin-bottom: 1rem;">
      {Phoenix.Flash.get(@flash, :error)}
    </div>
    """
  end
end
