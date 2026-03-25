defmodule Fixtures.BenignModule do
  # Normal function - reads config file (expected, low severity)
  def load_config do
    File.read!("config/app.json")
  end

  # Normal env access for app config (expected)
  def get_port do
    System.get_env("PORT") || "4000"
  end

  # Normal HTTP client usage in a function body (runtime, warning)
  def fetch_data(url) do
    :httpc.request(:get, {url, []}, [], [])
  end

  # String that looks like a URL but is in a comment
  # https://example.com is fine

  # Normal code, no suspicious patterns
  def add(a, b), do: a + b
end
