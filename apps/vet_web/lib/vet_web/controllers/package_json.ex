defmodule VetWeb.PackageJSON do
  def show(%{package: package}) do
    %{data: package_data(package)}
  end

  def history(%{history: history}) do
    %{
      data: %{
        name: history.name,
        entries: history.entries
      }
    }
  end

  defp package_data(package) do
    %{
      name: package.name,
      latest_version: package.latest_version,
      risk_score: package.risk_score,
      risk_level: package.risk_level,
      ecosystem: package.ecosystem,
      findings: package.findings,
      last_scanned_at: package.last_scanned_at
    }
  end
end
