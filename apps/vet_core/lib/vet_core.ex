defmodule VetCore do
  @moduledoc false

  alias VetCore.Types.ScanReport

  def scan(project_path, opts \\ []) do
    VetCore.Scanner.scan(project_path, opts)
  end

  def scan!(project_path, opts \\ []) do
    case scan(project_path, opts) do
      {:ok, %ScanReport{} = report} -> report
      {:error, reason} -> raise "Vet scan failed: #{inspect(reason)}"
    end
  end
end
