defmodule VetCoreTest do
  use ExUnit.Case

  test "scan/2 returns {:ok, %ScanReport{}} for a valid project" do
    project_path = Path.expand("../../../../git-foil", __DIR__)

    if File.exists?(Path.join(project_path, "mix.lock")) do
      assert {:ok, %VetCore.Types.ScanReport{} = report} =
               VetCore.scan(project_path, skip_hex: true)

      assert report.project_path == project_path
      assert is_list(report.dependency_reports)
      assert %DateTime{} = report.timestamp
    end
  end

  test "scan/2 returns error for missing project" do
    assert {:error, _} = VetCore.scan("/nonexistent/path", skip_hex: true)
  end
end
