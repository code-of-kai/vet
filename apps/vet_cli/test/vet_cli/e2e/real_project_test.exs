defmodule VetCli.E2E.RealProjectTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  @moduletag :real_project
  @moduletag timeout: 120_000

  @project_path "/Users/kaitaylor/Documents/Coding/git-foil"

  describe "scans git-foil project" do
    @tag :real_project
    test "scans successfully and produces valid output" do
      if File.exists?(Path.join(@project_path, "mix.lock")) do
        {:ok, report} = VetCore.scan(@project_path, skip_hex: true)

        # It should find dependencies
        assert length(report.dependency_reports) > 0

        # It should produce a valid summary
        assert is_map(report.summary)
        assert report.summary.total_deps > 0

        # Terminal output should not crash
        output = capture_io(fn -> VetReporter.Terminal.render(report) end)
        assert output =~ "Vet"

        # JSON output should be valid
        json = VetReporter.Json.encode(report)
        assert {:ok, parsed} = Jason.decode(json)
        assert is_list(parsed["dependencies"])
        assert length(parsed["dependencies"]) > 0

        # Diagnostics output should not crash
        diag_output = capture_io(fn -> VetReporter.Diagnostics.render(report) end)
        assert is_binary(diag_output)
      else
        IO.puts("Skipping real_project test: git-foil not found at #{@project_path}")
      end
    end
  end
end
