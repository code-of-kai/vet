defmodule VetCore.Stress.ManyFindingsTest do
  use ExUnit.Case, async: true

  alias VetCore.Types.{ScanReport, Dependency, DependencyReport, Finding}
  alias VetCore.Scorer

  @moduletag timeout: 60_000

  setup do
    tmp_dir =
      Path.join(
        System.tmp_dir!(),
        "vet_many_findings_stress_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(tmp_dir)
    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{project_path: tmp_dir}
  end

  describe "dependency with 500 System.cmd calls" do
    test "detects all 500 calls", %{project_path: project_path} do
      # Set up mix.lock
      lock_content =
        ~s(%{\n  "noisy_dep": {:hex, :noisy_dep, "1.0.0", "abc123", [:mix], [], "hexpm", "def456"}\n}\n)

      File.write!(Path.join(project_path, "mix.lock"), lock_content)

      # Create dep with 500 System.cmd calls
      dep_dir = Path.join([project_path, "deps", "noisy_dep"])
      lib_dir = Path.join(dep_dir, "lib")
      File.mkdir_p!(lib_dir)

      mix_source = """
      defmodule NoisyDep.MixProject do
        use Mix.Project
        def project, do: [app: :noisy_dep, version: "1.0.0"]
      end
      """

      File.write!(Path.join(dep_dir, "mix.exs"), mix_source)

      code =
        Enum.map_join(1..500, "\n", fn i ->
          "  def func_#{i}, do: System.cmd(\"echo\", [\"#{i}\"])"
        end)

      source = "defmodule NoisyDep do\n#{code}\nend\n"
      File.write!(Path.join(lib_dir, "noisy.ex"), source)

      {:ok, %ScanReport{} = report} = VetCore.scan(project_path, skip_hex: true)

      dep_report =
        Enum.find(report.dependency_reports, fn dr -> dr.dependency.name == :noisy_dep end)

      assert dep_report != nil

      system_exec_findings =
        Enum.filter(dep_report.findings, fn f -> f.category == :system_exec end)

      assert length(system_exec_findings) == 500,
             "Expected 500 system_exec findings, got #{length(system_exec_findings)}"
    end
  end

  describe "scorer handles 500 findings without overflow" do
    test "score caps at 100" do
      dep = %Dependency{name: :overflow_dep, version: "1.0.0", source: :hex}

      findings =
        Enum.map(1..500, fn i ->
          %Finding{
            dep_name: :overflow_dep,
            file_path: "lib/overflow.ex",
            line: i,
            check_id: :system_exec,
            category: :system_exec,
            severity: :critical,
            compile_time?: false,
            description: "System.cmd call ##{i}"
          }
        end)

      {score, level} = Scorer.score(dep, findings, nil)

      assert score == 100, "Score should cap at 100, got #{score}"
      assert level == :critical
    end
  end

  describe "score_report handles many findings" do
    test "summary computes correctly for 500 findings" do
      dep = %Dependency{name: :noisy, version: "1.0.0", source: :hex}

      findings =
        Enum.map(1..500, fn i ->
          %Finding{
            dep_name: :noisy,
            file_path: "lib/noisy.ex",
            line: i,
            check_id: :system_exec,
            category: :system_exec,
            severity: :critical,
            compile_time?: false,
            description: "System.cmd call ##{i}"
          }
        end)

      dep_report = %DependencyReport{
        dependency: dep,
        findings: findings,
        risk_score: 100,
        risk_level: :critical
      }

      summary = Scorer.score_report([dep_report])

      assert summary.total_deps == 1
      assert summary.total_findings == 500
      assert summary.critical_count == 1
      assert summary.highest_risk_score == 100
    end
  end

  describe "JSON serialization of report with 500 findings" do
    test "Jason.encode! succeeds for a large report" do
      dep = %Dependency{name: :noisy, version: "1.0.0", source: :hex}

      findings =
        Enum.map(1..500, fn i ->
          %Finding{
            dep_name: :noisy,
            file_path: "lib/noisy.ex",
            line: i,
            check_id: :system_exec,
            category: :system_exec,
            severity: :critical,
            compile_time?: false,
            description: "System.cmd call ##{i}"
          }
        end)

      dep_report = %DependencyReport{
        dependency: dep,
        findings: findings,
        risk_score: 100,
        risk_level: :critical
      }

      report = %ScanReport{
        project_path: "/tmp/test",
        timestamp: DateTime.utc_now(),
        dependency_reports: [dep_report],
        summary: Scorer.score_report([dep_report])
      }

      # Convert to a serializable map (structs need to be converted)
      serializable =
        report
        |> Map.from_struct()
        |> Map.update!(:dependency_reports, fn drs ->
          Enum.map(drs, fn dr ->
            dr
            |> Map.from_struct()
            |> Map.update!(:dependency, &Map.from_struct/1)
            |> Map.update!(:findings, fn fs -> Enum.map(fs, &Map.from_struct/1) end)
          end)
        end)

      assert {:ok, json} = Jason.encode(serializable)
      assert is_binary(json)
      assert byte_size(json) > 0

      # Verify we can decode it back
      assert {:ok, decoded} = Jason.decode(json)
      assert length(decoded["dependency_reports"]) == 1

      first_report = hd(decoded["dependency_reports"])
      assert length(first_report["findings"]) == 500
    end
  end
end
