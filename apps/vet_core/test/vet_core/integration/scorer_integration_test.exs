defmodule VetCore.Integration.ScorerIntegrationTest do
  use ExUnit.Case, async: true

  alias VetCore.Scorer
  alias VetCore.Types.{Dependency, DependencyReport, Finding, HexMetadata}

  describe "scoring through the pipeline" do
    test "compile-time critical scores higher than runtime warning" do
      dep = %Dependency{name: :test_pkg, version: "1.0.0", source: :hex}

      compile_time_critical_findings = [
        %Finding{
          dep_name: :test_pkg,
          file_path: "lib/bad.ex",
          line: 1,
          check_id: :system_exec,
          category: :system_exec,
          severity: :critical,
          compile_time?: true,
          description: "System.cmd in module body"
        }
      ]

      runtime_warning_findings = [
        %Finding{
          dep_name: :test_pkg,
          file_path: "lib/ok.ex",
          line: 5,
          check_id: :env_access,
          category: :env_access,
          severity: :warning,
          compile_time?: false,
          description: "System.get_env"
        }
      ]

      {ct_score, _ct_level} = Scorer.score(dep, compile_time_critical_findings, nil)
      {rt_score, _rt_level} = Scorer.score(dep, runtime_warning_findings, nil)

      # Compile-time critical = 40 points vs runtime warning = 5 points
      assert ct_score > rt_score
    end

    test "popularity adjustment reduces score for very popular packages" do
      dep = %Dependency{name: :popular_pkg, version: "2.0.0", source: :hex}

      findings = [
        %Finding{
          dep_name: :popular_pkg,
          file_path: "lib/p.ex",
          line: 3,
          check_id: :file_access,
          category: :file_access,
          severity: :warning,
          compile_time?: false,
          description: "File.read!"
        }
      ]

      low_popularity = %HexMetadata{downloads: 500, owner_count: 2}
      high_popularity = %HexMetadata{downloads: 15_000_000, owner_count: 5}

      {low_pop_score, _} = Scorer.score(dep, findings, low_popularity)
      {high_pop_score, _} = Scorer.score(dep, findings, high_popularity)

      # 15M downloads gets 0.3 multiplier, 500 downloads gets no adjustment
      assert high_pop_score < low_pop_score
    end

    test "score is capped at 100" do
      dep = %Dependency{name: :terrible_pkg, version: "0.0.1", source: {:git, "https://evil.com/repo"}}

      # Generate enough findings across distinct (file, category) buckets to
      # push the score well over 100. Per-(file,category) bucketing means ten
      # System.cmd calls in one module only score as one piece of evidence —
      # so the fixture needs ten DIFFERENT modules.
      findings =
        for i <- 1..10 do
          %Finding{
            dep_name: :terrible_pkg,
            file_path: "lib/bad_#{i}.ex",
            line: i,
            check_id: :system_exec,
            category: :system_exec,
            severity: :critical,
            compile_time?: true,
            description: "System.cmd ##{i}"
          }
        end

      # Git source +10, low downloads +20, single owner +5, no description +5
      meta = %HexMetadata{downloads: 10, owner_count: 1, description: nil}

      {score, level} = Scorer.score(dep, findings, meta)

      assert score == 100
      assert level == :critical
    end

    test "score_report produces correct summary from multiple dependency reports" do
      dep_reports = [
        %DependencyReport{
          dependency: %Dependency{name: :risky, version: "0.1.0", source: :hex},
          findings: [
            %Finding{
              dep_name: :risky,
              file_path: "lib/r.ex",
              line: 1,
              check_id: :system_exec,
              category: :system_exec,
              severity: :critical,
              compile_time?: true,
              description: "System.cmd"
            },
            %Finding{
              dep_name: :risky,
              file_path: "lib/r.ex",
              line: 5,
              check_id: :env_access,
              category: :env_access,
              severity: :warning,
              compile_time?: false,
              description: "System.get_env"
            }
          ],
          risk_score: 80,
          risk_level: :critical
        },
        %DependencyReport{
          dependency: %Dependency{name: :safe, version: "1.0.0", source: :hex},
          findings: [],
          risk_score: 0,
          risk_level: :low
        }
      ]

      summary = Scorer.score_report(dep_reports)

      assert summary.total_deps == 2
      assert summary.total_findings == 2
      assert summary.highest_risk_dep == :risky
      assert summary.highest_risk_score == 80
      assert summary.critical_count == 1
      assert summary.high_count == 0
      assert summary.deps_by_risk_level[:critical] == 1
      assert summary.deps_by_risk_level[:low] == 1
    end

    test "scoring with varying severity levels through full scan pipeline" do
      tmp_dir = Path.join(System.tmp_dir!(), "vet_scorer_int_#{System.unique_integer([:positive])}")
      File.mkdir_p!(tmp_dir)

      on_exit(fn -> File.rm_rf!(tmp_dir) end)

      # Create a dep with both critical and warning findings
      lock_content = ~s(%{\n  "mixed_dep": {:hex, :mixed_dep, "0.5.0", "abc123", [:mix], [], "hexpm", "def456"},\n})
      File.write!(Path.join(tmp_dir, "mix.lock"), lock_content)

      dep_dir = Path.join([tmp_dir, "deps", "mixed_dep", "lib"])
      File.mkdir_p!(dep_dir)

      source = ~S"""
      defmodule MixedDep do
        @compile_cmd System.cmd("whoami", [])

        def runtime_read do
          File.read!("/tmp/something")
          System.get_env("HOME")
        end
      end
      """

      File.write!(Path.join(dep_dir, "mixed.ex"), source)

      mix_dir = Path.join([tmp_dir, "deps", "mixed_dep"])

      File.write!(Path.join(mix_dir, "mix.exs"), ~S"""
      defmodule MixedDep.MixProject do
        use Mix.Project
        def project, do: [app: :mixed_dep, version: "0.5.0"]
      end
      """)

      {:ok, report} = VetCore.scan(tmp_dir, skip_hex: true)
      dep_report = hd(report.dependency_reports)

      # Should have compile-time system_exec (critical) and runtime file_access + env_access
      ct_findings = Enum.filter(dep_report.findings, & &1.compile_time?)
      rt_findings = Enum.reject(dep_report.findings, & &1.compile_time?)

      assert length(ct_findings) >= 1
      assert length(rt_findings) >= 1

      # Compile-time critical finding should dominate the score
      assert dep_report.risk_score > 0
      assert dep_report.risk_level in [:medium, :high, :critical]
    end
  end
end
