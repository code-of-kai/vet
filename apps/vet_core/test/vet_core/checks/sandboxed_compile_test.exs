defmodule VetCore.Checks.SandboxedCompileTest do
  use ExUnit.Case, async: true

  alias VetCore.Checks.SandboxedCompile
  alias VetCore.Sandbox.BehaviorReport
  alias VetCore.Types.Dependency

  test "run/3 returns [] when opt-in flag is absent" do
    dep = %Dependency{name: :test_dep, version: "1.0.0", source: :hex}
    tmp = Path.join(System.tmp_dir!(), "vet_sandbox_check_#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join([tmp, "deps", "test_dep"]))
    on_exit(fn -> File.rm_rf!(tmp) end)

    assert SandboxedCompile.run(dep, tmp, []) == []
    assert SandboxedCompile.run(dep, tmp, %{sandboxed_compile: false}) == []
  end

  test "run/3 returns [] when dep dir is missing even if opt-in" do
    dep = %Dependency{name: :missing_dep, version: "1.0.0", source: :hex}
    tmp = Path.join(System.tmp_dir!(), "vet_sandbox_check_missing_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf!(tmp) end)

    assert SandboxedCompile.run(dep, tmp, sandboxed_compile: true) == []
  end

  describe "report_to_findings/2" do
    test "returns [] when sandbox_available? is false" do
      report = %BehaviorReport{
        backend: :stub,
        command: ["mix"],
        workdir: "/tmp",
        exit_status: 0,
        duration_ms: 0,
        sandbox_available?: false
      }

      assert SandboxedCompile.report_to_findings(report, :foo) == []
    end

    test "fires critical finding per denied operation" do
      report = %BehaviorReport{
        backend: :sandbox_exec,
        command: ["mix"],
        workdir: "/tmp/wd",
        exit_status: 1,
        duration_ms: 10,
        sandbox_available?: true,
        denied_operations: [
          %{op: "file-write-create", target: "/etc/passwd", raw: "..."},
          %{op: "network-outbound", target: "tcp:attacker.test:443", raw: "..."}
        ]
      }

      findings = SandboxedCompile.report_to_findings(report, :test_dep)

      assert length(findings) == 2

      assert Enum.all?(findings, fn f ->
               f.check_id == :sandboxed_compile_denied and f.severity == :critical and
                 f.compile_time? == true
             end)
    end

    test "fires critical finding per network attempt" do
      report = %BehaviorReport{
        backend: :sandbox_exec,
        command: ["mix"],
        workdir: "/tmp/wd",
        exit_status: 0,
        duration_ms: 10,
        sandbox_available?: true,
        network_attempts: [{"attacker.example", 443}]
      }

      findings = SandboxedCompile.report_to_findings(report, :test_dep)

      assert [finding] = findings
      assert finding.check_id == :sandboxed_compile_network
      assert finding.severity == :critical
      assert String.contains?(finding.description, "attacker.example:443")
    end

    test "fires warning finding per subprocess spawned" do
      report = %BehaviorReport{
        backend: :sandbox_exec,
        command: ["mix"],
        workdir: "/tmp/wd",
        exit_status: 0,
        duration_ms: 10,
        sandbox_available?: true,
        processes_spawned: ["/bin/sh", "/usr/bin/curl"]
      }

      findings = SandboxedCompile.report_to_findings(report, :test_dep)

      assert length(findings) == 2
      assert Enum.all?(findings, &(&1.check_id == :sandboxed_compile_subprocess))
      assert Enum.all?(findings, &(&1.severity == :warning))
    end

    test "fires critical finding when writes happened outside workdir" do
      workdir = "/private/tmp/wd_write"

      report = %BehaviorReport{
        backend: :sandbox_exec,
        command: ["mix"],
        workdir: workdir,
        exit_status: 0,
        duration_ms: 10,
        sandbox_available?: true,
        files_written: [
          Path.join(workdir, "a.beam"),
          "/etc/passwd_new"
        ]
      }

      findings = SandboxedCompile.report_to_findings(report, :test_dep)

      assert [finding] = findings
      assert finding.check_id == :sandboxed_compile_write
      assert finding.file_path == "/etc/passwd_new"
    end

    test "clean report produces no findings" do
      report = %BehaviorReport{
        backend: :sandbox_exec,
        command: ["mix"],
        workdir: "/tmp/wd",
        exit_status: 0,
        duration_ms: 10,
        sandbox_available?: true
      }

      assert SandboxedCompile.report_to_findings(report, :test_dep) == []
    end

    test "all findings carry evidence_level :sandbox_observed" do
      report = %BehaviorReport{
        backend: :sandbox_exec,
        command: ["mix"],
        workdir: "/tmp/wd",
        exit_status: 1,
        duration_ms: 10,
        sandbox_available?: true,
        denied_operations: [%{op: "file-write-create", target: "/etc/passwd", raw: "..."}],
        network_attempts: [{"attacker.example", 443}],
        processes_spawned: ["/bin/sh"],
        files_written: ["/outside/workdir/file"]
      }

      findings = SandboxedCompile.report_to_findings(report, :test_dep)

      assert length(findings) == 4
      assert Enum.all?(findings, &(&1.evidence_level == :sandbox_observed))
    end
  end
end
