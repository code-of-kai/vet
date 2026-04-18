defmodule VetCore.Sandbox.BehaviorReportTest do
  use ExUnit.Case, async: true

  alias VetCore.Sandbox.BehaviorReport

  test "violations?/1 is false for a clean report" do
    report = %BehaviorReport{
      backend: :stub,
      command: ["echo"],
      workdir: "/tmp",
      exit_status: 0,
      duration_ms: 10
    }

    refute BehaviorReport.violations?(report)
  end

  test "violations?/1 is true when denied_operations is non-empty" do
    report = %BehaviorReport{
      backend: :sandbox_exec,
      command: ["cc"],
      workdir: "/tmp",
      exit_status: 1,
      duration_ms: 10,
      denied_operations: [%{op: "file-write", target: "/etc/passwd", raw: "..."}]
    }

    assert BehaviorReport.violations?(report)
  end

  test "violations?/1 is true when network_attempts is non-empty" do
    report = %BehaviorReport{
      backend: :bwrap,
      command: ["cc"],
      workdir: "/tmp",
      exit_status: 0,
      duration_ms: 10,
      network_attempts: [{"evil.example.com", 443}]
    }

    assert BehaviorReport.violations?(report)
  end

  test "violations?/1 is true when files written outside workdir" do
    report = %BehaviorReport{
      backend: :stub,
      command: ["cc"],
      workdir: "/private/tmp/workdir_a",
      exit_status: 0,
      duration_ms: 10,
      files_written: ["/private/tmp/workdir_a/out", "/etc/passwd"]
    }

    assert BehaviorReport.violations?(report)
  end

  test "violations?/1 is false when all written files are inside workdir" do
    report = %BehaviorReport{
      backend: :stub,
      command: ["cc"],
      workdir: "/private/tmp/workdir_b",
      exit_status: 0,
      duration_ms: 10,
      files_written: ["/private/tmp/workdir_b/a", "/private/tmp/workdir_b/b"]
    }

    refute BehaviorReport.violations?(report)
  end

  test "violations?/1 is true when any process was spawned" do
    report = %BehaviorReport{
      backend: :sandbox_exec,
      command: ["cc"],
      workdir: "/tmp",
      exit_status: 0,
      duration_ms: 10,
      processes_spawned: ["/bin/sh"]
    }

    assert BehaviorReport.violations?(report)
  end
end
