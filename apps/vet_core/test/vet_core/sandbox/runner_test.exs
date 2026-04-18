defmodule VetCore.Sandbox.RunnerTest do
  use ExUnit.Case, async: false

  alias VetCore.Sandbox.{BehaviorReport, Runner}
  alias VetCore.Sandbox.Runner.{Bwrap, SandboxExec, Stub}

  test "backend/0 picks SandboxExec on macOS when sandbox-exec exists" do
    cond do
      :os.type() == {:unix, :darwin} and File.regular?("/usr/bin/sandbox-exec") ->
        assert Runner.backend() == SandboxExec

      :os.type() == {:unix, :linux} and is_binary(System.find_executable("bwrap")) ->
        assert Runner.backend() == Bwrap

      true ->
        assert Runner.backend() == Stub
    end
  end

  test "compile_policy/1 denies network and subprocess by default" do
    policy = Runner.compile_policy("/tmp/project")
    refute policy.allow_network
    refute policy.allow_subprocess
    assert "/tmp/project" in policy.writable_paths
  end

  test "compile_policy/1 makes workdir both readable and writable" do
    policy = Runner.compile_policy("/tmp/project")
    assert "/tmp/project" in policy.writable_paths
    assert "/tmp/project" in policy.readable_paths
  end

  test "Stub.run/3 runs the command and reports sandbox_available?: false" do
    tmp = Path.join(System.tmp_dir!(), "vet_stub_test_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf!(tmp) end)

    report = Stub.run(["echo", "hi"], tmp, Runner.compile_policy(tmp))

    assert %BehaviorReport{} = report
    refute report.sandbox_available?
    assert report.exit_status == 0
    assert String.contains?(report.stdout, "hi")
    # Stub puts an explanatory note
    assert Enum.any?(report.notes, &String.contains?(&1, "No OS sandbox"))
  end

  test "Stub.available?/0 always returns true" do
    assert Stub.available?()
  end
end
