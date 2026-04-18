defmodule VetCore.Sandbox.Runner.SandboxExecTest do
  use ExUnit.Case, async: true

  alias VetCore.Sandbox.Runner.SandboxExec

  test "available?/0 reflects presence of /usr/bin/sandbox-exec" do
    expected = File.regular?("/usr/bin/sandbox-exec")
    assert SandboxExec.available?() == expected
  end

  describe "build_profile/2" do
    @policy %{
      allow_network: false,
      allow_subprocess: false,
      writable_paths: ["/tmp/workdir"],
      readable_paths: ["/tmp/workdir", "/usr/local/lib"]
    }

    test "starts with (version 1) and (deny default)" do
      profile = SandboxExec.build_profile(@policy, "/tmp/workdir")
      assert profile =~ "(version 1)"
      assert profile =~ "(deny default)"
    end

    test "always allows read on workdir" do
      profile = SandboxExec.build_profile(@policy, "/tmp/workdir")
      assert profile =~ "(allow file-read* (subpath \"/tmp/workdir\"))"
    end

    test "expands writable_paths to file-write* rules" do
      profile = SandboxExec.build_profile(@policy, "/tmp/workdir")
      assert profile =~ "(allow file-write* (subpath \"/tmp/workdir\"))"
    end

    test "does NOT allow network when allow_network: false" do
      profile = SandboxExec.build_profile(@policy, "/tmp/workdir")
      refute profile =~ "(allow network*)"
    end

    test "does NOT allow process-exec when allow_subprocess: false" do
      profile = SandboxExec.build_profile(@policy, "/tmp/workdir")
      refute profile =~ "(allow process-exec)"
    end

    test "allows network when policy permits it" do
      policy = %{@policy | allow_network: true}
      profile = SandboxExec.build_profile(policy, "/tmp/workdir")
      assert profile =~ "(allow network*)"
    end

    test "allows process-exec when policy permits it" do
      policy = %{@policy | allow_subprocess: true}
      profile = SandboxExec.build_profile(policy, "/tmp/workdir")
      assert profile =~ "(allow process-exec)"
    end

    test "allows reading from system code paths" do
      profile = SandboxExec.build_profile(@policy, "/tmp/workdir")
      assert profile =~ "/usr/lib"
      assert profile =~ "/System/Library"
    end
  end
end
