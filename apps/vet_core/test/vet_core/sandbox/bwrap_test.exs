defmodule VetCore.Sandbox.Runner.BwrapTest do
  use ExUnit.Case, async: true

  alias VetCore.Sandbox.Runner.Bwrap

  test "available?/0 reflects presence of bwrap executable" do
    expected = is_binary(System.find_executable("bwrap"))
    assert Bwrap.available?() == expected
  end

  describe "build_args/2 (network denial default)" do
    @policy %{
      allow_network: false,
      allow_subprocess: false,
      writable_paths: [],
      readable_paths: []
    }

    test "includes --unshare-net when allow_network is false" do
      args = Bwrap.build_args(@policy, "/tmp/wd")
      assert "--unshare-net" in args
    end

    test "includes --unshare-pid, --unshare-uts, --unshare-ipc" do
      args = Bwrap.build_args(@policy, "/tmp/wd")
      assert "--unshare-pid" in args
      assert "--unshare-uts" in args
      assert "--unshare-ipc" in args
    end

    test "includes --die-with-parent" do
      args = Bwrap.build_args(@policy, "/tmp/wd")
      assert "--die-with-parent" in args
    end

    test "--chdir to workdir" do
      args = Bwrap.build_args(@policy, "/tmp/wd")

      assert Enum.chunk_every(args, 2, 1, :discard)
             |> Enum.any?(fn
               ["--chdir", "/tmp/wd"] -> true
               _ -> false
             end)
    end
  end

  test "allow_network removes --unshare-net" do
    policy = %{
      allow_network: true,
      allow_subprocess: false,
      writable_paths: [],
      readable_paths: []
    }

    args = Bwrap.build_args(policy, "/tmp/wd")
    refute "--unshare-net" in args
  end
end
