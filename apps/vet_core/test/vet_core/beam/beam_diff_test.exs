defmodule VetCore.BEAM.BeamDiffTest do
  use ExUnit.Case, async: true

  alias VetCore.BEAM.{BeamDiff, BeamProfile}

  defp profile(opts \\ []) do
    %BeamProfile{
      module: opts[:module] || Foo,
      path: opts[:path] || "<test>",
      imports: opts[:imports] || [],
      exports: opts[:exports] || [],
      atoms: opts[:atoms] || [],
      attributes: opts[:attributes] || %{},
      compile_info: opts[:compile_info] || %{},
      dynamic_dispatch_count: opts[:dynamic_dispatch_count] || 0,
      handle_undefined_function?: opts[:handle_undefined_function?] || false
    }
  end

  describe "diff/2" do
    test "identical profiles produce an empty diff" do
      p = profile(imports: [{:erlang, :spawn, 3}], exports: [{:f, 0}], atoms: [:ok])
      diff = BeamDiff.diff(p, p)

      assert diff.imports_added == []
      assert diff.imports_removed == []
      assert diff.atoms_added == []
      assert diff.dynamic_dispatch_delta == 0
      refute BeamDiff.changed?(diff)
    end

    test "imports_added shows newly-imported MFAs" do
      old = profile(imports: [{:erlang, :spawn, 3}])
      new = profile(imports: [{:erlang, :spawn, 3}, {:ssh, :connect, 3}])

      diff = BeamDiff.diff(old, new)
      assert {:ssh, :connect, 3} in diff.imports_added
      assert diff.imports_removed == []
    end

    test "imports_removed shows imports that disappeared" do
      old = profile(imports: [{:ssh, :connect, 3}])
      new = profile(imports: [])

      diff = BeamDiff.diff(old, new)
      assert {:ssh, :connect, 3} in diff.imports_removed
    end

    test "exports_added/removed track export changes" do
      old = profile(exports: [{:f, 0}])
      new = profile(exports: [{:f, 0}, {:g, 1}])

      diff = BeamDiff.diff(old, new)
      assert {:g, 1} in diff.exports_added
      assert diff.exports_removed == []
    end

    test "atoms_added shows new atoms in the table" do
      old = profile(atoms: [:ok])
      new = profile(atoms: [:ok, :"http://attacker.test"])

      diff = BeamDiff.diff(old, new)
      assert :"http://attacker.test" in diff.atoms_added
    end

    test "dynamic_dispatch_delta tracks count changes" do
      old = profile(dynamic_dispatch_count: 1)
      new = profile(dynamic_dispatch_count: 5)

      diff = BeamDiff.diff(old, new)
      assert diff.dynamic_dispatch_delta == 4
    end

    test "handle_undefined_function_added? flips when newly exported" do
      old = profile(handle_undefined_function?: false)
      new = profile(handle_undefined_function?: true)

      diff = BeamDiff.diff(old, new)
      assert diff.handle_undefined_function_added?
      refute diff.handle_undefined_function_removed?
    end

    test "handle_undefined_function_removed? flips the other way" do
      old = profile(handle_undefined_function?: true)
      new = profile(handle_undefined_function?: false)

      diff = BeamDiff.diff(old, new)
      refute diff.handle_undefined_function_added?
      assert diff.handle_undefined_function_removed?
    end
  end

  describe "diff_set/2" do
    test "identifies added, removed, and changed modules" do
      a = profile(module: A, imports: [{:erlang, :spawn, 3}])
      b_old = profile(module: B, imports: [])
      b_new = profile(module: B, imports: [{:ssh, :connect, 3}])
      c = profile(module: C, imports: [])

      result = BeamDiff.diff_set([a, b_old], [b_new, c])

      assert Enum.map(result.added_modules, & &1.module) == [C]
      assert Enum.map(result.removed_modules, & &1.module) == [A]
      assert length(result.changed_modules) == 1
      [b_diff] = result.changed_modules
      assert b_diff.module == B
      assert {:ssh, :connect, 3} in b_diff.imports_added
    end

    test "unchanged modules are not in the changed list" do
      a = profile(module: A, imports: [{:erlang, :spawn, 3}])
      result = BeamDiff.diff_set([a], [a])
      assert result.changed_modules == []
    end
  end

  describe "classify/2" do
    test "fires :dangerous_imports_added on :ssh" do
      old = profile(imports: [])
      new = profile(imports: [{:ssh, :connect, 3}])
      diff = BeamDiff.diff(old, new)

      {suspicious?, signals} = BeamDiff.classify(diff)
      assert suspicious?
      assert :dangerous_imports_added in signals
    end

    test "fires :dangerous_imports_added on :os.cmd" do
      diff = BeamDiff.diff(profile(), profile(imports: [{:os, :cmd, 1}]))
      {true, signals} = BeamDiff.classify(diff)
      assert :dangerous_imports_added in signals
    end

    test "fires :dangerous_imports_added on :erlang.load_nif" do
      diff = BeamDiff.diff(profile(), profile(imports: [{:erlang, :load_nif, 2}]))
      {true, signals} = BeamDiff.classify(diff)
      assert :dangerous_imports_added in signals
    end

    test "does NOT fire on benign import additions" do
      diff = BeamDiff.diff(profile(), profile(imports: [{:erlang, :length, 1}]))
      {suspicious?, signals} = BeamDiff.classify(diff)
      refute suspicious?
      assert signals == []
    end

    test "fires :handle_undefined_function_added" do
      diff = BeamDiff.diff(profile(), profile(handle_undefined_function?: true))
      {true, signals} = BeamDiff.classify(diff)
      assert :handle_undefined_function_added in signals
    end

    test "fires :dynamic_dispatch_spike when delta crosses threshold" do
      diff = BeamDiff.diff(profile(dynamic_dispatch_count: 0),
                           profile(dynamic_dispatch_count: 5))
      {true, signals} = BeamDiff.classify(diff)
      assert :dynamic_dispatch_spike in signals
    end

    test "does NOT fire dispatch_spike below threshold" do
      diff = BeamDiff.diff(profile(dynamic_dispatch_count: 0),
                           profile(dynamic_dispatch_count: 2))
      {_, signals} = BeamDiff.classify(diff)
      refute :dynamic_dispatch_spike in signals
    end

    test "fires :suspicious_atoms_added on URL atom" do
      diff =
        BeamDiff.diff(profile(),
          profile(atoms: [:"http://attacker.test/beacon"]))

      {true, signals} = BeamDiff.classify(diff)
      assert :suspicious_atoms_added in signals
    end

    test "fires :suspicious_atoms_added on IPv4 atom" do
      diff = BeamDiff.diff(profile(), profile(atoms: [:"203.0.113.7"]))
      {true, signals} = BeamDiff.classify(diff)
      assert :suspicious_atoms_added in signals
    end

    test "configurable dispatch threshold" do
      diff = BeamDiff.diff(profile(dynamic_dispatch_count: 0),
                           profile(dynamic_dispatch_count: 2))
      {true, signals} = BeamDiff.classify(diff, dispatch_threshold: 2)
      assert :dynamic_dispatch_spike in signals
    end
  end
end
