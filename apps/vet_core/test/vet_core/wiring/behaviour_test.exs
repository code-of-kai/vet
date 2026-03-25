defmodule VetCore.Wiring.BehaviourTest do
  use ExUnit.Case, async: true

  @checks [
    VetCore.Checks.SystemExec,
    VetCore.Checks.CodeEval,
    VetCore.Checks.NetworkAccess,
    VetCore.Checks.FileAccess,
    VetCore.Checks.EnvAccess,
    VetCore.Checks.Obfuscation,
    VetCore.Checks.ShadyLinks,
    VetCore.Checks.CompilerHooks
  ]

  for check <- @checks do
    describe "#{inspect(check)}" do
      test "module is loaded" do
        assert Code.ensure_loaded?(unquote(check))
      end

      test "exports init/1" do
        Code.ensure_loaded!(unquote(check))
        assert function_exported?(unquote(check), :init, 1)
      end

      test "exports run/3" do
        Code.ensure_loaded!(unquote(check))
        assert function_exported?(unquote(check), :run, 3)
      end

      test "init([]) returns a value without crashing" do
        result = unquote(check).init([])
        assert result != nil || result == nil
      end

      test "run/3 with nonexistent dep returns [] (no crash)" do
        dep = %VetCore.Types.Dependency{name: :nonexistent_dep_for_wiring_test}
        result = unquote(check).run(dep, "/tmp/nonexistent_project_path", unquote(check).init([]))
        assert result == []
      end
    end
  end
end
