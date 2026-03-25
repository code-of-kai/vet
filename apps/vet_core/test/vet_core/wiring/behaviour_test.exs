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

      test "exports run/3" do
        Code.ensure_loaded!(unquote(check))
        assert function_exported?(unquote(check), :run, 3)
      end

      test "run/3 with nonexistent dep returns [] (no crash)" do
        dep = %VetCore.Types.Dependency{name: :nonexistent_dep_for_wiring_test}
        result = unquote(check).run(dep, "/tmp/nonexistent_project_path", [])
        assert result == []
      end
    end
  end
end
