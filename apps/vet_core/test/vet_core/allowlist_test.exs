defmodule VetCore.AllowlistTest do
  use ExUnit.Case

  alias VetCore.Allowlist
  alias VetCore.Types.Finding

  test "suppressed?(:rustler, :system_exec) returns true" do
    assert Allowlist.suppressed?(:rustler, :system_exec) == true
  end

  test "suppressed?(:unknown_pkg, :system_exec) returns false (baseline)" do
    assert Allowlist.suppressed?(:unknown_pkg, :system_exec) == false
  end

  test "suppressed?(:phoenix, :code_eval) returns true" do
    assert Allowlist.suppressed?(:phoenix, :code_eval) == true
  end

  test "suppressed?(:phoenix, :system_exec) returns true" do
    assert Allowlist.suppressed?(:phoenix, :system_exec) == true
  end

  test "suppressed? returns false for unsuppressed combination (baseline)" do
    assert Allowlist.suppressed?(:jason, :system_exec) == false
  end

  describe "filter_findings/3" do
    setup do
      tmp_dir = Path.join(System.tmp_dir!(), "vet_allowlist_test_#{:erlang.unique_integer([:positive])}")
      File.mkdir_p!(tmp_dir)
      on_exit(fn -> File.rm_rf!(tmp_dir) end)
      %{tmp_dir: tmp_dir}
    end

    test "removes suppressed findings", %{tmp_dir: tmp_dir} do
      findings = [
        %Finding{
          dep_name: :rustler,
          file_path: "lib/rustler.ex",
          line: 1,
          check_id: :system_exec,
          category: :system_exec,
          severity: :critical,
          description: "System.cmd call"
        },
        %Finding{
          dep_name: :rustler,
          file_path: "lib/rustler.ex",
          line: 5,
          check_id: :file_access,
          category: :file_access,
          severity: :warning,
          description: "File.read! call"
        }
      ]

      filtered = Allowlist.filter_findings(findings, :rustler, tmp_dir)

      # :rustler + :system_exec is suppressed, :rustler + :file_access is not
      assert length(filtered) == 1
      assert hd(filtered).category == :file_access
    end

    test "user config via .vet.exs is loaded and applied", %{tmp_dir: tmp_dir} do
      # Write a .vet.exs config file
      File.write!(Path.join(tmp_dir, ".vet.exs"), """
      %{
        allow: [
          {:my_dep, :network_access, "Trusted network call"}
        ]
      }
      """)

      findings = [
        %Finding{
          dep_name: :my_dep,
          file_path: "lib/my_dep.ex",
          line: 1,
          check_id: :network_access,
          category: :network_access,
          severity: :warning,
          description: "HTTP request"
        }
      ]

      filtered = Allowlist.filter_findings(findings, :my_dep, tmp_dir)

      assert filtered == []
    end

    test "malformed .vet.exs does not crash", %{tmp_dir: tmp_dir} do
      # Use a syntactically valid expression that evaluates to a non-map/non-list
      # (Code.eval_string raises on syntax errors, but the function handles unexpected return types)
      File.write!(Path.join(tmp_dir, ".vet.exs"), """
      :not_a_map_or_list
      """)

      findings = [
        %Finding{
          dep_name: :some_dep,
          file_path: "lib/some.ex",
          line: 1,
          check_id: :system_exec,
          category: :system_exec,
          severity: :critical,
          description: "System.cmd call"
        }
      ]

      # Should not crash; findings remain unfiltered
      result = Allowlist.filter_findings(findings, :some_dep, tmp_dir)
      assert length(result) == 1
    end
  end

  describe "load_user_config/1" do
    setup do
      tmp_dir = Path.join(System.tmp_dir!(), "vet_allowlist_cfg_test_#{:erlang.unique_integer([:positive])}")
      File.mkdir_p!(tmp_dir)
      on_exit(fn -> File.rm_rf!(tmp_dir) end)
      %{tmp_dir: tmp_dir}
    end

    test "returns empty list when no .vet.exs exists", %{tmp_dir: tmp_dir} do
      assert Allowlist.load_user_config(tmp_dir) == []
    end

    test "parses list format config", %{tmp_dir: tmp_dir} do
      File.write!(Path.join(tmp_dir, ".vet.exs"), """
      [{:my_dep, :system_exec}]
      """)

      result = Allowlist.load_user_config(tmp_dir)
      assert length(result) == 1
      assert {:my_dep, :system_exec, "User allowlisted"} in result
    end
  end
end
