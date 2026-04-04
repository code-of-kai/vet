defmodule VetCore.PreInstallCheckTest do
  use ExUnit.Case, async: true

  alias VetCore.PreInstallCheck

  describe "validate_package_name/1" do
    test "accepts valid package names" do
      assert {:ok, :phoenix} = PreInstallCheck.validate_package_name("phoenix")
      assert {:ok, :ex_aws_s3} = PreInstallCheck.validate_package_name("ex_aws_s3")
      assert {:ok, :a} = PreInstallCheck.validate_package_name("a")
    end

    test "rejects names starting with uppercase" do
      assert {:error, _} = PreInstallCheck.validate_package_name("Phoenix")
    end

    test "rejects names starting with numbers" do
      assert {:error, _} = PreInstallCheck.validate_package_name("3phoenix")
    end

    test "rejects names with hyphens" do
      assert {:error, _} = PreInstallCheck.validate_package_name("phoenix-html")
    end

    test "rejects empty string" do
      assert {:error, _} = PreInstallCheck.validate_package_name("")
    end

    test "rejects names longer than 64 chars" do
      long_name = String.duplicate("a", 65)
      assert {:error, _} = PreInstallCheck.validate_package_name(long_name)
    end

    test "accepts name at exactly 64 chars" do
      name = "a" <> String.duplicate("b", 63)
      assert {:ok, _} = PreInstallCheck.validate_package_name(name)
    end
  end

  describe "check_package/1" do
    test "detects typosquat of phoenix" do
      result = PreInstallCheck.check_package(:phoneix)

      assert result.typosquat_warnings != []
      assert Enum.any?(result.typosquat_warnings, &(&1 =~ "phoenix"))
    end

    test "clean package has no typosquat warnings" do
      result = PreInstallCheck.check_package(:my_totally_unique_pkg_name)

      assert result.typosquat_warnings == []
    end

    test "result includes phantom? field" do
      result = PreInstallCheck.check_package(:phoenix)

      assert is_boolean(result.phantom?)
    end

    test "result includes assessment string" do
      result = PreInstallCheck.check_package(:phoneix)

      assert is_binary(result.assessment)
    end

    test "result includes findings list" do
      result = PreInstallCheck.check_package(:phoneix)

      assert is_list(result.findings)

      for finding <- result.findings do
        assert finding.dep_name == :phoneix
      end
    end
  end

  describe "check_deps/1" do
    setup do
      tmp_dir = Path.join(System.tmp_dir!(), "vet_preinstall_test_#{System.unique_integer([:positive])}")
      File.mkdir_p!(tmp_dir)
      on_exit(fn -> File.rm_rf!(tmp_dir) end)
      %{tmp_dir: tmp_dir}
    end

    @tag timeout: 120_000
    test "parses mix.exs and checks deps", %{tmp_dir: tmp_dir} do
      mix_exs = """
      defmodule MyApp.MixProject do
        use Mix.Project

        def project do
          [app: :my_app, version: "0.1.0", deps: deps()]
        end

        defp deps do
          [
            {:phoenix, "~> 1.7"},
            {:jason, "~> 1.0"}
          ]
        end
      end
      """

      File.write!(Path.join(tmp_dir, "mix.exs"), mix_exs)

      assert {:ok, results} = PreInstallCheck.check_deps(tmp_dir)
      assert is_list(results)
      # phoenix and jason are well-known popular packages — should not be flagged
      # (only packages with warnings are returned)
    end

    test "returns error for missing mix.exs", %{tmp_dir: tmp_dir} do
      assert {:error, _} = PreInstallCheck.check_deps(Path.join(tmp_dir, "nonexistent"))
    end
  end
end
