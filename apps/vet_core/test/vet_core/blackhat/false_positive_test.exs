defmodule VetCore.Blackhat.FalsePositiveTest do
  @moduledoc """
  Black hat tests verifying the scanner does NOT produce false positives
  on legitimate code patterns. Each test confirms that benign code either
  produces no findings or produces findings at the appropriate (non-critical)
  severity level.
  """
  use ExUnit.Case, async: true

  alias VetCore.Checks.{SystemExec, NetworkAccess, FileAccess, EnvAccess, Obfuscation}
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

    unless Enum.any?(source_files, fn {f, _} -> f == "mix.exs" end) do
      mix_content = """
      defmodule #{Macro.camelize(to_string(dep_name))}.MixProject do
        use Mix.Project
        def project, do: [app: :#{dep_name}, version: "1.0.0"]
      end
      """

      File.write!(Path.join(dep_dir, "mix.exs"), mix_content)
    end

    lock = ~s(%{\n  "#{dep_name}": {:hex, :#{dep_name}, "1.0.0", "abc123", [:mix], [], "hexpm", "def456"},\n})
    File.write!(Path.join(tmp_dir, "mix.lock"), lock)

    {tmp_dir, %Dependency{name: dep_name, version: "1.0.0", source: :hex}}
  end

  defp cleanup(tmp_dir) do
    File.rm_rf!(tmp_dir)
  end

  # ---------------------------------------------------------------------------
  # Test: Normal config reading (runtime env access)
  # ---------------------------------------------------------------------------

  describe "normal config reading" do
    setup do
      source = ~S"""
      defmodule Legit.Config do
        def database_url, do: System.get_env("DATABASE_URL")
        def port, do: System.get_env("PORT") || "4000"
      end
      """

      {tmp_dir, dep} = setup_dep(:legit_config, [{"config.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "env_access findings exist but are runtime (not compile-time critical)",
         %{project_path: path, dep: dep} do
      findings = EnvAccess.run(dep, path, [])
      assert length(findings) >= 1

      # All findings should be runtime (inside def), not compile-time
      for finding <- findings do
        assert finding.compile_time? == false,
               "Expected runtime finding but got compile-time: #{finding.description}"
      end

      # DATABASE_URL is a sensitive pattern, so it gets :critical from the
      # sensitive var override, but PORT should be :warning (runtime, non-sensitive)
      port_finding =
        Enum.find(findings, fn f -> String.contains?(f.description, "PORT") end)

      if port_finding do
        assert port_finding.severity == :warning
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Test: Standard NIF build tool (allowlisted dep)
  # ---------------------------------------------------------------------------

  describe "standard NIF build tool (rustler-like)" do
    setup do
      source = ~S"""
      defmodule Legit.NifBuilder do
        def compile do
          System.cmd("cargo", ["build", "--release"])
        end
      end
      """

      {tmp_dir, dep_generic} = setup_dep(:legit_nif, [{"nif_builder.ex", source}])

      # Also set up as :rustler to test allowlisting
      dep_rustler = %Dependency{name: :rustler, version: "1.0.0", source: :hex}
      rustler_dir = Path.join([tmp_dir, "deps", "rustler", "lib"])
      File.mkdir_p!(rustler_dir)
      File.write!(Path.join(rustler_dir, "nif_builder.ex"), source)

      rustler_mix = """
      defmodule Rustler.MixProject do
        use Mix.Project
        def project, do: [app: :rustler, version: "1.0.0"]
      end
      """

      File.write!(Path.join([tmp_dir, "deps", "rustler", "mix.exs"]), rustler_mix)

      # Update lock to include rustler
      lock = ~s(%{\n  "legit_nif": {:hex, :legit_nif, "1.0.0", "abc123", [:mix], [], "hexpm", "def456"},\n  "rustler": {:hex, :rustler, "1.0.0", "abc123", [:mix], [], "hexpm", "def456"},\n})
      File.write!(Path.join(tmp_dir, "mix.lock"), lock)

      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep_generic: dep_generic, dep_rustler: dep_rustler}
    end

    test "system_exec IS detected for generic dep", %{project_path: path, dep_generic: dep} do
      findings = SystemExec.run(dep, path, [])
      assert length(findings) >= 1
      assert Enum.any?(findings, &(&1.check_id == :system_exec))
    end

    test "system_exec is suppressed for :rustler via allowlist",
         %{project_path: path, dep_rustler: dep} do
      # The raw check still finds it
      raw_findings = SystemExec.run(dep, path, [])
      assert length(raw_findings) >= 1

      # But the allowlist filter removes it
      filtered = VetCore.Allowlist.filter_findings(raw_findings, :rustler, path)
      assert filtered == []
    end
  end

  # ---------------------------------------------------------------------------
  # Test: Normal HTTP client usage (runtime, warning severity)
  # ---------------------------------------------------------------------------

  describe "normal HTTP client usage" do
    setup do
      source = ~S"""
      defmodule Legit.ApiClient do
        def fetch_data(url) do
          Req.get(url)
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:legit_http, [{"api_client.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "network_access detected at :warning severity (runtime)",
         %{project_path: path, dep: dep} do
      findings = NetworkAccess.run(dep, path, [])
      assert length(findings) >= 1

      req_finding = Enum.find(findings, &(&1.check_id == :network_access))
      assert req_finding != nil
      # Inside a def, so runtime -> base severity :warning
      assert req_finding.severity == :warning
      assert req_finding.compile_time? == false
    end
  end

  # ---------------------------------------------------------------------------
  # Test: Normal file operations (non-sensitive path)
  # ---------------------------------------------------------------------------

  describe "normal file operations" do
    setup do
      source = ~S"""
      defmodule Legit.FileOps do
        def read_config do
          File.read!("config/app.exs")
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:legit_fileops, [{"file_ops.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "file_access detected at :warning, NOT :critical (non-sensitive path)",
         %{project_path: path, dep: dep} do
      findings = FileAccess.run(dep, path, [])
      assert length(findings) >= 1

      file_finding = Enum.find(findings, &(&1.check_id == :file_access))
      assert file_finding != nil
      # Non-sensitive path + runtime -> :warning
      assert file_finding.severity == :warning
      assert file_finding.compile_time? == false
    end
  end

  # ---------------------------------------------------------------------------
  # Test: Benign Base64 usage (no eval -- should NOT trigger obfuscation)
  # ---------------------------------------------------------------------------

  describe "benign Base64 usage (no eval)" do
    setup do
      source = ~S"""
      defmodule Legit.Base64 do
        def decode_token(token) do
          Base.decode64!(token)
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:legit_base64, [{"base64_util.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "NO obfuscation finding (Base64 without eval is safe)",
         %{project_path: path, dep: dep} do
      findings = Obfuscation.run(dep, path, [])

      # There should be no decode_eval finding (Base64 alone is fine)
      decode_eval_findings =
        Enum.filter(findings, &(&1.check_id == :obfuscation_decode_eval))

      assert decode_eval_findings == [],
             "Base64 without eval should not trigger decode_eval, got: #{inspect(decode_eval_findings)}"

      # There should also be no dynamic_apply findings
      apply_findings =
        Enum.filter(findings, &(&1.check_id == :obfuscation_dynamic_apply))

      assert apply_findings == []
    end
  end
end
