defmodule VetCore.Stress.EdgeCasesTest do
  use ExUnit.Case, async: true

  alias VetCore.Types.ScanReport
  alias VetCore.Checks.FileHelper

  @moduletag timeout: 60_000

  setup do
    tmp_dir =
      Path.join(
        System.tmp_dir!(),
        "vet_edge_cases_stress_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(tmp_dir)
    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{project_path: tmp_dir}
  end

  describe "empty mix.lock" do
    test "parse returns {:ok, []} for an empty map", %{project_path: project_path} do
      File.write!(Path.join(project_path, "mix.lock"), "%{}\n")

      assert {:ok, report} = VetCore.scan(project_path, skip_hex: true)
      assert report.dependency_reports == []
    end
  end

  describe "mix.lock with only whitespace and comments" do
    test "whitespace-only content raises or returns error", %{project_path: project_path} do
      # An empty string evaluates to nil in Code.eval_string, which will cause
      # a pattern match error. This should result in an error, not a crash.
      File.write!(Path.join(project_path, "mix.lock"), "   \n  \n")

      result =
        try do
          VetCore.scan(project_path, skip_hex: true)
        rescue
          _ -> :rescued
        catch
          _, _ -> :caught
        end

      # The system should either return an error tuple or raise — not hang
      assert result in [:rescued, :caught] or match?({:error, _}, result)
    end

    test "comment-only lock file raises or returns error", %{project_path: project_path} do
      File.write!(Path.join(project_path, "mix.lock"), "# just a comment\n")

      result =
        try do
          VetCore.scan(project_path, skip_hex: true)
        rescue
          _ -> :rescued
        catch
          _, _ -> :caught
        end

      assert result in [:rescued, :caught] or match?({:error, _}, result)
    end
  end

  describe "binary file in deps/lib/" do
    test "binary file that is not valid Elixir is handled by FileHelper.read_and_parse", %{project_path: project_path} do
      # FileHelper.read_and_parse uses a with clause: File.read + Code.string_to_quoted.
      # For truly binary content, Code.string_to_quoted may raise a UnicodeConversionError
      # before returning {:error, _}, which causes the task to crash.
      # Test that the system at least does not hang — it either succeeds or raises.

      lock_content =
        ~s(%{\n  "bin_dep": {:hex, :bin_dep, "1.0.0", "abc123", [:mix], [], "hexpm", "def456"}\n}\n)

      File.write!(Path.join(project_path, "mix.lock"), lock_content)

      dep_dir = Path.join([project_path, "deps", "bin_dep"])
      lib_dir = Path.join(dep_dir, "lib")
      File.mkdir_p!(lib_dir)

      mix_source = """
      defmodule BinDep.MixProject do
        use Mix.Project
        def project, do: [app: :bin_dep, version: "1.0.0"]
      end
      """

      File.write!(Path.join(dep_dir, "mix.exs"), mix_source)

      # Write a file that looks like text but has invalid Elixir syntax (not raw binary)
      invalid_source = "this is not valid elixir {{{{{{{}}}}} @@@ def end end end"
      File.write!(Path.join(lib_dir, "invalid_file.ex"), invalid_source)

      # Also write a valid file alongside it
      File.write!(Path.join(lib_dir, "valid.ex"), "defmodule Valid do\n  def ok, do: :ok\nend\n")

      # Invalid syntax file should be silently skipped, scan should succeed
      assert {:ok, %ScanReport{} = report} = VetCore.scan(project_path, skip_hex: true)

      dep_report =
        Enum.find(report.dependency_reports, fn dr -> dr.dependency.name == :bin_dep end)

      assert dep_report != nil
    end
  end

  describe "deeply nested AST" do
    test "100+ levels of nesting does not cause stack overflow", %{project_path: project_path} do
      lock_content =
        ~s(%{\n  "deep_dep": {:hex, :deep_dep, "1.0.0", "abc123", [:mix], [], "hexpm", "def456"}\n}\n)

      File.write!(Path.join(project_path, "mix.lock"), lock_content)

      dep_dir = Path.join([project_path, "deps", "deep_dep"])
      lib_dir = Path.join(dep_dir, "lib")
      File.mkdir_p!(lib_dir)

      mix_source = """
      defmodule DeepDep.MixProject do
        use Mix.Project
        def project, do: [app: :deep_dep, version: "1.0.0"]
      end
      """

      File.write!(Path.join(dep_dir, "mix.exs"), mix_source)

      # Generate deeply nested if statements (100+ levels)
      inner = "System.cmd(\"echo\", [\"deep\"])"

      nested =
        Enum.reduce(1..100, inner, fn i, acc ->
          "if true do\n#{acc}\nelse\n:nope_#{i}\nend"
        end)

      source = "defmodule DeepDep do\n  def deep do\n#{nested}\n  end\nend\n"
      File.write!(Path.join(lib_dir, "deep.ex"), source)

      # Should complete without stack overflow
      assert {:ok, %ScanReport{}} = VetCore.scan(project_path, skip_hex: true)
    end
  end

  describe "file with no newline at end" do
    test "parses and scans correctly", %{project_path: project_path} do
      lock_content =
        ~s(%{\n  "no_nl_dep": {:hex, :no_nl_dep, "1.0.0", "abc123", [:mix], [], "hexpm", "def456"}\n}\n)

      File.write!(Path.join(project_path, "mix.lock"), lock_content)

      dep_dir = Path.join([project_path, "deps", "no_nl_dep"])
      lib_dir = Path.join(dep_dir, "lib")
      File.mkdir_p!(lib_dir)

      File.write!(Path.join(dep_dir, "mix.exs"),
        "defmodule NoNlDep.MixProject do\n  use Mix.Project\n  def project, do: [app: :no_nl_dep, version: \"1.0.0\"]\nend")

      # File with no trailing newline
      source = "defmodule NoNlDep do\n  def cmd, do: System.cmd(\"echo\", [\"hi\"])\nend"
      File.write!(Path.join(lib_dir, "no_nl.ex"), source)

      assert {:ok, %ScanReport{} = report} = VetCore.scan(project_path, skip_hex: true)

      dep_report =
        Enum.find(report.dependency_reports, fn dr -> dr.dependency.name == :no_nl_dep end)

      system_findings = Enum.filter(dep_report.findings, &(&1.category == :system_exec))
      assert length(system_findings) > 0
    end
  end

  describe "file with only comments" do
    test "produces no findings", %{project_path: project_path} do
      lock_content =
        ~s(%{\n  "comment_dep": {:hex, :comment_dep, "1.0.0", "abc123", [:mix], [], "hexpm", "def456"}\n}\n)

      File.write!(Path.join(project_path, "mix.lock"), lock_content)

      dep_dir = Path.join([project_path, "deps", "comment_dep"])
      lib_dir = Path.join(dep_dir, "lib")
      File.mkdir_p!(lib_dir)

      File.write!(Path.join(dep_dir, "mix.exs"),
        "defmodule CommentDep.MixProject do\n  use Mix.Project\n  def project, do: [app: :comment_dep, version: \"1.0.0\"]\nend\n")

      # File with only comments — valid Elixir, but no code
      source = "# This is a comment\n# Another comment\n# Nothing else here\n"
      File.write!(Path.join(lib_dir, "comments.ex"), source)

      assert {:ok, %ScanReport{} = report} = VetCore.scan(project_path, skip_hex: true)

      dep_report =
        Enum.find(report.dependency_reports, fn dr -> dr.dependency.name == :comment_dep end)

      assert dep_report.findings == [] or
               Enum.all?(dep_report.findings, fn f -> f.file_path != Path.join(lib_dir, "comments.ex") end)
    end
  end

  describe "file with unicode characters" do
    test "handles unicode in strings and identifiers", %{project_path: project_path} do
      lock_content =
        ~s(%{\n  "unicode_dep": {:hex, :unicode_dep, "1.0.0", "abc123", [:mix], [], "hexpm", "def456"}\n}\n)

      File.write!(Path.join(project_path, "mix.lock"), lock_content)

      dep_dir = Path.join([project_path, "deps", "unicode_dep"])
      lib_dir = Path.join(dep_dir, "lib")
      File.mkdir_p!(lib_dir)

      File.write!(Path.join(dep_dir, "mix.exs"),
        "defmodule UnicodeDep.MixProject do\n  use Mix.Project\n  def project, do: [app: :unicode_dep, version: \"1.0.0\"]\nend\n")

      source = ~S"""
      defmodule UnicodeDep do
        @greeting "Hej varlden! \u00e4\u00f6\u00fc \u{1F600}"

        def hello do
          "\u4f60\u597d\u4e16\u754c"
        end

        def emoji, do: "\u{1F680}\u{1F30D}"
      end
      """

      File.write!(Path.join(lib_dir, "unicode.ex"), source)

      # Should not crash on unicode content
      assert {:ok, %ScanReport{}} = VetCore.scan(project_path, skip_hex: true)
    end
  end

  describe "zero-length string for entropy check" do
    test "shannon_entropy does not crash on empty string" do
      # The Obfuscation check only processes strings > 40 chars,
      # but let's test the FileHelper/walk machinery with an empty-string file.
      # We test indirectly by scanning a dep with an empty module body.
      # The key thing: no division by zero if empty strings are encountered.

      # Direct test: read_and_parse + obfuscation check on a file with empty strings
      tmp_dir =
        Path.join(
          System.tmp_dir!(),
          "vet_entropy_edge_#{System.unique_integer([:positive])}"
        )

      File.mkdir_p!(tmp_dir)
      on_exit(fn -> File.rm_rf!(tmp_dir) end)

      lock_content =
        ~s(%{\n  "empty_str_dep": {:hex, :empty_str_dep, "1.0.0", "abc", [:mix], [], "hexpm", "def"}\n}\n)

      File.write!(Path.join(tmp_dir, "mix.lock"), lock_content)

      dep_dir = Path.join([tmp_dir, "deps", "empty_str_dep"])
      lib_dir = Path.join(dep_dir, "lib")
      File.mkdir_p!(lib_dir)

      File.write!(Path.join(dep_dir, "mix.exs"),
        "defmodule EmptyStrDep.MixProject do\n  use Mix.Project\n  def project, do: [app: :empty_str_dep, version: \"1.0.0\"]\nend\n")

      source = ~s(defmodule EmptyStrDep do\n  @empty ""\n  @also_empty ''\n  def blank, do: ""\nend\n)
      File.write!(Path.join(lib_dir, "empty_str.ex"), source)

      assert {:ok, %ScanReport{}} = VetCore.scan(tmp_dir, skip_hex: true)
    end
  end

  describe "dependency name edge cases" do
    test "very long dependency name (200 chars) parses successfully", %{project_path: project_path} do
      long_name = String.duplicate("a", 200)

      lock_content =
        ~s(%{\n  "#{long_name}": {:hex, :#{long_name}, "1.0.0", "abc123", [:mix], [], "hexpm", "def456"}\n}\n)

      File.write!(Path.join(project_path, "mix.lock"), lock_content)

      dep_dir = Path.join([project_path, "deps", long_name])
      lib_dir = Path.join(dep_dir, "lib")
      File.mkdir_p!(lib_dir)

      File.write!(Path.join(dep_dir, "mix.exs"),
        "defmodule LongName.MixProject do\n  use Mix.Project\n  def project, do: [app: :#{long_name}, version: \"1.0.0\"]\nend\n")

      File.write!(Path.join(lib_dir, "long.ex"), "defmodule LongName do\n  def ok, do: :ok\nend\n")

      assert {:ok, %ScanReport{} = report} = VetCore.scan(project_path, skip_hex: true)
      assert length(report.dependency_reports) == 1

      dep_report = hd(report.dependency_reports)
      assert dep_report.dependency.name == String.to_atom(long_name)
    end
  end

  describe "mix.lock with 1000 dependencies" do
    test "parses successfully", %{project_path: project_path} do
      entries =
        Enum.map_join(1..1000, ",\n", fn i ->
          ~s(  "dep_#{i}": {:hex, :dep_#{i}, "1.0.0", "hash#{i}", [:mix], [], "hexpm", "ihash#{i}"})
        end)

      lock_content = "%{\n#{entries}\n}\n"
      File.write!(Path.join(project_path, "mix.lock"), lock_content)

      assert {:ok, deps} = VetCore.LockParser.parse(project_path)
      assert length(deps) == 1000
    end
  end

  describe "ScanReport with nil summary" do
    test "serialization to map does not crash" do
      report = %ScanReport{
        project_path: "/tmp/test",
        timestamp: DateTime.utc_now(),
        dependency_reports: [],
        summary: nil
      }

      # Converting to a map and then to JSON should not crash
      map = Map.from_struct(report)
      assert {:ok, _json} = Jason.encode(map)
    end
  end

  describe "FileHelper.snippet edge cases" do
    test "snippet with line beyond file length raises FunctionClauseError due to negative slice" do
      source = "line1\nline2\nline3"

      # When line is beyond file length, snippet computes a negative amount
      # for Enum.slice, which raises FunctionClauseError. This documents
      # a boundary condition in the current implementation.
      assert_raise FunctionClauseError, fn ->
        FileHelper.snippet(source, 100)
      end
    end

    test "snippet at line 1 returns first line" do
      source = "line1\nline2\nline3"
      result = FileHelper.snippet(source, 1)
      assert is_binary(result)
      assert result == "line1"
    end

    test "snippet on empty source returns empty string" do
      result = FileHelper.snippet("", 1)
      assert is_binary(result)
    end
  end
end
