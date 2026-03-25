defmodule VetCore.Blackhat.EvasionVectorsTest do
  @moduledoc """
  Black hat tests for specific evasion vectors discovered by studying Dune, Sobelow,
  and Rewire. Each test creates a minimal temp fixture with the evasion pattern, runs
  the relevant check(s), and asserts whether Vet detects it or documents a known gap.

  Tests tagged with `@tag :known_gap` represent vectors we currently CANNOT detect.
  They assert `findings == []` so they will break (and alert us) if we later add
  detection — at which point we promote them to real assertions.
  """
  use ExUnit.Case, async: true

  alias VetCore.Checks.{SystemExec, CodeEval, FileAccess, Obfuscation}
  alias VetCore.Types.Dependency

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp setup_dep(dep_name, source_files) do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_evasion_#{System.unique_integer([:positive])}")
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
  # 1. Capture operator bypass: &Code.eval_string/1 stored and called
  # ---------------------------------------------------------------------------

  describe "capture operator bypass" do
    setup do
      source = ~S"""
      defmodule Evasion.CaptureOperator do
        def run(input) do
          evaluator = &Code.eval_string/1
          evaluator.(input)
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:evasion_capture_op, [{"capture_op.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "detects Code.eval_string inside capture operator", %{project_path: path, dep: dep} do
      # The & operator's AST still contains the {:., _, [{:__aliases__, _, [:Code]}, :eval_string]}
      # node, so the CodeEval check matches it despite the indirection.
      findings = CodeEval.run(dep, path, [])
      eval_findings = Enum.filter(findings, &(&1.check_id == :code_eval))
      assert length(eval_findings) >= 1
    end
  end

  # ---------------------------------------------------------------------------
  # 2. Pipe-through-restricted: "whoami" |> System.cmd([])
  # ---------------------------------------------------------------------------

  describe "pipe-through-restricted" do
    setup do
      source = ~S"""
      defmodule Evasion.PipeThrough do
        def run do
          "whoami" |> System.cmd([])
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:evasion_pipe, [{"pipe_through.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "detects System.cmd through pipe operator", %{project_path: path, dep: dep} do
      # The pipe rewrites the AST but System.cmd still appears as a dot-call node.
      # The walker visits all nodes including children of |>, so the match fires.
      findings = SystemExec.run(dep, path, [])
      exec_findings = Enum.filter(findings, &(&1.check_id == :system_exec))
      assert length(exec_findings) >= 1
    end
  end

  # ---------------------------------------------------------------------------
  # 3. Dynamic dispatch via variable: mod = System; mod.cmd("whoami", [])
  # ---------------------------------------------------------------------------

  describe "dynamic dispatch via variable" do
    @tag :known_gap
    setup do
      source = ~S"""
      defmodule Evasion.DynamicDispatch do
        def run do
          mod = System
          mod.cmd("whoami", [])
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:evasion_dynamic_dispatch, [{"dynamic_dispatch.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    @tag :known_gap
    test "KNOWN GAP: variable module reference evades SystemExec",
         %{project_path: path, dep: dep} do
      # mod.cmd("whoami", []) parses as a dot-call on the variable `mod`, not on
      # {:__aliases__, _, [:System]}. Without data-flow analysis, we cannot resolve
      # the variable to its literal value.
      findings = SystemExec.run(dep, path, [])
      exec_findings = Enum.filter(findings, &(&1.check_id == :system_exec))
      assert exec_findings == []
    end
  end

  # ---------------------------------------------------------------------------
  # 4. Import-then-bare-call: import System; cmd("whoami", [])
  # ---------------------------------------------------------------------------

  describe "import-then-bare-call" do
    @tag :known_gap
    setup do
      source = ~S"""
      defmodule Evasion.ImportBareCall do
        import System
        def run do
          cmd("whoami", [])
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:evasion_import_bare, [{"import_bare.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    @tag :known_gap
    test "KNOWN GAP: imported bare cmd() call evades SystemExec",
         %{project_path: path, dep: dep} do
      # After `import System`, the call `cmd("whoami", [])` has no module prefix
      # in the AST — it appears as {:cmd, meta, args} rather than a dot-call on
      # System. Would require import tracking to detect.
      findings = SystemExec.run(dep, path, [])
      exec_findings = Enum.filter(findings, &(&1.check_id == :system_exec))
      assert exec_findings == []
    end
  end

  # ---------------------------------------------------------------------------
  # 5. EEx.eval_string: separate code execution vector
  # ---------------------------------------------------------------------------

  describe "EEx.eval_string code execution" do
    @tag :known_gap
    setup do
      source = ~S"""
      defmodule Evasion.EExEval do
        def run do
          EEx.eval_string("<%= System.cmd(\"whoami\", []) %>")
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:evasion_eex, [{"eex_eval.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    @tag :known_gap
    test "KNOWN GAP: EEx.eval_string is not covered by CodeEval",
         %{project_path: path, dep: dep} do
      # CodeEval only matches Code.eval_string, Code.eval_quoted, Code.eval_file,
      # Code.compile_string, Code.compile_quoted, and :erlang.binary_to_term.
      # EEx.eval_string is a separate code execution vector that compiles and
      # evaluates EEx templates — not currently tracked.
      findings = CodeEval.run(dep, path, [])
      eval_findings = Enum.filter(findings, &(&1.check_id == :code_eval))
      assert eval_findings == []
    end
  end

  # ---------------------------------------------------------------------------
  # 6. Atom exhaustion DoS: String.to_atom(input)
  # ---------------------------------------------------------------------------

  describe "atom exhaustion DoS" do
    @tag :known_gap
    setup do
      source = ~S"""
      defmodule Evasion.AtomExhaustion do
        def handle(input) do
          key = String.to_atom(input)
          Map.get(%{}, key)
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:evasion_atom_dos, [{"atom_dos.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    @tag :known_gap
    test "KNOWN GAP: String.to_atom not detected (no DoS check exists)",
         %{project_path: path, dep: dep} do
      # Sobelow flags String.to_atom(user_input) as a denial-of-service vector
      # because atoms are never garbage collected. Vet has no DoS category or
      # check for this pattern yet.
      # Run all available checks to confirm nothing catches it.
      all_findings =
        SystemExec.run(dep, path, []) ++
          CodeEval.run(dep, path, []) ++
          FileAccess.run(dep, path, []) ++
          Obfuscation.run(dep, path, [])

      assert all_findings == []
    end
  end

  # ---------------------------------------------------------------------------
  # 7. binary_to_term with :safe option — still can deserialize functions
  # ---------------------------------------------------------------------------

  describe "binary_to_term with :safe option" do
    setup do
      source = ~S"""
      defmodule Evasion.BinaryToTermSafe do
        def deserialize(data) do
          :erlang.binary_to_term(data, [:safe])
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:evasion_btt_safe, [{"btt_safe.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "detects :erlang.binary_to_term even with :safe option",
         %{project_path: path, dep: dep} do
      # The :safe option only prevents creation of NEW atoms, but still allows
      # deserialization of anonymous functions and other dangerous terms.
      # CodeEval correctly flags any call to :erlang.binary_to_term regardless
      # of options.
      findings = CodeEval.run(dep, path, [])
      btt_findings = Enum.filter(findings, &(&1.check_id == :code_eval))
      assert length(btt_findings) >= 1
      assert Enum.any?(btt_findings, &String.contains?(&1.description, "binary_to_term"))
    end
  end

  # ---------------------------------------------------------------------------
  # 8. Double-arg file exfiltration: File.cp("~/.ssh/id_rsa", "/tmp/exfil")
  # ---------------------------------------------------------------------------

  describe "double-arg file exfiltration" do
    setup do
      source = ~S"""
      defmodule Evasion.FileCopy do
        def exfil do
          File.cp("~/.ssh/id_rsa", "/tmp/exfil")
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:evasion_file_cp, [{"file_cp.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "detects File.cp with sensitive source path", %{project_path: path, dep: dep} do
      # FileAccess checks File.cp (it's in @file_functions) and args_contain_sensitive_path?
      # scans all arguments, so the first arg "~/.ssh/id_rsa" triggers :critical severity.
      findings = FileAccess.run(dep, path, [])
      file_findings = Enum.filter(findings, &(&1.check_id == :file_access))
      assert length(file_findings) >= 1
      assert Enum.any?(file_findings, &(&1.severity == :critical))
    end
  end

  # ---------------------------------------------------------------------------
  # 9. Alias obfuscation: alias Code, as: C; C.eval_string("dangerous")
  # ---------------------------------------------------------------------------

  describe "alias obfuscation" do
    @tag :known_gap
    setup do
      source = ~S"""
      defmodule Evasion.AliasObfuscation do
        alias Code, as: C

        def run do
          C.eval_string("dangerous")
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:evasion_alias, [{"alias_obfuscation.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    @tag :known_gap
    test "KNOWN GAP: aliased module C evades CodeEval",
         %{project_path: path, dep: dep} do
      # `alias Code, as: C` causes `C.eval_string(...)` to parse with
      # {:__aliases__, _, [:C]} instead of [:Code]. Without alias resolution,
      # CodeEval's pattern match on [:Code] never fires.
      findings = CodeEval.run(dep, path, [])
      eval_findings = Enum.filter(findings, &(&1.check_id == :code_eval))
      assert eval_findings == []
    end
  end

  # ---------------------------------------------------------------------------
  # 10. Nested function reference: fun = &System.cmd/2; fun.("whoami", [])
  # ---------------------------------------------------------------------------

  describe "nested function reference" do
    setup do
      source = ~S"""
      defmodule Evasion.NestedFunRef do
        def run do
          fun = &System.cmd/2
          fun.("whoami", [])
        end
      end
      """

      {tmp_dir, dep} = setup_dep(:evasion_nested_ref, [{"nested_ref.ex", source}])
      on_exit(fn -> cleanup(tmp_dir) end)
      %{project_path: tmp_dir, dep: dep}
    end

    test "detects System.cmd inside function reference capture",
         %{project_path: path, dep: dep} do
      # The &System.cmd/2 capture operator's AST contains the dot-call node
      # {{:., _, [{:__aliases__, _, [:System]}, :cmd]}, _, []} inside the & form.
      # The AST walker traverses into it and SystemExec's match fires.
      findings = SystemExec.run(dep, path, [])
      exec_findings = Enum.filter(findings, &(&1.check_id == :system_exec))
      assert length(exec_findings) >= 1
    end
  end
end
