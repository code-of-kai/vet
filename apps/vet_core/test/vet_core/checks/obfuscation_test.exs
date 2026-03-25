defmodule VetCore.Checks.ObfuscationTest do
  use ExUnit.Case

  alias VetCore.Checks.Obfuscation
  alias VetCore.Types.Dependency

  setup do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_obfuscation_test_#{:erlang.unique_integer([:positive])}")
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.mkdir_p!(dep_dir)

    on_exit(fn -> File.rm_rf!(tmp_dir) end)

    %{tmp_dir: tmp_dir, dep_dir: dep_dir}
  end

  defp run_check(tmp_dir, source) do
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.write!(Path.join(dep_dir, "module.ex"), source)

    dep = %Dependency{name: :test_dep, version: "1.0.0", source: :hex}
    state = Obfuscation.init([])
    Obfuscation.run(dep, tmp_dir, state)
  end

  test "Base.decode64 + Code.eval_string in same scope is detected", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def run do
        {:ok, decoded} = Base.decode64("c29tZSBjb2Rl")
        Code.eval_string(decoded)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    decode_eval_findings =
      Enum.filter(findings, &(&1.check_id == :obfuscation_decode_eval))

    assert length(decode_eval_findings) >= 1
    finding = hd(decode_eval_findings)
    assert finding.severity == :critical
    assert finding.description =~ "Base.decode64"
    assert finding.description =~ "Code.eval_string"
  end

  test "high-entropy string (random bytes) is detected", %{tmp_dir: tmp_dir} do
    # Use a deterministic high-entropy string (all 256 byte values cycling) that
    # exceeds the 5.5 Shannon entropy threshold and is > 40 chars.
    # Build a string with all printable ASCII chars cycling to maximize entropy.
    high_entropy_bytes =
      Enum.to_list(33..126)
      |> List.duplicate(3)
      |> List.flatten()
      |> Enum.take(200)
      |> :binary.list_to_bin()

    # Escape for embedding in Elixir source as a string
    escaped = String.replace(high_entropy_bytes, "\\", "\\\\") |> String.replace("\"", "\\\"")

    source = """
    defmodule TestMod do
      @payload "#{escaped}"
      def run, do: @payload
    end
    """

    findings = run_check(tmp_dir, source)

    entropy_findings =
      Enum.filter(findings, &(&1.check_id == :obfuscation_entropy))

    assert length(entropy_findings) >= 1
    assert hd(entropy_findings).description =~ "High-entropy string"
  end

  test "normal strings are not flagged (baseline)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      @doc "This is a normal documentation string for the module."
      def hello, do: "Hello, world!"
      def greeting, do: "Good morning, how are you today?"
    end
    """

    findings = run_check(tmp_dir, source)

    entropy_findings =
      Enum.filter(findings, &(&1.check_id == :obfuscation_entropy))

    assert entropy_findings == []
  end

  test "dynamic apply/3 with variable module is detected", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def run(mod, func) do
        apply(mod, func, [])
      end
    end
    """

    findings = run_check(tmp_dir, source)

    apply_findings =
      Enum.filter(findings, &(&1.check_id == :obfuscation_dynamic_apply))

    assert length(apply_findings) >= 1
    assert hd(apply_findings).description =~ "Dynamic apply"
  end

  test "apply(SomeModule, :func, []) with literal atoms is NOT detected (baseline)", %{tmp_dir: tmp_dir} do
    # In AST, `String` is {:__aliases__, _, [:String]} not a bare atom,
    # so we use bare erlang-style atoms like :lists to test the "both atoms" path
    source = """
    defmodule TestMod do
      def run do
        apply(:lists, :reverse, [[1, 2, 3]])
      end
    end
    """

    findings = run_check(tmp_dir, source)

    apply_findings =
      Enum.filter(findings, &(&1.check_id == :obfuscation_dynamic_apply))

    assert apply_findings == []
  end

  test "no false positives on completely benign code (baseline)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule SafeMod do
      def hello, do: :world
      def add(a, b), do: a + b
    end
    """

    findings = run_check(tmp_dir, source)

    assert findings == []
  end
end
