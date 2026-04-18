defmodule VetCore.Checks.BeamReflectionTest do
  use ExUnit.Case, async: false

  alias VetCore.Checks.BeamReflection
  alias VetCore.Types.Dependency

  setup do
    unique = System.unique_integer([:positive])
    tmp_dir = Path.join(System.tmp_dir!(), "vet_beam_reflection_test_#{unique}")
    ebin = Path.join([tmp_dir, "_build", "dev", "lib", "test_dep", "ebin"])
    File.mkdir_p!(ebin)
    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{tmp_dir: tmp_dir, ebin: ebin, unique: unique}
  end

  defp dep do
    %Dependency{name: :test_dep, version: "1.0.0", source: :hex}
  end

  defp compile_to(ebin, source, module_name) do
    [{^module_name, beam_bin}] = Code.compile_string(source)
    suffix = module_name |> Atom.to_string() |> String.replace_prefix("Elixir.", "")
    File.write!(Path.join(ebin, "#{suffix}.beam"), beam_bin)
  end

  defp run(tmp), do: BeamReflection.run(dep(), tmp, [])

  test "no findings when ebin is absent", %{tmp_dir: _tmp_dir} do
    other_tmp = Path.join(System.tmp_dir!(), "vet_no_ebin_#{System.unique_integer([:positive])}")
    File.mkdir_p!(other_tmp)
    on_exit(fn -> File.rm_rf!(other_tmp) end)

    assert run(other_tmp) == []
  end

  test "fires :reflection_handle_undefined when module exports it", %{
    tmp_dir: tmp,
    ebin: ebin,
    unique: u
  } do
    module = Module.concat([Vet.ReflectTest, "Sneaky#{u}"])

    source = """
    defmodule Vet.ReflectTest.Sneaky#{u} do
      def unquote(:"$handle_undefined_function")(name, args), do: {name, args}
    end
    """

    compile_to(ebin, source, module)

    findings = run(tmp)

    assert Enum.any?(findings, fn f ->
             f.check_id == :reflection_handle_undefined and f.severity == :critical
           end)
  end

  test "safe pure-data module fires no findings", %{tmp_dir: tmp, ebin: ebin, unique: u} do
    module = Module.concat([Vet.ReflectTest, "Pure#{u}"])

    source = """
    defmodule Vet.ReflectTest.Pure#{u} do
      def add(a, b), do: a + b
      def greet(n), do: "hi \#{n}"
    end
    """

    compile_to(ebin, source, module)

    findings = run(tmp)
    assert findings == []
  end

  test "single apply call below thresholds emits no density finding", %{
    tmp_dir: tmp,
    ebin: ebin,
    unique: u
  } do
    module = Module.concat([Vet.ReflectTest, "OneApply#{u}"])

    source = """
    defmodule Vet.ReflectTest.OneApply#{u} do
      def call(m, f, a), do: apply(m, f, a)
    end
    """

    compile_to(ebin, source, module)

    findings = run(tmp)

    # Below the warning threshold of 5 imports / 15 dispatch — the per-module
    # info noise is intentionally suppressed because every Elixir BEAM has
    # at least one apply call (GenServer, Plug, Phoenix all dispatch).
    refute Enum.any?(findings, fn f -> f.check_id == :reflection_density end)
  end

  test "fires :reflection_decode_and_dispatch when binary_to_term + apply present", %{
    tmp_dir: tmp,
    ebin: ebin,
    unique: u
  } do
    module = Module.concat([Vet.ReflectTest, "Decoder#{u}"])

    source = """
    defmodule Vet.ReflectTest.Decoder#{u} do
      def go(payload) do
        {m, f, a} = :erlang.binary_to_term(payload)
        apply(m, f, a)
      end
    end
    """

    compile_to(ebin, source, module)

    findings = run(tmp)

    assert Enum.any?(findings, fn f ->
             f.check_id == :reflection_decode_and_dispatch and f.severity == :critical and
               String.contains?(f.description, "binary_to_term")
           end)
  end

  test "fires :reflection_density (warning) when dispatch threshold crossed", %{
    tmp_dir: tmp,
    ebin: ebin,
    unique: u
  } do
    module = Module.concat([Vet.ReflectTest, "Heavy#{u}"])

    # Build a module with many fun.() calls to push the dispatch count over
    # the threshold (15 dispatch instructions).
    source = """
    defmodule Vet.ReflectTest.Heavy#{u} do
      def a(f), do: f.()
      def b(f), do: f.()
      def c(f), do: f.()
      def d(f), do: f.()
      def e(f), do: f.()
      def g(f), do: f.()
      def h(f), do: f.()
      def i(f), do: f.()
      def j(f), do: f.()
      def k(f), do: f.()
      def l(f), do: f.()
      def m(f), do: f.()
      def n(f), do: f.()
      def o(f), do: f.()
      def p(f), do: f.()
      def q(f), do: f.()
    end
    """

    compile_to(ebin, source, module)

    findings = run(tmp)

    density = Enum.find(findings, fn f -> f.check_id == :reflection_density end)
    assert density != nil
    assert density.severity in [:warning, :critical]
    assert String.contains?(density.description, "dispatch")
  end

  test "fires :reflection_density (critical) when both density thresholds crossed",
       %{tmp_dir: tmp, ebin: ebin, unique: u} do
    module = Module.concat([Vet.ReflectTest, "BothHeavy#{u}"])

    source = """
    defmodule Vet.ReflectTest.BothHeavy#{u} do
      def a(s), do: String.to_atom(s)
      def b(s), do: String.to_existing_atom(s)
      def c(b), do: :erlang.binary_to_atom(b, :utf8)
      def d(b), do: :erlang.binary_to_term(b)
      def e(m, f, a), do: apply(m, f, a)
      def f(b), do: :erlang.binary_to_existing_atom(b, :utf8)
      def go(f), do: f.()
      def go2(f), do: f.()
      def go3(f), do: f.()
      def go4(f), do: f.()
      def go5(f), do: f.()
      def go6(f), do: f.()
      def go7(f), do: f.()
      def go8(f), do: f.()
      def go9(f), do: f.()
      def go10(f), do: f.()
      def go11(f), do: f.()
      def go12(f), do: f.()
      def go13(f), do: f.()
      def go14(f), do: f.()
      def go15(f), do: f.()
    end
    """

    compile_to(ebin, source, module)

    findings = run(tmp)

    density = Enum.find(findings, fn f -> f.check_id == :reflection_density end)
    assert density != nil
    assert density.severity == :critical
  end
end
