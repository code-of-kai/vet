defmodule VetCore.BEAM.BeamProfileTest do
  use ExUnit.Case, async: false

  alias VetCore.BEAM.BeamProfile

  setup do
    unique = System.unique_integer([:positive])
    tmp_dir = Path.join(System.tmp_dir!(), "vet_beam_profile_test_#{unique}")
    File.mkdir_p!(tmp_dir)
    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{tmp_dir: tmp_dir, unique: unique}
  end

  defp compile_and_write(source, module_name, tmp_dir) do
    [{^module_name, beam_bin}] = Code.compile_string(source)
    path = Path.join(tmp_dir, "#{module_name_suffix(module_name)}.beam")
    File.write!(path, beam_bin)
    path
  end

  defp module_name_suffix(module_atom) do
    module_atom
    |> Atom.to_string()
    |> String.replace_prefix("Elixir.", "")
  end

  test "builds a profile from a simple module", %{tmp_dir: tmp_dir, unique: u} do
    module_name = Module.concat([Vet.BeamTest, "Simple#{u}"])

    source = """
    defmodule Vet.BeamTest.Simple#{u} do
      def hello, do: :world
    end
    """

    path = compile_and_write(source, module_name, tmp_dir)

    assert {:ok, profile} = BeamProfile.build(path)
    assert profile.module == module_name
    assert profile.path == path
    assert is_list(profile.imports)
    assert is_list(profile.exports)
    assert {:hello, 0} in profile.exports
    assert profile.dynamic_dispatch_count == 0
    assert profile.handle_undefined_function? == false
  end

  test "detects :ssh import in the imports table", %{tmp_dir: tmp_dir, unique: u} do
    module_name = Module.concat([Vet.BeamTest, "SshUser#{u}"])

    source = """
    defmodule Vet.BeamTest.SshUser#{u} do
      def connect(host, port) do
        :ssh.connect(host, port, [])
      end
    end
    """

    path = compile_and_write(source, module_name, tmp_dir)
    {:ok, profile} = BeamProfile.build(path)

    ssh_imports = Enum.filter(profile.imports, fn {m, _f, _a} -> m == :ssh end)
    assert ssh_imports != []
  end

  test "sees through defdelegate — target appears in imports", %{tmp_dir: tmp_dir, unique: u} do
    module_name = Module.concat([Vet.BeamTest, "Delegator#{u}"])

    source = """
    defmodule Vet.BeamTest.Delegator#{u} do
      defdelegate connect(a, b, c), to: :ssh
    end
    """

    path = compile_and_write(source, module_name, tmp_dir)
    {:ok, profile} = BeamProfile.build(path)

    assert {:ssh, :connect, 3} in profile.imports
  end

  test "counts dynamic dispatch instructions", %{tmp_dir: tmp_dir, unique: u} do
    module_name = Module.concat([Vet.BeamTest, "Applier#{u}"])

    source = """
    defmodule Vet.BeamTest.Applier#{u} do
      def run(mod, fun, args), do: apply(mod, fun, args)
      def run_fun(f, x), do: f.(x)
    end
    """

    path = compile_and_write(source, module_name, tmp_dir)
    {:ok, profile} = BeamProfile.build(path)

    assert profile.dynamic_dispatch_count > 0
  end

  test "flags $handle_undefined_function/2 export", %{tmp_dir: tmp_dir, unique: u} do
    module_name = Module.concat([Vet.BeamTest, "Sneaky#{u}"])

    source = """
    defmodule Vet.BeamTest.Sneaky#{u} do
      def unquote(:"$handle_undefined_function")(name, args) do
        {:handled, name, args}
      end
    end
    """

    path = compile_and_write(source, module_name, tmp_dir)
    {:ok, profile} = BeamProfile.build(path)

    assert profile.handle_undefined_function? == true
  end

  test "content_hash is stable and sensitive to imports", %{tmp_dir: tmp_dir, unique: u} do
    # Same source compiled twice must produce the same content hash even
    # though the on-disk binaries may differ in metadata.
    base_source = fn suffix ->
      module = "Vet.BeamTest.Hashable#{u}_#{suffix}"

      """
      defmodule #{module} do
        def run, do: :ok
      end
      """
    end

    a_source = base_source.("a")
    b_source = base_source.("b")

    # Rename module so atoms differ, but structure is the same.
    a_module = Module.concat([Vet.BeamTest, "Hashable#{u}_a"])
    b_module = Module.concat([Vet.BeamTest, "Hashable#{u}_b"])

    a_path = compile_and_write(a_source, a_module, tmp_dir)
    b_path = compile_and_write(b_source, b_module, tmp_dir)

    {:ok, a_profile} = BeamProfile.build(a_path)
    {:ok, b_profile} = BeamProfile.build(b_path)

    # Different module names → different atoms in atom table → different hash.
    refute BeamProfile.content_hash(a_profile) == BeamProfile.content_hash(b_profile)

    # Same profile twice → same hash.
    assert BeamProfile.content_hash(a_profile) == BeamProfile.content_hash(a_profile)
  end

  test "suspicious_atoms classifies URL/IP/hostname atoms" do
    profile = %BeamProfile{
      module: Foo,
      path: "<test>",
      atoms: [
        :"http://example.com",
        :"https://attacker.test/beacon",
        :"1.2.3.4",
        :"c2.attacker.com",
        :safe_atom,
        :ok,
        :error,
        :Elixir,
        :"192.0.2.1"
      ]
    }

    suspicious = BeamProfile.suspicious_atoms(profile)

    assert :"http://example.com" in suspicious
    assert :"https://attacker.test/beacon" in suspicious
    assert :"1.2.3.4" in suspicious
    assert :"192.0.2.1" in suspicious
    assert :"c2.attacker.com" in suspicious
    refute :safe_atom in suspicious
    refute :ok in suspicious
    refute :error in suspicious
    refute :Elixir in suspicious
  end

  test "build/1 returns error for a non-BEAM file", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "not_a_beam.txt")
    File.write!(path, "hello")

    assert {:error, _} = BeamProfile.build(path)
  end

  test "build_all/1 loads every .beam in a directory", %{tmp_dir: tmp_dir, unique: u} do
    m1 = Module.concat([Vet.BeamTest, "Dir1_#{u}"])
    m2 = Module.concat([Vet.BeamTest, "Dir2_#{u}"])
    s1 = "defmodule Vet.BeamTest.Dir1_#{u} do\n  def a, do: 1\nend"
    s2 = "defmodule Vet.BeamTest.Dir2_#{u} do\n  def b, do: 2\nend"

    compile_and_write(s1, m1, tmp_dir)
    compile_and_write(s2, m2, tmp_dir)

    profiles = BeamProfile.build_all(tmp_dir)
    assert length(profiles) == 2
    modules = Enum.map(profiles, & &1.module)
    assert m1 in modules
    assert m2 in modules
  end
end
