defmodule VetCore.Checks.NativeCode do
  @moduledoc """
  Layer 5 — Native code surface detection.

  NIFs and port drivers are a complete bypass of every other Vet layer:

  - NIFs run in the BEAM scheduler thread with no OS isolation.
  - A NIF crash takes down the entire VM.
  - NIF binaries are opaque to bytecode analysis (they're machine code).
  - Native build steps run during `mix deps.compile`, often with the same
    privileges as the developer's shell.

  Signals fired:

  - `priv/**/*.so`, `*.dylib`, `*.dll` shipped — pre-compiled NIF artifacts.
  - `c_src/`, `native/` directories — C/Rust/Zig source compiled during install.
  - `Makefile`, `CMakeLists.txt`, `build.zig`, `Cargo.toml` at the project root —
    build-system manifests.
  - Mix project's `:compilers` list includes `:elixir_make` or `:rustler`.
  - Any compiled BEAM imports `:erlang.load_nif/2`.

  This check runs against the unpacked dep directory (`deps/<name>/`) and any
  compiled artifacts in `_build/<env>/lib/<name>/` and `priv/`.
  """
  use VetCore.Check

  alias VetCore.BEAM.BeamProfile
  alias VetCore.Types.Finding

  @category :native_code

  @native_extensions [".so", ".dylib", ".dll"]
  @build_files ~w(Makefile makefile GNUmakefile CMakeLists.txt build.zig Cargo.toml)
  @native_source_dirs ~w(c_src native rust src_c)

  @impl true
  def run(%{name: dep_name} = _dep, project_path, _state) do
    dep_dir = Path.join([project_path, "deps", to_string(dep_name)])

    findings =
      if File.dir?(dep_dir) do
        priv_artifact_findings(dep_dir, dep_name) ++
          native_source_findings(dep_dir, dep_name) ++
          build_file_findings(dep_dir, dep_name) ++
          mix_compilers_findings(dep_dir, dep_name)
      else
        []
      end

    findings ++ load_nif_findings(dep_name, project_path)
  end

  # --- Internals -------------------------------------------------------------

  defp priv_artifact_findings(dep_dir, dep_name) do
    priv = Path.join(dep_dir, "priv")

    if File.dir?(priv) do
      priv
      |> Path.join("**/*")
      |> Path.wildcard()
      |> Enum.filter(&native_artifact?/1)
      |> Enum.map(fn path ->
        %Finding{
          dep_name: dep_name,
          file_path: path,
          line: 1,
          check_id: :native_code_artifact,
          category: @category,
          severity: :critical,
          compile_time?: false,
          description:
            "Pre-compiled native artifact shipped at #{Path.relative_to(path, dep_dir)} — " <>
              "machine code that runs in the BEAM scheduler with no OS isolation; " <>
              "opaque to bytecode analysis"
        }
      end)
    else
      []
    end
  end

  defp native_artifact?(path) do
    File.regular?(path) and Path.extname(path) in @native_extensions
  end

  defp native_source_findings(dep_dir, dep_name) do
    @native_source_dirs
    |> Enum.flat_map(fn dir ->
      full = Path.join(dep_dir, dir)
      if File.dir?(full), do: [{dir, full}], else: []
    end)
    |> Enum.map(fn {dir, full} ->
      %Finding{
        dep_name: dep_name,
        file_path: full,
        line: 1,
        check_id: :native_code_source,
        category: @category,
        severity: :warning,
        compile_time?: true,
        description:
          "Native-code source directory #{dir}/ present — " <>
            "package compiles native code during `mix deps.compile`, " <>
            "running build tools with the developer's shell privileges"
      }
    end)
  end

  defp build_file_findings(dep_dir, dep_name) do
    @build_files
    |> Enum.flat_map(fn name ->
      full = Path.join(dep_dir, name)
      if File.regular?(full), do: [{name, full}], else: []
    end)
    |> Enum.map(fn {name, full} ->
      %Finding{
        dep_name: dep_name,
        file_path: full,
        line: 1,
        check_id: :native_code_build_file,
        category: @category,
        severity: :warning,
        compile_time?: true,
        description:
          "Native build file #{name} at the package root — " <>
            "indicates a non-Elixir build step runs during install"
      }
    end)
  end

  defp mix_compilers_findings(dep_dir, dep_name) do
    mix_path = Path.join(dep_dir, "mix.exs")

    if File.regular?(mix_path) do
      case File.read(mix_path) do
        {:ok, source} ->
          Enum.flat_map([:elixir_make, :rustler], fn compiler ->
            if compilers_contains?(source, compiler) do
              [
                %Finding{
                  dep_name: dep_name,
                  file_path: mix_path,
                  line: 1,
                  check_id: :native_code_compiler,
                  category: @category,
                  severity: :warning,
                  compile_time?: true,
                  description:
                    "mix.exs declares compiler #{inspect(compiler)} — " <>
                      "package builds native code during compile (NIF or port driver)"
                }
              ]
            else
              []
            end
          end)

        _ ->
          []
      end
    else
      []
    end
  end

  defp compilers_contains?(source, compiler) do
    # Conservative substring check — looks for the atom literal in the
    # compilers list. If the user has it spelled differently (e.g. behind
    # a variable) we miss it, but the artifact/source/build-file checks
    # would still catch a real native package.
    String.contains?(source, ":#{compiler}")
  end

  defp load_nif_findings(dep_name, project_path) do
    ebin_dirs(dep_name, project_path)
    |> Enum.flat_map(&BeamProfile.build_all/1)
    |> Enum.flat_map(fn profile ->
      if loads_nif?(profile) do
        [
          %Finding{
            dep_name: dep_name,
            file_path: profile.path,
            line: 1,
            check_id: :native_code_load_nif,
            category: @category,
            severity: :critical,
            compile_time?: false,
            description:
              "BEAM #{inspect(profile.module)} imports :erlang.load_nif/2 — " <>
                "module loads native code at runtime; the loaded binary " <>
                "can execute arbitrary machine code in the BEAM process"
          }
        ]
      else
        []
      end
    end)
  end

  defp loads_nif?(%BeamProfile{imports: imports}) do
    Enum.any?(imports, fn
      {:erlang, :load_nif, 2} -> true
      _ -> false
    end)
  end

  defp ebin_dirs(dep_name, project_path) do
    name = to_string(dep_name)

    [project_path, "_build", "*", "lib", name, "ebin"]
    |> Path.join()
    |> Path.wildcard()
    |> Enum.filter(&File.dir?/1)
  end
end
