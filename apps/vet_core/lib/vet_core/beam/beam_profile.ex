defmodule VetCore.BEAM.BeamProfile do
  @moduledoc """
  Snapshot of a single BEAM file's static structure. Produced by reading the
  `imports`, `exports`, `atoms`, `attributes`, and `compile_info` chunks via
  `:beam_lib.chunks/2`, plus a dynamic-dispatch instruction count from
  `:beam_disasm.file/1`.

  Source-level evasion mechanisms (defdelegate, atom-aliased module
  references, macro-synthesized calls, `.erl` files compiled to BEAM) all
  collapse at this layer because the BEAM has the literal call wired in
  regardless of how the source was spelled.
  """

  defstruct [
    :module,
    :path,
    imports: [],
    exports: [],
    atoms: [],
    attributes: %{},
    compile_info: %{},
    dynamic_dispatch_count: 0,
    handle_undefined_function?: false
  ]

  @type mfa_tuple :: {module(), atom(), non_neg_integer()}

  @type t :: %__MODULE__{
          module: atom() | nil,
          path: String.t(),
          imports: [mfa_tuple()],
          exports: [{atom(), non_neg_integer()}],
          atoms: [atom()],
          attributes: %{atom() => term()},
          compile_info: %{atom() => term()},
          dynamic_dispatch_count: non_neg_integer(),
          handle_undefined_function?: boolean()
        }

  @doc """
  Build a profile from a path to a `.beam` file.

  Returns `{:ok, profile}` or `{:error, reason}` if the file cannot be
  read or is not a valid BEAM module.
  """
  @spec build(String.t()) :: {:ok, t()} | {:error, term()}
  def build(beam_path) when is_binary(beam_path) do
    charlist = String.to_charlist(beam_path)

    with {:ok, chunk_data} <- read_chunks(charlist) do
      {:ok,
       %__MODULE__{
         module: chunk_data.module,
         path: beam_path,
         imports: chunk_data.imports,
         exports: chunk_data.exports,
         atoms: chunk_data.atoms,
         attributes: chunk_data.attributes,
         compile_info: chunk_data.compile_info,
         dynamic_dispatch_count: count_dynamic_dispatch(charlist),
         handle_undefined_function?: handle_undefined_function?(chunk_data.exports)
       }}
    end
  end

  @doc """
  Build profiles for every `.beam` in an `ebin` directory.
  """
  @spec build_all(String.t()) :: [t()]
  def build_all(ebin_dir) when is_binary(ebin_dir) do
    ebin_dir
    |> Path.join("*.beam")
    |> Path.wildcard()
    |> Enum.flat_map(fn path ->
      case build(path) do
        {:ok, profile} -> [profile]
        {:error, _} -> []
      end
    end)
  end

  @doc """
  Stable hash of the profile's content. Safe to use as a cache key across
  runs — based on sorted imports/exports/atoms/attributes and the dispatch
  counters, not on mutable metadata like the file path.
  """
  @spec content_hash(t()) :: String.t()
  def content_hash(%__MODULE__{} = profile) do
    payload =
      :erlang.term_to_binary({
        profile.module,
        Enum.sort(profile.imports),
        Enum.sort(profile.exports),
        Enum.sort(profile.atoms),
        profile.attributes,
        profile.dynamic_dispatch_count,
        profile.handle_undefined_function?
      })

    :crypto.hash(:sha256, payload) |> Base.encode16(case: :lower)
  end

  @doc """
  The set of all imported MFA tuples, as a MapSet for fast membership tests.
  """
  @spec import_set(t()) :: MapSet.t(mfa_tuple())
  def import_set(%__MODULE__{imports: imports}) do
    MapSet.new(imports)
  end

  @doc """
  Filter the atom table to entries that look like URLs, IPv4 addresses, or
  DNS hostnames. Useful as a suspicious-atom signal in version diffing.

  This is heuristic: a hostname-shaped atom in a dep that didn't previously
  have one is a signal, not proof. False positives are expected and accepted.
  """
  @spec suspicious_atoms(t()) :: [atom()]
  def suspicious_atoms(%__MODULE__{atoms: atoms}) do
    Enum.filter(atoms, &suspicious_atom?/1)
  end

  # --- Internals -------------------------------------------------------------

  defp read_chunks(charlist) do
    case :beam_lib.chunks(charlist, [:imports, :exports, :atoms, :attributes, :compile_info]) do
      {:ok, {module, chunks}} ->
        {:ok,
         %{
           module: module,
           imports: Keyword.get(chunks, :imports, []),
           exports: Keyword.get(chunks, :exports, []),
           atoms: decode_atoms(Keyword.get(chunks, :atoms, [])),
           attributes: Keyword.get(chunks, :attributes, []) |> normalize_kw(),
           compile_info: Keyword.get(chunks, :compile_info, []) |> normalize_kw()
         }}

      {:error, :beam_lib, reason} ->
        {:error, reason}

      other ->
        {:error, {:unexpected_beam_lib_result, other}}
    end
  end

  defp decode_atoms(atoms_chunk) when is_list(atoms_chunk) do
    # :atoms chunk returns [{integer, atom}] — flatten to just the atom list.
    Enum.map(atoms_chunk, fn
      {_idx, atom} when is_atom(atom) -> atom
      atom when is_atom(atom) -> atom
      _ -> nil
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp normalize_kw(kw) when is_list(kw) do
    Enum.reduce(kw, %{}, fn
      {k, v}, acc when is_atom(k) -> Map.put(acc, k, v)
      _, acc -> acc
    end)
  end

  defp normalize_kw(_), do: %{}

  defp count_dynamic_dispatch(charlist) do
    try do
      case :beam_disasm.file(charlist) do
        {:beam_file, _module, _exports, _attributes, _compile_info, code} ->
          Enum.reduce(code, 0, fn
            {:function, _name, _arity, _label, instructions}, acc ->
              acc + count_dispatch_instructions(instructions)

            _, acc ->
              acc
          end)

        _ ->
          0
      end
    catch
      _, _ -> 0
    end
  end

  defp count_dispatch_instructions(instructions) when is_list(instructions) do
    Enum.count(instructions, &dispatch_instruction?/1)
  end

  defp count_dispatch_instructions(_), do: 0

  # The BEAM has several opcodes that dispatch without a statically-known
  # target. Their exact shapes differ across OTP versions; we match on the
  # opcode head to stay robust.
  defp dispatch_instruction?({:call_fun, _arity}), do: true
  defp dispatch_instruction?({:call_fun2, _tag, _arity, _fun}), do: true
  defp dispatch_instruction?({:apply, _arity}), do: true
  defp dispatch_instruction?({:apply_last, _arity, _deallocate}), do: true
  defp dispatch_instruction?(_), do: false

  defp handle_undefined_function?(exports) do
    Enum.any?(exports, fn
      {:"$handle_undefined_function", 2} -> true
      _ -> false
    end)
  end

  @url_re ~r/^https?:\/\//
  @ipv4_re ~r/^\d{1,3}(\.\d{1,3}){3}$/
  @hostname_re ~r/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$/

  defp suspicious_atom?(atom) when is_atom(atom) do
    str = Atom.to_string(atom)

    cond do
      Regex.match?(@url_re, str) -> true
      Regex.match?(@ipv4_re, str) -> true
      # Hostnames need at least one dot and look like a domain.
      String.contains?(str, ".") and Regex.match?(@hostname_re, str) -> true
      true -> false
    end
  end

  defp suspicious_atom?(_), do: false
end
