defmodule VetCore.Generators do
  @moduledoc """
  StreamData generators for Vet domain types.
  Compose bottom-up: leaves → structs → contexts.
  """

  use ExUnitProperties

  alias VetCore.Types.{Dependency, Finding, HexMetadata, DependencyReport}

  # -- Level 1: Leaf generators --

  def severity, do: member_of([:info, :warning, :critical])

  def category do
    member_of([
      :system_exec, :code_eval, :network_access, :file_access,
      :env_access, :obfuscation, :shady_links, :compiler_hooks,
      :dos_atom_exhaustion, :metadata, :phantom_package
    ])
  end

  def risk_level, do: member_of([:low, :medium, :high, :critical])

  def dep_source do
    one_of([
      constant(:hex),
      bind(string(:alphanumeric, min_length: 5, max_length: 20), fn url ->
        constant({:git, "https://github.com/user/#{url}"})
      end),
      bind(string(:alphanumeric, min_length: 3, max_length: 10), fn path ->
        constant({:path, "../#{path}"})
      end)
    ])
  end

  def package_name_atom do
    bind(package_name_string(), fn name -> constant(String.to_atom(name)) end)
  end

  def package_name_string do
    gen all(
      first <- member_of(Enum.to_list(?a..?z)),
      rest <- string(Enum.concat([?a..?z, ?0..?9, [?_]]), min_length: 0, max_length: 30)
    ) do
      <<first>> <> rest
    end
  end

  def version_string do
    gen all(
      major <- integer(0..20),
      minor <- integer(0..50),
      patch <- integer(0..99)
    ) do
      "#{major}.#{minor}.#{patch}"
    end
  end

  def depth, do: integer(1..10)

  # -- Level 2: Struct generators --

  def dependency do
    gen all(
      name <- package_name_atom(),
      version <- version_string(),
      source <- dep_source(),
      direct? <- boolean(),
      depth <- depth()
    ) do
      %Dependency{
        name: name,
        version: version,
        source: source,
        direct?: direct?,
        depth: depth,
        children: []
      }
    end
  end

  def finding do
    gen all(
      dep_name <- package_name_atom(),
      line <- integer(1..500),
      check_id <- member_of([:system_exec, :code_eval, :obfuscation, :network_access,
                              :file_access, :env_access, :shady_links, :compiler_hooks,
                              :atom_exhaustion, :eex_eval, :obfuscation_entropy,
                              :obfuscation_dynamic_apply, :obfuscation_decode_eval]),
      cat <- category(),
      sev <- severity(),
      compile_time? <- boolean()
    ) do
      %Finding{
        dep_name: dep_name,
        file_path: "deps/#{dep_name}/lib/#{dep_name}.ex",
        line: line,
        check_id: check_id,
        category: cat,
        severity: sev,
        compile_time?: compile_time?,
        description: "Test finding: #{check_id}"
      }
    end
  end

  def hex_metadata do
    gen all(
      downloads <- one_of([constant(nil), integer(0..100_000_000)]),
      owner_count <- one_of([constant(nil), integer(1..20)]),
      retired? <- boolean(),
      days_ago <- integer(0..365)
    ) do
      release_date = DateTime.utc_now() |> DateTime.add(-days_ago * 86400)

      %HexMetadata{
        downloads: downloads,
        latest_version: "1.0.0",
        latest_release_date: release_date,
        owner_count: owner_count,
        description: "A package",
        retired?: retired?
      }
    end
  end

  def hex_metadata_or_nil do
    one_of([constant(nil), hex_metadata()])
  end

  # -- Level 3: Dependency graph generators --

  def dependency_graph do
    gen all(
      count <- integer(2..10),
      deps <- list_of(dependency(), length: count)
    ) do
      deps
      |> Enum.with_index()
      |> Enum.map(fn {dep, i} ->
        if i == 0 do
          %{dep | direct?: true, children: deps |> Enum.drop(1) |> Enum.take(2) |> Enum.map(& &1.name)}
        else
          %{dep | direct?: false, children: []}
        end
      end)
      |> Enum.uniq_by(& &1.name)
    end
  end

  # -- Level 4: Scoring context generators --

  def scoring_context do
    gen all(
      dep <- dependency(),
      findings <- list_of(finding(), min_length: 0, max_length: 10),
      meta <- hex_metadata_or_nil()
    ) do
      findings = Enum.map(findings, fn f -> %{f | dep_name: dep.name} end)
      {dep, findings, meta}
    end
  end
end
