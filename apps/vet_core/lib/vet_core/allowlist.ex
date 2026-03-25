defmodule VetCore.Allowlist do
  @moduledoc false

  alias VetCore.Types.Finding

  @built_in [
    # Build tools & NIFs
    {:rustler, :system_exec, "NIF compilation via cargo"},
    {:elixir_make, :system_exec, "Native build tool"},
    {:ex_doc, :system_exec, "Documentation generation"},

    # Code eval (template/query/parser compilation)
    {:phoenix, :code_eval, "Template compilation"},
    {:phoenix_live_view, :code_eval, "Template compilation"},
    {:ecto, :code_eval, "Query compilation"},
    {:ecto_sql, :code_eval, "Query compilation"},
    {:jason, :code_eval, "JSON codec compilation"},
    {:poison, :code_eval, "JSON codec compilation"},
    {:nimble_parsec, :code_eval, "Parser generator"},
    {:plug, :code_eval, "Router compilation"},
    {:telemetry, :code_eval, "Telemetry compilation"},
    {:makeup, :code_eval, "Syntax highlighter compilation"},
    {:credo, :code_eval, "Linter config evaluation"},

    # Frameworks — env access, file access, obfuscation are normal patterns
    {:plug, :env_access, "Plug configuration reads env vars"},
    {:plug, :file_access, "Plug debugger reads source files"},
    {:plug, :obfuscation, "Plug uses apply/3 for pipeline dispatch"},
    {:phoenix, :env_access, "Phoenix configuration reads env vars"},
    {:phoenix, :system_exec, "Phoenix code reloader"},
    {:phoenix, :obfuscation, "Phoenix uses apply/3 for dispatch"},
    {:bandit, :obfuscation, "Bandit uses apply/3 for handler dispatch"},

    # Dev/test tools
    {:credo, :system_exec, "Credo runs git for blame info"},
    {:credo, :file_access, "Credo reads source files for analysis"},
    {:credo, :env_access, "Credo reads env for config"},
    {:dialyxir, :system_exec, "Dialyzer invocation"},
    {:dialyxir, :env_access, "PLT directory configuration"},
    {:dialyxir, :file_access, "PLT file operations"},
    {:excoveralls, :system_exec, "Coverage tool runs mix/git"},
    {:excoveralls, :env_access, "CI environment detection"},
    {:file_system, :system_exec, "File watcher uses OS-specific backends"},
    {:file_system, :env_access, "File watcher backend configuration"},

    # Network access
    {:mix_audit, :network_access, "Fetches security advisories"},
    {:hex, :network_access, "Package manager"},
    {:req, :network_access, "HTTP client library"},
    {:finch, :network_access, "HTTP client library"},
    {:mint, :network_access, "HTTP client library"},

    # Known packages that use File.read! for version in mix.exs
    {:typed_struct, :file_access, "Reads VERSION file"},
    {:typed_struct, :system_exec, "Git commands in mix.exs"},
    {:websock, :file_access, "Reads VERSION/CHANGELOG"},
    {:erlex, :file_access, "Reads VERSION file"},

    # Atom exhaustion — legitimate atom conversion
    {:phoenix, :dos_atom_exhaustion, "Phoenix legitimately converts atoms for routing"},
    {:ecto, :dos_atom_exhaustion, "Ecto legitimately converts atoms for schema fields"}
  ]

  @spec suppressed?(atom(), Finding.category()) :: boolean()
  def suppressed?(dep_name, category) do
    suppressed_in_built_in?(dep_name, category)
  end

  @spec suppressed?(atom(), Finding.category(), String.t()) :: boolean()
  def suppressed?(dep_name, category, project_path) do
    suppressed_in_built_in?(dep_name, category) ||
      suppressed_in_user_config?(dep_name, category, project_path)
  end

  @spec load_user_config(String.t()) :: [tuple()]
  def load_user_config(project_path) do
    config_path = Path.join(project_path, ".vet.exs")

    case File.read(config_path) do
      {:ok, contents} ->
        case Code.eval_string(contents) do
          {config, _bindings} when is_map(config) ->
            parse_user_suppressions(config)

          {config, _bindings} when is_list(config) ->
            parse_user_suppressions(%{allow: config})

          _ ->
            []
        end

      {:error, _} ->
        []
    end
  end

  @spec filter_findings([Finding.t()], atom(), String.t()) :: [Finding.t()]
  def filter_findings(findings, dep_name, project_path) do
    user_suppressions = load_user_config(project_path)

    Enum.reject(findings, fn finding ->
      case suppression_reason(dep_name, finding.category, user_suppressions) do
        nil -> false
        _reason -> true
      end
    end)
  end

  # -- Private -----------------------------------------------------------------

  defp suppressed_in_built_in?(dep_name, category) do
    Enum.any?(@built_in, fn {name, cat, _reason} ->
      name == dep_name and cat == category
    end)
  end

  defp suppressed_in_user_config?(dep_name, category, project_path) do
    user_suppressions = load_user_config(project_path)

    Enum.any?(user_suppressions, fn {name, cat, _reason} ->
      name == dep_name and cat == category
    end)
  end

  defp suppression_reason(dep_name, category, user_suppressions) do
    built_in_match =
      Enum.find(@built_in, fn {name, cat, _reason} ->
        name == dep_name and cat == category
      end)

    user_match =
      Enum.find(user_suppressions, fn {name, cat, _reason} ->
        name == dep_name and cat == category
      end)

    case built_in_match || user_match do
      {_name, _cat, reason} -> reason
      nil -> nil
    end
  end

  defp parse_user_suppressions(%{allow: allow_list}) when is_list(allow_list) do
    Enum.flat_map(allow_list, fn
      {dep_name, category, reason} when is_atom(dep_name) and is_atom(category) ->
        [{dep_name, category, reason}]

      {dep_name, category} when is_atom(dep_name) and is_atom(category) ->
        [{dep_name, category, "User allowlisted"}]

      _ ->
        []
    end)
  end

  defp parse_user_suppressions(_), do: []
end
