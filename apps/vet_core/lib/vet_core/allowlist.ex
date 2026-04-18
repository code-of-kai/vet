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
    {:poison, :code_eval, "JSON codec compilation"},
    {:credo, :code_eval, "Linter config evaluation"},

    # Frameworks — env access, file access, obfuscation are normal patterns
    {:plug, :env_access, "Plug configuration reads env vars"},
    {:plug, :file_access, "Plug debugger reads source files"},
    {:plug, :obfuscation, "Plug uses apply/3 for pipeline dispatch"},
    {:phoenix, :env_access, "Phoenix configuration reads env vars"},
    {:phoenix, :system_exec, "Phoenix code reloader"},
    {:phoenix, :obfuscation, "Phoenix uses apply/3 for dispatch"},

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
    {:ecto, :dos_atom_exhaustion, "Ecto legitimately converts atoms for schema fields"},

    # Phoenix 1.7+ ecosystem (default `mix phx.new --database postgres`)
    {:thousand_island, :network_access, "Bandit's underlying socket layer"},
    {:phoenix_live_view, :obfuscation, "LiveView uses apply/3 for component dispatch"},
    {:phoenix_live_view, :compiler_hooks, "LiveView uses @before_compile for views"},
    {:phoenix_live_view, :file_access, "LiveView reads template files at compile time"},
    {:phoenix_live_dashboard, :obfuscation, "Dashboard uses apply/3 for page dispatch"},
    {:phoenix_live_reload, :file_access, "Watches source files for changes"},
    {:phoenix_ecto, :code_eval, "Form integration with Ecto changesets"},
    {:phoenix_template, :code_eval, "Template compilation"},
    {:phoenix_template, :compiler_hooks, "@before_compile for template engines"},
    {:phoenix_template, :file_access, "Reads template files at compile time"},

    # Database
    {:postgrex, :network_access, "PostgreSQL client"},
    {:postgrex, :env_access, "Reads PG* environment variables"},
    {:myxql, :network_access, "MySQL client"},
    {:myxql, :env_access, "Reads MYSQL_* environment variables"},
    {:db_connection, :obfuscation, "Adapter dispatch via apply/3"},
    {:ecto, :env_access, "Ecto config reads env vars"},
    {:ecto_sql, :system_exec, "Migrations may invoke shell tools"},
    {:ecto_sql, :file_access, "Reads migration files"},

    # Telemetry
    {:telemetry_poller, :system_exec, "Reads /proc on Linux for VM metrics"},
    {:telemetry_poller, :file_access, "Reads /proc filesystem"},

    # Internationalization
    {:gettext, :code_eval, "PO file compilation"},
    {:gettext, :compiler_hooks, "@before_compile for backend modules"},
    {:gettext, :file_access, "Reads .po translation files at compile time"},

    # Email
    {:swoosh, :network_access, "Email delivery via HTTP/SMTP"},
    {:swoosh, :code_eval, "Adapter compilation"},
    {:bamboo, :network_access, "Email delivery via HTTP/SMTP"},
    {:gen_smtp, :network_access, "SMTP client"},

    # Asset pipeline
    {:esbuild, :system_exec, "Runs esbuild binary"},
    {:esbuild, :file_access, "Reads/writes asset files"},
    {:esbuild, :network_access, "Downloads esbuild binary on first run"},
    {:tailwind, :system_exec, "Runs tailwind binary"},
    {:tailwind, :file_access, "Reads/writes CSS files"},
    {:tailwind, :network_access, "Downloads tailwind binary on first run"},
    {:dart_sass, :system_exec, "Runs sass binary"},
    {:dart_sass, :file_access, "Reads/writes Sass files"},
    {:dart_sass, :network_access, "Downloads sass binary on first run"},

    # Networking & clustering
    {:dns_cluster, :network_access, "DNS lookups for node discovery"},

    # Crypto / TLS
    {:plug_crypto, :obfuscation, "Uses :crypto for cookie/session encryption"},
    {:castore, :file_access, "Bundles and reads CA certificate store"},
    {:bcrypt_elixir, :system_exec, "NIF compilation via cargo/make"},
    {:argon2_elixir, :system_exec, "NIF compilation"},
    {:pbkdf2_elixir, :code_eval, "Hash algorithm compilation"},

    # Pools and HTML
    {:nimble_pool, :obfuscation, "Pool dispatch via apply/3"},
    {:floki, :code_eval, "HTML parser compilation"},

    # Test tools
    {:floki, :file_access, "Reads HTML files for parser tests"},
    {:mox, :code_eval, "Defines mocks via macros"},
    {:bypass, :network_access, "Test HTTP server for mocking external APIs"}
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
        case Code.string_to_quoted(contents) do
          {:ok, ast} ->
            extract_suppressions_from_ast(ast)

          {:error, _} ->
            []
        end

      {:error, _} ->
        []
    end
  end

  defp extract_suppressions_from_ast({:%{}, _meta, entries}) when is_list(entries) do
    # Map literal: %{allow: [...]}
    case Keyword.get(entries, :allow) do
      nil -> []
      list_ast -> parse_suppression_list_ast(list_ast)
    end
  end

  defp extract_suppressions_from_ast(list_ast) when is_list(list_ast) do
    # Bare list: [{:pkg, :category, "reason"}, ...]
    parse_suppression_list_ast(list_ast)
  end

  defp extract_suppressions_from_ast(_), do: []

  defp parse_suppression_list_ast(items) when is_list(items) do
    Enum.flat_map(items, fn
      # 3-tuple: {:pkg, :category, "reason"}
      {:{}, _meta, [dep_name, category, reason]}
      when is_atom(dep_name) and is_atom(category) and is_binary(reason) ->
        [{dep_name, category, reason}]

      # 2-tuple: {:pkg, :category} — represented as plain keyword pair in AST
      {dep_name, category}
      when is_atom(dep_name) and is_atom(category) ->
        [{dep_name, category, "User allowlisted"}]

      _ ->
        []
    end)
  end

  defp parse_suppression_list_ast(_), do: []

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
