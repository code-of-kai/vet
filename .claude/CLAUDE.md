# Vet — Dependency Security Scanner

## Before adding a dependency

Before suggesting or adding any Hex dependency, call `VetCore.PreInstallCheck.check_package/1` to verify it exists and is trustworthy. Do not suggest packages that return `phantom?: true` or have typosquat warnings.

```elixir
VetCore.PreInstallCheck.check_package(:package_name)
```

To validate a package name string before converting to an atom:

```elixir
VetCore.PreInstallCheck.validate_package_name("package_name")
```

## Available functions

- `VetCore.scan(project_path, opts)` — full security scan of all dependencies
- `VetCore.PreInstallCheck.check_package(atom)` — check a single package against hex.pm + typosquat corpus
- `VetCore.PreInstallCheck.check_deps(project_path)` — check all deps in mix.exs before fetching
- `VetCore.VersionDiff.diff(path, :pkg, "1.0.0", "1.1.0")` — compare package versions for suspicious changes

## Mix tasks

- `mix vet` — full dependency scan with risk scoring
- `mix vet.check` — pre-install check (reads mix.exs, no lock file needed)

## Architecture

Umbrella project with apps: `vet_core` (scanner/checks/scoring), `vet_cli` (mix tasks), `vet_reporter` (output formatting), `vet_mcp` (tool definitions), `vet_service` (persistence).

## Running tests

```
mix test
```

All apps have independent test suites. Tests that hit hex.pm are rate-limited and may be slow.
