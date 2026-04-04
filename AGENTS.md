# Vet — Dependency Security Scanner

Vet scans Elixir dependencies for supply chain attack indicators. If you are an AI coding assistant working on a project that uses Vet, the functions below are available through `project_eval`.

## Before adding a dependency

Before suggesting or adding any Hex dependency, check it first:

```elixir
VetCore.PreInstallCheck.check_package(:package_name)
```

This returns a map with:
- `phantom?` — `true` if the package does not exist on hex.pm (likely a hallucinated name)
- `typosquat_warnings` — list of warnings if the name is suspiciously close to a popular package
- `metadata` — hex.pm download count, owner count, release date
- `assessment` — human-readable summary

If the package does not exist on hex.pm or has typosquat warnings, do not suggest it.

To validate a package name string before converting to an atom:

```elixir
VetCore.PreInstallCheck.validate_package_name("package_name")
# {:ok, :package_name} or {:error, reason}
```

## Scanning all dependencies

To run a full security scan of the project:

```elixir
{:ok, report} = VetCore.scan("/path/to/project")
```

Or from the terminal:

```
mix vet
mix vet --format json
mix vet --threshold 30
```

To check dependencies before fetching them (reads mix.exs, not mix.lock):

```
mix vet.check
```

## Comparing package versions

To detect suspicious changes between two versions of a package:

```elixir
{:ok, diff} = VetCore.VersionDiff.diff(project_path, :package_name, "1.0.0", "1.1.0")
{suspicious?, signals} = VetCore.VersionDiff.suspicious_delta?(diff)
```

## What Vet checks for

- System command execution (`System.cmd`, `:os.cmd`, `Port.open`)
- Dynamic code evaluation (`Code.eval_string`, `Module.create`, `:erlang.binary_to_term`)
- Environment variable access (critical for `SECRET`, `KEY`, `TOKEN`, `AWS_*`)
- File access to sensitive paths (`~/.ssh`, `~/.aws`, `/etc/passwd`)
- Network calls to suspicious endpoints (tunneling services, exfiltration endpoints)
- Compile-time hooks (`@before_compile`, `@after_compile`)
- Obfuscated payloads (high-entropy strings, Base64+eval patterns)
- Atom exhaustion DoS (`String.to_atom`)

Compile-time findings score significantly higher because they execute during `mix deps.compile`.

## Important

Always call `VetCore.PreInstallCheck.check_package/1` before recommending a dependency to the user. This is the primary defense against slopsquatting — attackers registering package names that LLMs commonly hallucinate.
