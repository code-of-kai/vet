# Vet

Static analysis tool for Elixir dependencies. Scans your project's dependency code for supply chain attack indicators — credential theft, code execution, data exfiltration, obfuscation — before they reach production.

## Why

Your dependencies run in the same BEAM as your application. A compromised package can call `System.get_env("AWS_SECRET_ACCESS_KEY")` at compile time, exfiltrate it over HTTP, and you will never see it happen. The Elixir ecosystem trusts its packages, and that trust is largely deserved. But trust does not scale with the number of transitive dependencies in a modern project.

Vet walks the AST of every dependency in your lock file and flags patterns that have no legitimate reason to appear in a library: compile-time system commands, environment variable access for sensitive keys, network calls to suspicious endpoints, obfuscated payloads, and more.

It also addresses a newer problem: LLMs hallucinate package names at a measurable rate. Attackers have begun registering those hallucinated names on package registries with malicious payloads — a technique called "slopsquatting." Vet detects these phantom packages and typosquats before you install them.

## Installation

Add `vet_cli` to your project's dependencies:

```elixir
def deps do
  [
    {:vet_cli, "~> 0.1", only: :dev, runtime: false}
  ]
end
```

## Usage

### Full dependency scan

```bash
mix vet
```

This parses your `mix.lock`, walks the source of every dependency, and reports findings with risk scores. Dependencies are scored from 0 to 100 based on the severity of findings and package metadata.

Options:

  * `--path`, `-p` — project path (defaults to current directory)
  * `--format`, `-f` — output format: `terminal` (default), `json`, `diagnostics`
  * `--threshold`, `-t` — exit with error if any dependency's risk score meets or exceeds this value (default: 50)
  * `--skip-hex` — skip hex.pm metadata checks (useful offline or in CI without network)
  * `--verbose`, `-v` — verbose output

### Pre-install check

```bash
mix vet.check
```

Run this *before* `mix deps.get`. It reads your `mix.exs` directly — no lock file or fetched dependencies required — and checks each declared dependency against hex.pm:

  * Does the package exist? (phantom package detection)
  * Is the name suspiciously close to a popular package? (typosquat/slopsquat detection)
  * Is it recently published with very low adoption? (metadata signals)

If any dependency does not exist on hex.pm, the task exits with an error.

## What it checks

Vet runs 10 checks against each dependency's source code via AST analysis:

| Check | Category | What it detects |
|---|---|---|
| `SystemExec` | `:system_exec` | `System.cmd`, `System.shell`, `:os.cmd`, `Port.open` |
| `CodeEval` | `:code_eval` | `Code.eval_string`, `Code.compile_string`, `:erlang.binary_to_term`, `Module.create` |
| `EExEval` | `:code_eval` | `EEx.eval_string`, `EEx.eval_file`, `EEx.compile_string` |
| `CompilerHooks` | `:compiler_hooks` | `@before_compile`, `@after_compile`, custom compilers in mix.exs |
| `EnvAccess` | `:env_access` | `System.get_env` — critical for sensitive variables (`SECRET`, `KEY`, `TOKEN`, `AWS_*`, `DATABASE_URL`) |
| `FileAccess` | `:file_access` | `File` operations — critical for sensitive paths (`~/.ssh`, `~/.aws`, `/etc/passwd`) |
| `NetworkAccess` | `:network_access` | `:httpc.request`, `:gen_tcp.connect`, `Req`, `HTTPoison`, `Finch`, `Mint.HTTP` |
| `Obfuscation` | `:obfuscation` | Base64 decode paired with eval, high-entropy strings (>5.5 Shannon entropy), dynamic `apply/3` |
| `ShadyLinks` | `:shady_links` | Suspicious TLDs, tunneling services (ngrok, serveo), exfiltration endpoints (pastebin, telegram, discord webhooks) |
| `AtomExhaustion` | `:dos_atom_exhaustion` | `String.to_atom`, `:erlang.binary_to_atom` — DoS via atom table exhaustion |

Every finding distinguishes between compile-time and runtime context. Compile-time findings score significantly higher because they execute during `mix deps.compile` — before your application code runs.

## Scoring

Each dependency receives a risk score (0–100) combining code findings and package metadata:

**Findings** — compile-time critical: +40, compile-time warning: +20, runtime critical: +15, runtime warning: +5, info: +1.

**Metadata** — non-hex source (git/path): +10, downloads <100: +20, downloads <1000: +10, released in last 7 days: +15, single owner: +5, no description: +5.

**Popularity adjustment** — packages with >10M downloads: score ×0.3, >1M: score ×0.5. Widely adopted packages are less likely to be malicious; their findings are typically legitimate framework patterns.

**Risk levels** — critical (>=80), high (>=50), medium (>=20), low (<20).

## Allowlist

Many legitimate libraries trigger findings. Phoenix uses `@before_compile`, Ecto runs `Code.eval_quoted` for query compilation, Rustler executes system commands to build native code. Vet ships with a built-in allowlist covering ~50 common packages and their expected patterns.

You can extend it with a `.vet.exs` file in your project root:

```elixir
%{
  allow: [
    {:my_package, :system_exec, "Runs native build toolchain"},
    {:another_package, :network_access, "Fetches remote config at compile time"}
  ]
}
```

## MCP integration

Vet exposes three tools via the [Model Context Protocol](https://modelcontextprotocol.io), integrated through [Tidewave](https://github.com/tidewave-ai/tidewave_phoenix):

  * `vet_check_package` — check a package *before* adding it as a dependency. Detects phantom packages, typosquats, and slopsquatting targets. Does not require the package to be installed.

  * `vet_scan_dependencies` — full project scan, returns JSON with risk scores and findings.

  * `vet_diff_versions` — compare two versions of a package for suspicious changes, new findings, or profile shifts.

This means an AI coding assistant connected to your running application can verify that a package exists and is trustworthy before suggesting it — intercepting slopsquatting at the point of recommendation rather than after installation.

To enable it, add Tidewave to your Phoenix endpoint (see [Tidewave's installation guide](https://hexdocs.pm/tidewave/installation.html)). Vet's tools register automatically on application start.

## Architecture

Vet is structured as an umbrella project:

  * `vet_core` — scanner, checks, AST walker, scoring, metadata fetching, typosquat detection
  * `vet_cli` — Mix tasks (`mix vet`, `mix vet.check`)
  * `vet_reporter` — output formatting (terminal, JSON, diagnostics)
  * `vet_mcp` — MCP tool definitions and Tidewave integration
  * `vet_service` — persistence layer for scan history and community attestations

## Limitations

  * Elixir/Erlang only. Does not scan npm, Python, or other ecosystems.
  * Static analysis. Cannot detect malicious behavior hidden behind runtime conditionals or encrypted payloads that are decrypted at a later stage.
  * The typosquat corpus is a static list of ~200 popular packages. Packages outside this list will not trigger proximity checks.
  * Metadata checks require network access to hex.pm. Use `--skip-hex` when running offline.

## License

MIT
