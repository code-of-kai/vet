# Security

Vet is a security tool. Its own attack surface matters more than most projects because compromising the scanner disables the defense.

## Reporting vulnerabilities

If you find a security issue in Vet, please email kai@[TODO] rather than opening a public issue.

## Trust boundaries

Vet treats the following as untrusted input:

- **mix.lock** — parsed via `Code.string_to_quoted` (AST only, no execution)
- **.vet.exs config** — parsed via `Code.string_to_quoted` (AST only, no execution)
- **Dependency source files** — parsed via `Code.string_to_quoted` with try/rescue crash resilience
- **Package names and versions** — validated against strict regex before use in shell commands
- **Hex.pm API responses** — trusted over HTTPS but treated as potentially unavailable

## What Vet trusts

- **Hex.pm API data** — download counts, owner counts, release dates. If hex.pm itself is compromised, Vet's metadata checks become unreliable. This is outside Vet's control.
- **The built-in allowlist** — suppressions in `apps/vet_core/lib/vet_core/allowlist.ex`. A malicious change to this file silently disables detection for specific packages.
- **AGENTS.md / CLAUDE.md** — instructions to AI coding agents. A malicious change to these files could instruct agents to skip scanning or ignore findings.

## Review policy for sensitive files

Changes to the following files should be reviewed with the same scrutiny as security-critical code:

- `apps/vet_core/lib/vet_core/allowlist.ex` — the `@built_in` list controls which findings are suppressed. Adding an entry disables detection for that package/category combination across all users.
- `AGENTS.md` and `.claude/CLAUDE.md` — these instruct AI agents on how to use Vet. Modifying them changes the behavior of every agent that reads them.
- `apps/vet_core/lib/vet_core/lock_parser.ex` — parses untrusted input. Any change that reintroduces `Code.eval_string` reintroduces arbitrary code execution.
- `apps/vet_core/lib/vet_core/version_diff.ex` — calls `System.cmd`. Any change to input validation could reintroduce shell injection.

## Known limitations

- **Static analysis ceiling** — Vet cannot detect malicious behavior hidden behind runtime conditionals, encrypted payloads that are decrypted at a later stage, or code loaded dynamically from external sources at runtime.
- **Elixir/Erlang only** — does not scan npm, Python, or other ecosystem dependencies.
- **Typosquat corpus** — the reference list of ~200 popular packages is static. Packages outside this list will not trigger proximity checks.
- **Vet does not prove safety** — a clean scan reduces risk but does not eliminate it. Do not treat "Vet says clean" as a guarantee.
