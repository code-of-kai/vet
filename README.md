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
  * `--no-diff` — skip automatic version diffing (faster scans, no network fetch of previous versions)
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

### Version diffing

Vet automatically compares each dependency against its previous version on Hex. Hex retains every published version permanently, so this works regardless of what you previously had installed.

If a version transition introduces suspicious patterns (new files outside of tests, increased security findings, or a shift in the package's security profile), Vet flags it as a `[VERSION DIFF]` finding. These findings bypass the allowlist. The allowlist says "we trust this package's existing behavior." A version diff says "the behavior changed."

This is how Vet catches a compromised update to an allowlisted package. If a trusted dependency pushes a new version that adds compile-time credential theft, the diff against the previous version surfaces it even though the package is allowlisted.

Use `--no-diff` to disable version diffing for faster offline scans.

## What it checks

Vet runs 10 source-level checks against each dependency's AST:

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

## Defense in depth: seven layers beyond AST

Source-level scanning has known evasion paths: `defdelegate`, atom-aliased module names, macro-synthesized calls, `.erl` files compiled to BEAM, `$handle_undefined_function/2`, NIFs, and dynamic dispatch. Vet does not pretend these don't exist — instead it stacks six additional inspection layers, each of which catches a different evasion class. An attacker has to defeat *all* of them, not just AST analysis.

| Layer | Where it operates | What it defeats |
|---|---|---|
| **1. BEAM imports** (`Checks.BeamImports`) | `:beam_lib` chunks of compiled `.beam` files | Source-level evasion via `defdelegate`, atom aliasing, macro synthesis, `.erl` files. The BEAM has the literal call wired in regardless of how the source spelled it. |
| **2. Compile sandbox** (`Checks.SandboxedCompile`) | OS-level sandbox (`sandbox-exec` on macOS, `bwrap` on Linux) | Compile-time escape. Runs `mix deps.compile <pkg>` inside a denylist sandbox; reports denied syscalls, network attempts, subprocess spawns, writes outside the workdir. Opt-in via `sandboxed_compile: true`. |
| **3. Reflection tripwires** (`Checks.BeamReflection`) | BEAM imports + dynamic-dispatch opcode counts | `apply/3`, `String.to_atom`, `binary_to_term` + dispatch combinations, `$handle_undefined_function/2` exports. Counts dispatch opcodes per module, not source occurrences. |
| **4. Version delta** (`Checks.BeamDelta` + `BEAM.BeamDiff` + `BEAM.ProfileCache`) | Cached prior BEAM profile vs current | Gradual introduction. Diffs the current compiled profile against a cached snapshot of the prior version; flags new dangerous imports, new `$handle_undefined`, dispatch spikes (default threshold: +3), suspicious atoms (URLs/IPs/hostnames). |
| **5. Native code surface** (`Checks.NativeCode`) | `priv/*.so/.dylib/.dll`, `c_src/`, `Cargo.toml`, `:rustler`/`:elixir_make` in mix.exs, `:erlang.load_nif/2` in BEAMs | NIF bypass. Native code is opaque machine running in the BEAM scheduler — Vet can't analyze it, but it can detect its presence. |
| **6. Attestation** (`Checks.Attestation` + `Attestation.{Manifest, Signer, Verifier, Store}`) | Ed25519-signed `*.manifest.json` + `*.sig` in `.vet/attestations/`, trusted keys in `.vet/trusted_keys/` or `~/.vet/trusted_keys/` | Tampered installs and untrusted publishers. Verifies the signature was produced by a trusted key and that every module hash in the manifest matches the local install byte-for-byte. Modes: `:advisory` (default), `:require` (warning for unsigned), `:strict` (critical for unsigned). |
| **7. Capability verifier** (`Checks.CapabilityVerifier`) | `:vet_capabilities` list declared in dep's `mix.exs` vs MFAs observed in compiled BEAMs | Undeclared capability expansion. A package that promises `[:network]` but ships `:ssh` calls in its BEAM emits a critical `:capability_undeclared_use` finding. |

These layers don't replace AST scanning — they augment it. Most malicious patterns surface in source. The seven layers exist to close the doors that source analysis alone leaves open.

### Threat model — what each evasion costs the attacker

| Hypothetical evasion | Layer that catches it | What the attacker has to do instead |
|---|---|---|
| `defdelegate` to obfuscate target module | Layer 1 (imports table) | Avoid the imports chunk entirely — only possible via NIF, caught by Layer 5 |
| Atom-aliased module reference (`mod = :"Sys" <> "tem"; mod.cmd("...")`) | Layer 3 (dispatch + reflection counts) | Drop reflection altogether |
| Macro that emits dangerous calls at compile time | Layer 1 (the macro expansion ends up in the BEAM) | Hide call inside a NIF — Layer 5 |
| `.erl` source file (skipped by Elixir AST walker) | Layer 1 (compiled identically to `.ex`) | Same answer |
| `$handle_undefined_function/2` for runtime resolution | Layer 1 + Layer 3 (export-table check) | Removing the export defeats the technique |
| Compile-time `System.cmd("curl ...")` | Layer 2 (sandbox blocks subprocess + network) | The compile fails inside the sandbox |
| Gradual ratchet: introduce one dangerous import per release | Layer 4 (delta against cached prior version) | Each step still produces a delta finding |
| Pure NIF payload | Layer 5 detects the artifact, mix.exs `compilers`, or `:erlang.load_nif/2` import | Strip every native file/build directive — at which point there's no NIF |
| Repackaged tarball with extra modules | Layer 6 (manifest hashes diverge from install) | Compromise a trusted key |
| Add `:ssh` calls to a "pure compute" library | Layer 7 (`:vet_capabilities` mismatch) | Update mix.exs declarations, which is itself a visible signal |

No single layer is a silver bullet. Together, they push the cost of a successful supply-chain attack from "spell the call differently" up to "compromise the publisher's signing key, evade the sandbox, and avoid every BEAM-level signal across the entire delta."

## Scoring

Each dependency receives a risk score (0–100) combining code findings and package metadata:

**Findings** — compile-time critical: +40, compile-time warning: +20, runtime critical: +15, runtime warning: +5, info: +1.

**Metadata** — non-hex source (git/path): +10, downloads <100: +20, downloads <1000: +10, released in last 7 days: +15, single owner: +5, no description: +5, dependency depth 3-4: +5, depth 5+: +10.

**Popularity adjustment** — packages with >10M downloads: score ×0.3, >1M: score ×0.5. Widely adopted packages are less likely to be malicious; their findings are typically legitimate framework patterns.

**Risk levels** — critical (>=80), high (>=50), medium (>=20), low (<20).

## Allowlist

Many legitimate libraries trigger findings. Phoenix uses `@before_compile`, Ecto runs `Code.eval_quoted` for query compilation, Rustler executes system commands to build native code. Vet ships with a built-in allowlist covering the Phoenix 1.7+ ecosystem and common Elixir packages (~100 suppression rules).

You can extend it with a `.vet.exs` file in your project root:

```elixir
%{
  allow: [
    {:my_package, :system_exec, "Runs native build toolchain"},
    {:another_package, :network_access, "Fetches remote config at compile time"}
  ]
}
```

## AI agent integration

Vet ships with an `AGENTS.md` that tells AI coding assistants how to use its functions. If your project uses [Tidewave](https://github.com/tidewave-ai/tidewave_phoenix), agents can call Vet's functions through `project_eval` with zero configuration.

The key function for agents:

```elixir
VetCore.PreInstallCheck.check_package(:some_package)
```

This checks whether a package exists on hex.pm, detects typosquats and slopsquatting targets, and returns metadata signals — all before the package is installed. An AI assistant that calls this before suggesting a dependency can intercept slopsquatting at the point of recommendation rather than after installation.

Other functions available through `project_eval`:

  * `VetCore.scan(path)` — full project scan with risk scores and findings
  * `VetCore.VersionDiff.diff(path, :pkg, "1.0.0", "1.1.0")` — compare package versions for suspicious changes
  * `VetCore.PreInstallCheck.check_deps(path)` — check all mix.exs dependencies at once

See `AGENTS.md` for complete usage.

## Architecture

Vet is structured as an umbrella project:

  * `vet_core` — scanner, checks, AST walker, scoring, metadata fetching, typosquat detection
  * `vet_cli` — Mix tasks (`mix vet`, `mix vet.check`)
  * `vet_reporter` — output formatting (terminal, JSON, diagnostics)
  * `vet_service` — persistence layer for scan history and community attestations

## Limitations

  * **Vet reduces risk. It does not eliminate it.** A clean scan is not proof of safety. Do not use Vet as the sole basis for trusting a dependency.
  * Elixir/Erlang only. Does not scan npm, Python, or other ecosystems.
  * **Native code is opaque.** Layer 5 detects the *presence* of NIFs and native build systems but cannot analyze the machine code they ship. A NIF that exfiltrates secrets is invisible to every layer except presence detection.
  * **Layer 4 needs a baseline.** The delta check requires a cached prior profile in `.vet/beam_profiles/`. The first scan of a new dependency has nothing to diff against — the second scan is when delta findings become useful.
  * **Layer 6 is opt-in for the ecosystem.** Most Hex packages are not signed. Attestation is most valuable for inner-source / vendored / private-registry packages where you control the signing.
  * **Layer 2 is opt-in.** The sandbox is gated behind `sandboxed_compile: true` because running every dep's compile inside `sandbox-exec` / `bwrap` materially slows scans and depends on the host OS shipping the right tool.
  * **Layer 7 detects undeclared capabilities, not malicious ones.** A package can declare `[:network, :system_exec, :code_eval]` and Vet will not flag it — the value is in the surprise. Diff against the prior declaration to spot expanding scope.
  * Static analysis. Cannot detect malicious behavior hidden behind runtime conditionals, encrypted payloads decrypted at a later stage, or code loaded dynamically from external sources beyond what Layer 4's delta surfaces.
  * The typosquat corpus is a static list of ~200 popular packages. Packages outside this list will not trigger proximity checks.
  * Metadata checks require network access to hex.pm. Use `--skip-hex` when running offline.
  * Vet trusts hex.pm API responses. If hex.pm itself is compromised, metadata-based checks become unreliable.

See [SECURITY.md](SECURITY.md) for Vet's own attack surface and trust boundaries.

## License

MIT
