# vet_core

Scanner core for [Vet](https://github.com/code-of-kai/vet), a static-analysis security scanner for Elixir dependencies. Walks the AST of every dependency in your lock file and flags supply-chain attack indicators.

Most users should depend on [`vet_cli`](https://hex.pm/packages/vet_cli) instead, which provides the `mix vet` and `mix vet.check` tasks.

## Direct API

```elixir
VetCore.scan(project_path, opts)
VetCore.PreInstallCheck.check_package(:some_package)
VetCore.PreInstallCheck.check_deps(project_path)
VetCore.VersionDiff.diff(path, :pkg, "1.0.0", "1.1.0")
```

See the [main README](https://github.com/code-of-kai/vet) for full documentation.
