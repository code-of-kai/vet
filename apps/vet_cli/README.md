# vet_cli

Mix tasks for [Vet](https://github.com/code-of-kai/vet), a static-analysis security scanner for Elixir dependencies.

## Installation

```elixir
def deps do
  [
    {:vet_cli, "~> 0.1", only: :dev, runtime: false}
  ]
end
```

## Usage

```bash
mix vet         # full dependency scan
mix vet.check   # pre-install check (reads mix.exs)
```

See the [main README](https://github.com/code-of-kai/vet) for full documentation.
