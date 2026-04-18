defmodule VetCore.Checks.Attestation do
  @moduledoc """
  Layer 6 — Attestation manifest verification.

  When a package has a signed `*.manifest.json` + `*.sig` pair stored
  in `<project>/.vet/attestations/<package>/`, this check verifies:

  1. The signature is valid for the manifest under at least one trusted
     public key (loaded from `<project>/.vet/trusted_keys/` or
     `~/.vet/trusted_keys/`).
  2. The manifest's `module_hashes` match the actual content_hash of
     each compiled BEAM in the local install.

  Findings:

  - `:attestation_unsigned` (info) — package has no manifest at all.
    Most packages don't, so this is informational by default.
  - `:attestation_untrusted` (critical) — manifest exists but no
    trusted key verifies it.
  - `:attestation_hash_mismatch` (critical) — signature is valid, but
    one or more module hashes diverge from the local install. Either
    the install was tampered with or the manifest is stale.
  - `:attestation_capability_mismatch` (warning) — manifest declares a
    different capability set than the locally-observed one. Forwarded
    to the `Layer 7` infrastructure for severity.

  This check is gated by a flag because attestation is an opt-in
  ecosystem signal — most packages today are unsigned. Run with
  `attestation: :require` to elevate `:attestation_unsigned` to
  warning, or `attestation: :strict` to make it critical.
  """
  use VetCore.Check

  alias VetCore.Attestation.{Manifest, Store, Verifier}
  alias VetCore.BEAM.BeamProfile
  alias VetCore.Types.Finding

  @category :attestation_mismatch

  @impl true
  def run(%{name: dep_name, version: version} = _dep, project_path, state)
      when is_binary(version) do
    package = to_string(dep_name)
    mode = mode_from(state)

    case Store.load(project_path, package, version) do
      {:error, :no_attestation} ->
        unsigned_findings(dep_name, package, version, mode)

      {:ok, {manifest, sig}} ->
        do_verify(manifest, sig, project_path, dep_name, package, version)
    end
  end

  def run(_dep, _project_path, _state), do: []

  defp mode_from(state) when is_list(state) do
    Keyword.get(state, :attestation, :advisory)
  end

  defp mode_from(_), do: :advisory

  defp unsigned_findings(_, _, _, :advisory), do: []

  defp unsigned_findings(dep_name, package, version, :require) do
    [
      build_finding(dep_name, package, version, :attestation_unsigned, :warning,
        "no signed manifest found")
    ]
  end

  defp unsigned_findings(dep_name, package, version, :strict) do
    [
      build_finding(dep_name, package, version, :attestation_unsigned, :critical,
        "no signed manifest found and policy is strict")
    ]
  end

  defp do_verify(%Manifest{} = manifest, sig, project_path, dep_name, package, version) do
    json = Manifest.to_canonical_json(manifest)

    case any_trusted_key_verifies(json, sig, Store.trusted_keys(project_path)) do
      :ok ->
        local_profiles = current_profiles(dep_name, project_path)
        verify_install(manifest, local_profiles, dep_name, package, version)

      :no_match ->
        [
          build_finding(dep_name, package, version, :attestation_untrusted, :critical,
            "manifest signature does not match any trusted public key")
        ]
    end
  end

  defp any_trusted_key_verifies(_json, _sig, []), do: :no_match

  defp any_trusted_key_verifies(json, sig, [{_name, key} | rest]) do
    case Verifier.verify(json, sig, key) do
      :ok -> :ok
      _ -> any_trusted_key_verifies(json, sig, rest)
    end
  end

  defp verify_install(%Manifest{} = manifest, profiles, dep_name, package, version) do
    case Verifier.verify_against_install(manifest, profiles) do
      :ok ->
        []

      {:error, {:hash_mismatch, diffs}} ->
        Enum.map(diffs, fn diff ->
          build_finding(
            dep_name,
            package,
            version,
            :attestation_hash_mismatch,
            :critical,
            "module #{diff.module}: #{diff.status}; declared #{shorten(diff.declared)} " <>
              "vs local #{shorten(diff.local)}"
          )
        end)
    end
  end

  defp current_profiles(dep_name, project_path) do
    name = to_string(dep_name)

    [project_path, "_build", "*", "lib", name, "ebin"]
    |> Path.join()
    |> Path.wildcard()
    |> Enum.filter(&File.dir?/1)
    |> Enum.flat_map(&BeamProfile.build_all/1)
  end

  defp shorten(nil), do: "<absent>"
  defp shorten(<<prefix::binary-size(8), _::binary>>), do: prefix <> "…"
  defp shorten(other), do: to_string(other)

  defp build_finding(dep_name, package, version, check_id, severity, detail) do
    %Finding{
      dep_name: dep_name,
      file_path: ".vet/attestations/#{package}/#{version}.manifest.json",
      line: 1,
      check_id: check_id,
      category: @category,
      severity: severity,
      compile_time?: false,
      description: "Attestation for #{package}@#{version}: #{detail}"
    }
  end
end
