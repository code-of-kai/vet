defmodule VetCore.Types do
  @moduledoc false

  defmodule Dependency do
    @moduledoc false
    @enforce_keys [:name]
    defstruct [
      :name,
      :version,
      :hash,
      :source,
      :children,
      direct?: true,
      depth: 1
    ]

    @type source :: :hex | {:git, String.t()} | {:path, String.t()}

    @type t :: %__MODULE__{
            name: atom(),
            version: String.t() | nil,
            hash: String.t() | nil,
            source: source(),
            direct?: boolean(),
            children: [atom()] | nil,
            depth: pos_integer()
          }
  end

  defmodule Finding do
    @moduledoc false
    @enforce_keys [:dep_name, :file_path, :line, :check_id, :category, :severity, :description]
    defstruct [
      :dep_name,
      :file_path,
      :line,
      :column,
      :check_id,
      :category,
      :severity,
      :snippet,
      :description,
      compile_time?: false,
      evidence_level: :pattern_match
    ]

    @type severity :: :info | :warning | :critical

    # Evidence ladder — graduated confidence in a finding.
    # Scorer weights each rung; correlate_findings + llm_review + sandbox
    # promote findings up the ladder as independent signals agree.
    @type evidence_level ::
            :pattern_match
            | :corroborated
            | :sandbox_observed
            | :llm_confirmed
            | :known_incident

    @type category ::
            :system_exec
            | :code_eval
            | :network_access
            | :file_access
            | :env_access
            | :obfuscation
            | :shady_links
            | :compiler_hooks
            | :dos_atom_exhaustion
            | :metadata
            | :phantom_package
            | :version_transition
            | :temporal_anomaly
            | :bytecode_imports
            | :native_code
            | :reflection
            | :bytecode_version_delta
            | :sandboxed_compile_behavior
            | :capability_mismatch
            | :attestation_mismatch

    @type t :: %__MODULE__{
            dep_name: atom(),
            file_path: String.t(),
            line: pos_integer(),
            column: pos_integer() | nil,
            check_id: atom(),
            category: category(),
            severity: severity(),
            compile_time?: boolean(),
            evidence_level: evidence_level(),
            snippet: String.t() | nil,
            description: String.t()
          }
  end

  defmodule HexMetadata do
    @moduledoc false
    defstruct [
      :downloads,
      :latest_version,
      :latest_release_date,
      :previous_version,
      :lookback_version,
      :owner_count,
      :description,
      retired?: false
    ]

    @type t :: %__MODULE__{
            downloads: non_neg_integer() | nil,
            latest_version: String.t() | nil,
            latest_release_date: DateTime.t() | nil,
            previous_version: String.t() | nil,
            lookback_version: String.t() | nil,
            owner_count: non_neg_integer() | nil,
            description: String.t() | nil,
            retired?: boolean()
          }
  end

  defmodule DependencyReport do
    @moduledoc false
    defstruct [
      :dependency,
      :hex_metadata,
      :risk_score,
      :risk_level,
      :version_diff,
      findings: [],
      patches: []
    ]

    @type risk_level :: :low | :medium | :high | :critical

    @type t :: %__MODULE__{
            dependency: Dependency.t(),
            findings: [Finding.t()],
            hex_metadata: HexMetadata.t() | nil,
            risk_score: non_neg_integer(),
            risk_level: risk_level(),
            version_diff: map() | nil,
            patches: [map()]
          }
  end

  defmodule ScanReport do
    @moduledoc false
    defstruct [
      :project_path,
      :timestamp,
      :summary,
      dependency_reports: [],
      allowlist_notes: []
    ]

    @type t :: %__MODULE__{
            project_path: String.t(),
            timestamp: DateTime.t(),
            dependency_reports: [DependencyReport.t()],
            summary: map(),
            allowlist_notes: [map()]
          }
  end
end
