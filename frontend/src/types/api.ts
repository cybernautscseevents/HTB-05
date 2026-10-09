/**
 * Canonical domain models and API contracts matching the ACSA backend.
 * Real data contracts only - no arbitrary or fabricated fields.
 */

export type Verdict =
  | 'PROVEN_EXPOSURE'
  | 'PROVEN_AFFECTED'
  | 'POTENTIALLY_AFFECTED'
  | 'PROVEN_NOT_AFFECTED'
  | 'UNKNOWN'
  | 'CONTRADICTORY'
  | 'NOT_VERIFIED';

export type ApplicabilityStatus = 'AFFECTED' | 'NOT_AFFECTED' | 'UNKNOWN';

export type ReachabilityState = 'REACHABLE' | 'NOT_REACHABLE' | 'UNKNOWN';

export type AttackerControlStatus = 'CONFIRMED' | 'NOT_ESTABLISHED' | 'UNKNOWN';

export type RemediationStrategy =
  | 'DIRECT_UPGRADE'
  | 'TRANSITIVE_OVERRIDE'
  | 'PARENT_UPGRADE'
  | 'API_REPLACEMENT'
  | 'REMOVE_DEPENDENCY'
  | 'CONFIG_MITIGATION'
  | 'NO_SAFE_CANDIDATE';

export type CandidateStatus =
  | 'PROPOSED'
  | 'ACCEPTED'
  | 'REJECTED'
  | 'REQUIRES_CONFIRMATION'
  | 'CONTRADICTION_BLOCKED'
  | 'NO_SAFE_CANDIDATE';

export type ClosureStatus =
  | 'PROVEN_CLOSED'
  | 'EXPECTED_TO_CLOSE'
  | 'REQUIRES_VERIFICATION';

export type EvidenceConfidence = 'HIGH' | 'MEDIUM' | 'LOW';

export type DependencyRelation = 'DIRECT' | 'TRANSITIVE' | 'UNUSED' | 'UNKNOWN';

export type VerificationStatus =
  | 'PROVEN_REMEDIATED'
  | 'REMEDIATION_PARTIALLY_VERIFIED'
  | 'REQUIRES_VERIFICATION'
  | 'REMEDIATION_FAILED'
  | 'CONTRADICTORY'
  | 'NOT_VERIFIED';

export type TestValidationStatus = 'PASSED' | 'FAILED' | 'NOT_EXECUTED';

export type ProbeType =
  | 'HTTP_INPUT_TO_SINK'
  | 'MODULE_RESOLUTION'
  | 'SYMBOL_INVOCATION'
  | 'ROUTE_EXECUTION'
  | 'DEPENDENCY_VERSION_CONFIRMATION';

export type ProbeEvaluationStatus =
  | 'PENDING'
  | 'CONFIRMED'
  | 'NOT_CONFIRMED'
  | 'INCONCLUSIVE';

export interface SourceLocation {
  file_path: string;
  line_number: number | null;
}

export interface Component {
  name: string;
  version: string | null;
  purl?: string | null;
  is_direct?: boolean;
  manifest_path?: string | null;
  lockfile_path?: string | null;
  declared_range?: string | null;
}

export interface Vulnerability {
  id: string;
  aliases: string[];
  summary: string;
  details: string | null;
  severity: string | null;
  affected_ranges: string[];
  fixed_versions: string[];
  vulnerable_symbols: string[];
  database_specific: Record<string, unknown>;
}

export interface DataFlowStep {
  step_type: string;
  expression: string;
  location: SourceLocation | null;
  description: string;
}

export interface InputSource {
  source_type: string;
  expression: string;
  location: SourceLocation;
  entry_point: string | null;
}

export interface ContextAnalysis {
  status: AttackerControlStatus;
  source: InputSource | null;
  entry_point: string | null;
  sink: string | null;
  sink_location: SourceLocation | null;
  data_flow_path: string[];
  data_flow_steps: DataFlowStep[];
  uncertainty_reason: string | null;
  missing_evidence: string | null;
  confidence: number;
  evidence_ids: string[];
  metadata: Record<string, unknown>;
}

export interface ReachabilityAnalysis {
  status: ReachabilityState;
  target_symbol: string | null;
  entry_point: string | null;
  call_site: string | null;
  evidence_path: string[];
  uncertainty_reason: string | null;
  missing_evidence: string | null;
  confidence: number;
  evidence_ids: string[];
  metadata: Record<string, unknown>;
}

export interface Finding {
  id: string;
  vulnerability: Vulnerability;
  component: Component;
  verdict: Verdict;
  applicability_status: ApplicabilityStatus;
  source_observation_id: string | null;
  source_artifact_path: string | null;
  source: string;
  evidence_ids: string[];
  confidence: number;
  created_at: string;
  notes: string | null;
  reachability: ReachabilityAnalysis | null;
  context: ContextAnalysis | null;
  uncertainty_reason: string | null;
  missing_evidence: string | null;
}

export interface Evidence {
  id: string;
  source: string;
  evidence_type: string;
  description: string;
  provenance: Record<string, unknown>;
  confidence: number;
  created_at: string;
}

export interface CanonicalInventory {
  components: Record<string, Component>;
  observations: Record<string, unknown>;
  contradictions: Array<Record<string, unknown>>;
  is_contradictory: boolean;
  sources: string[];
}

export interface VulnerabilityScanResult {
  repository_path: string;
  inventory: CanonicalInventory;
  findings: Finding[];
  vulnerabilities: Vulnerability[];
  evidence: Evidence[];
  queries_executed: number;
  exact_versions_queried: number;
  advisories_count: number;
  affected_count: number;
  not_affected_count: number;
  unknown_count: number;
  osv_available: boolean;
  errors: string[];
  from_cache_count: number;
  reachability_evaluated: boolean;
  context_evaluated: boolean;
  fusion_evaluated: boolean;
  proven_exposure_count: number;
  proven_affected_count: number;
  potentially_affected_count: number;
  proven_not_affected_count: number;
  contradictory_count: number;
}

export interface RemediationCandidate {
  candidate_id: string;
  strategy: RemediationStrategy;
  package_name: string;
  current_version: string;
  target_version: string | null;
  target_component?: string | null;
  proposed_version?: string | null;
  files_changed: string[];
  dependencies_affected: string[];
  api_impact: string;
  version_impact: string;
  closure_status: ClosureStatus;
  confidence_level: EvidenceConfidence;
  confidence?: string | number | null;
  lockfile_action: string;
  closed_advisories_count: number;
  total_advisories_count: number;
  closed_paths_count: number;
  total_paths_count: number;
  reason: string;
  evidence_ids: string[];
  preconditions: string[];
  expected_effect: string;
  status: CandidateStatus;
  simulated_patch: string | null;
}

export interface RemediationAnalysisResult {
  finding_id: string;
  package_name: string;
  current_version: string;
  verdict: Verdict;
  advisories: string[];
  dependency_relation: DependencyRelation;
  parent_package?: string | null;
  candidates: RemediationCandidate[];
  selected_candidate?: RemediationCandidate | null;
  verification_spec?: unknown | null;
  blast_radius_explanation?: string;
}

export interface RemediationReport {
  repository_path: string;
  total_findings_evaluated: number;
  remediated_findings_count?: number;
  results?: RemediationAnalysisResult[];
  generated_at?: string;

  // Optional fields for UI view compatibility and helper derived properties
  candidates_generated?: number;
  contradictions_detected?: number;
  candidates?: RemediationCandidate[];
  manifest_patches?: Record<string, string>;
  lockfile_regeneration_required?: boolean;
  summary?: string;
  created_at?: string;
}

export interface ProofConditions {
  version_closed: boolean;
  advisories_closed: boolean;
  vulnerable_symbol_closed: boolean;
  exposure_path_closed: boolean;
  tests_validated: boolean;
  test_status: TestValidationStatus;
  test_reason: string | null;
}

export interface EvidenceSnapshot {
  phase: string;
  repository_identity: string;
  component: string;
  version: string | null;
  advisories: string[];
  verdict: Verdict;
  reachability_status: ReachabilityState;
  reachable_symbols: string[];
  exposure_paths: string[];
}

export interface ProofVerificationItem {
  candidate: string;
  target_component: string;
  strategy: string;
  before: EvidenceSnapshot;
  after: EvidenceSnapshot;
  proof_conditions: ProofConditions;
  evidence: string[];
  verification_status: VerificationStatus;
  uncertainty_reason: string | null;
  missing_evidence: string | null;
  final_verdict: Verdict;
}

export interface VerifyRemediationResponse {
  repository_path: string;
  verification_mode: string;
  total_candidates_verified: number;
  proven_remediated_count: number;
  requires_verification_count: number;
  failed_count: number;
  results: ProofVerificationItem[];
  summary?: string | null;
  warning?: string | null;
  message?: string | null;
}

export interface ProbeSpecification {
  probe_id: string;
  finding_id: string;
  probe_type: ProbeType;
  target_component: string;
  target_symbol: string | null;
  entry_point: string | null;
  input_source: string | null;
  uncertainty_reason: string;
  missing_evidence: string;
  required_observation: string;
  success_condition: string;
  failure_condition: string;
  safety_constraints: string[];
  expected_verdict_if_confirmed: Verdict;
  expected_verdict_if_not_confirmed: Verdict;
  priority_rank: number;
  status: ProbeEvaluationStatus;
  created_at: string;
  metadata: Record<string, unknown>;
}

export interface ProbeObservation {
  probe_id: string;
  finding_id: string;
  observed: boolean | null;
  evidence_payload: Record<string, unknown>;
  observed_at?: string;
  observer_notes?: string | null;
}

export interface ProbeEvaluation {
  evaluation_id: string;
  probe_id: string;
  finding_id: string;
  evaluation_status: ProbeEvaluationStatus;
  original_verdict: Verdict;
  resolved_verdict: Verdict;
  rationale: string;
  updated_evidence_ids: string[];
  evaluated_at: string;
}

export interface ProbePlanReport {
  repository_path: string;
  total_unknown_findings: number;
  total_probes_generated: number;
  probes_by_type: Record<string, number>;
  probes: ProbeSpecification[];
  summary: string;
  created_at: string;
}

export interface HealthResponse {
  status: string;
  service: string;
}
