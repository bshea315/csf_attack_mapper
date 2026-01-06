// User types
export interface User {
  id: number;
  username: string;
  email: string;
  role: 'admin' | 'editor' | 'viewer';
  is_active: boolean;
  created_at: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface AuthToken {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

// Detection types
export interface SplArtifacts {
  indexes: string[];
  sourcetypes: string[];
  datamodels: string[];
  macros: string[];
  fields_referenced: string[];
  commands_used: string[];
  time_constraints: Record<string, string> | null;
  aggregations: Record<string, string[]> | null;
  thresholds: Array<{ field: string; operator: string; value: number }>;
  complexity_score: number | null;
  complexity_signals: Record<string, unknown> | null;
}

export interface MitreMappingSummary {
  technique_id: string;
  technique_name: string;
  confidence: number;
  method: string;
  is_accepted: boolean;
}

export interface CsfImpactSummary {
  csf_id: string;
  function: string;
  impact_score: number;
}

export interface LinkedPlaybookSummary {
  id: number;
  playbook_id: string;
  name: string;
  is_active: boolean;
  link_type: string;
}

export interface Detection {
  id: number;
  detection_id: string;
  name: string;
  description: string | null;
  spl: string;
  severity: string | null;
  status: string;
  owner_team: string | null;
  original_mitre_tags: string[] | null;
  data_source_notes: string | null;
  created_at: string;
  updated_at: string;
  spl_artifacts?: SplArtifacts;
  mitre_mappings: MitreMappingSummary[];
  csf_impacts: CsfImpactSummary[];
  linked_playbook_count: number;
  linked_playbooks: LinkedPlaybookSummary[];
}

export interface DetectionListResponse {
  items: Detection[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

// MITRE types
export interface MitreTechnique {
  id: string;
  name: string;
  description: string | null;
  tactics: string[];
  platforms: string[];
  data_sources: string[];
  is_subtechnique: boolean;
  parent_technique_id: string | null;
  url: string | null;
  detection_count: number;
}

// CSF types
export interface CsfCategory {
  id: string;
  function: string;
  category: string;
  subcategory: string | null;
  name: string;
  description: string | null;
  detection_count: number;
  coverage_score: number;
}

// Analytics types
export interface OverviewStats {
  total_detections: number;
  enabled_detections: number;
  disabled_detections: number;
  enabled_percentage: number;
  techniques_covered: number;
  total_techniques: number;
  technique_coverage_percentage: number;
  csf_functions_covered: number;
  average_csf_coverage: number;
  last_ingest_at: string | null;
}

export interface TechniqueCoverage {
  technique_id: string;
  technique_name: string;
  tactics: string[];
  detection_count: number;
  weighted_coverage: number;
  is_subtechnique: boolean;
  parent_technique_id: string | null;
  url: string | null;
  // Added when grouping with subtechniques
  subtechniques?: TechniqueCoverage[];
  aggregated_detection_count?: number;
  tactic?: string;
}

export interface AttackCoverageResponse {
  tactics: string[];
  techniques_by_tactic: Record<string, TechniqueCoverage[]>;
  total_techniques: number;
  covered_techniques: number;
  coverage_percentage: number;
  top_covered: TechniqueCoverage[];
  uncovered: Array<{ technique_id: string; technique_name: string }>;
}

export interface CsfFunctionCoverage {
  function: string;
  categories: Array<{
    id: string;
    name: string;
    category: string;
    detection_count: number;
    score: number;
  }>;
  total_subcategories: number;
  covered_subcategories: number;
  total_categories: number;
  covered_categories: number;
  average_score: number;
  detection_count: number;
}

export interface CsfCoverageResponse {
  functions: CsfFunctionCoverage[];
  overall_score: number;
  govern_score: number;
  identify_score: number;
  protect_score: number;
  detect_score: number;
  respond_score: number;
  recover_score: number;
}

export interface GapItem {
  type: string;
  id: string;
  name: string;
  severity: string;
  description: string;
  recommendation: string;
  impact_estimate: number;
  detection_id?: number;
}

export interface GapAnalysisResponse {
  technique_gaps: GapItem[];
  csf_gaps: GapItem[];
  quality_issues: GapItem[];
  total_gaps: number;
  critical_gaps: number;
  high_priority_items: GapItem[];
}

// Score breakdown for enhanced recommendation engine
export interface ScoreBreakdown {
  coverage_gap: number;
  impact: number;
  effort: number;
  risk: number;
}

export interface Recommendation {
  id: string;
  type: string;
  priority: number;
  priority_score?: number;  // New: actual calculated score
  title: string;
  description: string;
  evidence: string[];
  impact_estimate: number;
  affected_techniques: string[];
  affected_csf: string[];
  detection_id?: number;
  score_breakdown?: ScoreBreakdown;  // New: detailed scoring breakdown
  rationale?: string;  // New: human-readable explanation
  // Legacy fields for backwards compatibility
  related_techniques?: string[];
  category?: string;
  estimated_impact?: string;
  effort?: string;
}

export interface RecommendationResponse {
  recommendations: Recommendation[];
  total_count: number;
  returned_count?: number;  // New: number actually returned (may be less than total)
  by_type: Record<string, number>;
  scoring_weights?: Record<string, number>;  // New: weights used for scoring
}

// Ingest types
export interface IngestBatch {
  id: number;
  source_type: string;
  source_filename: string | null;
  total_records: number | null;
  successful: number;
  failed: number;
  warnings: string[];
  status: string;
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
}

// Reprocess types
export interface ReprocessRequest {
  use_enhanced_mapper: boolean;
  confirmation: string;
}

export interface ReprocessResponse {
  total_detections: number;
  successful: number;
  failed: number;
  errors: string[];
  mapper_type: string;
}

// ============================================================================
// Splunk Configuration Types
// ============================================================================

export interface SplunkConfig {
  id: number;
  name: string;
  base_url: string;
  auth_type: 'token' | 'basic';
  verify_tls: boolean;
  es_app_namespace: string;
  es_owner: string;
  soar_playbook_run_index: string;
  soar_action_run_index: string;
  soar_time_window_days: number;
  has_token: boolean;
  has_password: boolean;
  is_active: boolean;
  last_es_sync_at: string | null;
  last_soar_sync_at: string | null;
  es_detection_count: number;
  soar_playbook_count: number;
  soar_run_count: number;
  created_at: string;
  updated_at: string;
}

export interface SplunkConfigCreate {
  name?: string;
  base_url: string;
  auth_type: 'token' | 'basic';
  auth_token?: string;
  auth_username?: string;
  auth_password?: string;
  verify_tls?: boolean;
  es_app_namespace?: string;
  es_owner?: string;
  soar_playbook_run_index?: string;
  soar_action_run_index?: string;
  soar_time_window_days?: number;
}

export interface SplunkConnectionTestResponse {
  success: boolean;
  message: string;
  server_info?: {
    version: string;
    build: string;
    server_name: string;
    os_name: string;
    license_state: string;
  };
  error?: string;
}

export interface ESSyncResponse {
  success: boolean;
  total_found: number;
  created: number;
  updated: number;
  unchanged: number;
  failed: number;
  errors: string[];
  duration_seconds: number;
}

export interface SOARSyncRequest {
  days: number;
}

export interface SOARSyncResponse {
  success: boolean;
  playbook_runs_found: number;
  playbook_runs_created: number;
  action_runs_found: number;
  action_runs_created: number;
  playbooks_discovered: number;
  errors: string[];
  duration_seconds: number;
}

// ============================================================================
// Playbook and SOAR Types
// ============================================================================

export interface Playbook {
  id: number;
  playbook_id: string;
  name: string;
  description: string | null;
  is_active: boolean;
  category: string | null;
  time_saved_minutes: number;
  avg_manual_time_minutes: number | null;
  created_at: string;
  updated_at: string;
  run_count: number;
  success_rate: number | null;
  linked_detection_count: number;
  total_time_saved_hours: number;
}

export interface PlaybookUpdate {
  name?: string;
  description?: string;
  is_active?: boolean;
  category?: string;
  time_saved_minutes?: number;
  avg_manual_time_minutes?: number;
}

export interface PlaybookListResponse {
  items: Playbook[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface PlaybookRun {
  id: number;
  playbook_run_id: string;
  playbook_id: number | null;
  playbook_name: string | null;
  status: string;
  start_time: string | null;
  end_time: string | null;
  duration_seconds: number | null;
  container_id: string | null;
  event_time: string | null;
  action_count: number;
  successful_actions: number;
  failed_actions: number;
  created_at: string;
}

export interface PlaybookRunListResponse {
  items: PlaybookRun[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface ActionMetrics {
  action_name: string;
  app_name: string | null;
  total_runs: number;
  successful_runs: number;
  failed_runs: number;
  success_rate: number;
  avg_duration_seconds: number | null;
  common_errors?: string[];
}

export interface PlaybookMetrics {
  playbook_id: number;
  playbook_name: string;
  category: string | null;
  total_runs: number;
  successful_runs: number;
  failed_runs: number;
  success_rate: number;
  avg_duration_seconds: number | null;
  p50_duration_seconds?: number | null;
  p95_duration_seconds?: number | null;
  last_run_at: string | null;
  linked_detections: number;
  time_saved_per_run_minutes: number;
  total_time_saved_hours: number;
}

export interface PlaybookTimeSaved {
  playbook_id: number;
  playbook_name: string;
  category: string | null;
  successful_runs: number;
  time_saved_per_run_minutes: number;
  total_time_saved_minutes: number;
  total_time_saved_hours: number;
}

export interface AppMetrics {
  app_name: string;
  total_actions: number;
  successful_actions: number;
  failed_actions: number;
  success_rate: number;
  unique_action_types: number;
  avg_action_duration: number | null;
}

export interface SOAROverviewMetrics {
  total_playbooks: number;
  active_playbooks: number;
  playbooks_with_time_config: number;
  total_runs: number;
  successful_runs: number;
  failed_runs: number;
  cancelled_runs: number;
  overall_success_rate: number;
  total_actions: number;
  avg_actions_per_run: number;
  unique_action_types: number;
  unique_apps: number;
  avg_run_duration_seconds: number | null;
  median_run_duration_seconds: number | null;
  runs_last_24h: number;
  runs_last_7d: number;
  runs_last_30d: number;
  total_time_saved_minutes: number;
  total_time_saved_hours: number;
  estimated_cost_savings: number;
  linked_detections: number;
  unlinked_detections: number;
  automation_coverage_percent: number;
  mttr_minutes: number | null;
  automation_rate: number;
}

export interface SOARDashboardResponse {
  overview: SOAROverviewMetrics;
  time_saved_by_playbook: PlaybookTimeSaved[];
  top_playbooks: PlaybookMetrics[];
  top_actions: ActionMetrics[];
  top_apps: AppMetrics[];
  recent_failures: PlaybookRun[];
  time_series: Array<{
    date: string;
    total: number;
    success: number;
    failure: number;
  }>;
  category_breakdown: Array<{
    category: string;
    total_runs: number;
    successful_runs: number;
    failed_runs: number;
    success_rate: number;
  }>;
}

export interface PlaybookStatsResponse {
  playbook: Playbook;
  metrics: PlaybookMetrics;
  action_breakdown: ActionMetrics[];
  recent_runs: PlaybookRun[];
  linked_detections: Array<{
    id: number;
    name: string;
    severity: string;
    link_type: string;
  }>;
}

export interface DetectionPlaybookLinkCreate {
  detection_id: number;
  link_type?: string;
}

export interface DetectionPlaybookLink {
  id: number;
  detection_id: number;
  playbook_id: number;
  link_type: string;
  link_evidence: string | null;
  detection_name: string | null;
  playbook_name: string | null;
  created_by: number | null;
  created_at: string;
}
