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

export interface Recommendation {
  id: string;
  type: string;
  priority: number;
  title: string;
  description: string;
  evidence: string[];
  impact_estimate: number;
  affected_techniques: string[];
  affected_csf: string[];
  detection_id?: number;
}

export interface RecommendationResponse {
  recommendations: Recommendation[];
  total_count: number;
  by_type: Record<string, number>;
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
