export type Action = "allow" | "monitor" | "sanitize" | "block" | "alert";
export type Severity = "low" | "medium" | "high" | "critical";

export interface AuditEvent {
  event_id: string;
  timestamp: string;
  request_id?: string;
  source?: string;
  action?: Action;
  severity?: Severity;
  risk_score?: number;
  attack_types?: string[];
  tenant_id?: string;
  user_id?: string;
}

export interface Stats {
  total: number;
  blocked: number;
  alerted: number;
  detection_rate: number;
  avg_risk_score: number;
  action_counts: Record<string, number>;
  attack_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  risk_buckets: Record<string, number>;
}

export interface RedTeamFailure {
  test_id: string;
  category: string;
  expected_action: Action;
  actual_action: Action;
  risk_score: number;
}

export interface RedTeamResult {
  suite: string;
  total_tests: number;
  passed: number;
  failed: number;
  pass_rate: number;
  missed_attack_types: string[];
  report_id: string;
  failures: RedTeamFailure[];
}
