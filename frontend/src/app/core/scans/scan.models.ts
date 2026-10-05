/** Mirrors the backend's scan, report and dashboard responses (snake_case, as sent on the wire). */

export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
export type SourceType = 'SNIPPET' | 'FILE' | 'ZIP';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type ReferenceSource = 'OWASP' | 'CWE' | 'ATTACK' | 'OTHER';

/** Most severe first - the order reports and charts use. */
export const SEVERITIES: readonly Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export interface Scan {
  id: string;
  source_type: SourceType;
  status: ScanStatus;
  progress_percent: number;
  error_message: string | null;
  total_files: number;
  total_findings: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface ScanList {
  scans: Scan[];
  total: number;
  limit: number;
  offset: number;
}

export interface ScanFile {
  id: string;
  filename: string;
  relative_path: string;
  language: string | null;
  size_bytes: number;
  loc: number;
}

export interface FindingReference {
  source: ReferenceSource;
  ref_id: string;
  title: string;
  url: string | null;
}

export interface Finding {
  id: string;
  scan_file_id: string | null;
  title: string;
  severity: Severity;
  confidence: number;
  cwe_id: string | null;
  owasp_category: string | null;
  attack_technique_id: string | null;
  file_path: string;
  line_start: number;
  line_end: number;
  vulnerable_snippet: string;
  explanation: string;
  recommendation: string;
  fixed_code: string | null;
  references: FindingReference[];
}

export interface ScanReport {
  scan: Scan;
  severity_counts: Record<Severity, number>;
  files: ScanFile[];
  findings: Finding[];
}

export interface CweCount {
  cwe_id: string;
  count: number;
}

export interface DashboardSummary {
  total_scans: number;
  scans_by_status: Record<ScanStatus, number>;
  total_findings: number;
  findings_by_severity: Record<Severity, number>;
  top_cwes: CweCount[];
  recent_scans: Scan[];
}

/** What to scan: pasted code (with an optional language hint), or an uploaded file. */
export type ScanSubmission = { code: string; language: string | null } | { file: File };

/** True while the backend is still working on the scan, i.e. it is worth polling. */
export function isInProgress(status: ScanStatus): boolean {
  return status === 'PENDING' || status === 'RUNNING';
}

const SOURCE_LABELS: Record<SourceType, string> = {
  SNIPPET: 'Snippet',
  FILE: 'File',
  ZIP: 'Archive',
};

export function sourceLabel(source: SourceType): string {
  return SOURCE_LABELS[source];
}
