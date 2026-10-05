import {
  DashboardSummary,
  Finding,
  Scan,
  ScanFile,
  ScanList,
  ScanReport,
  Severity,
} from '../app/core/scans/scan.models';

/** Shared by the specs only - nothing here is imported by application code. */

let sequence = 0;

/** A distinct, well-formed id per call, so fixtures never collide in `track` expressions. */
function nextId(): string {
  sequence += 1;
  return `00000000-0000-4000-8000-${String(sequence).padStart(12, '0')}`;
}

export function makeScan(overrides: Partial<Scan> = {}): Scan {
  return {
    id: nextId(),
    source_type: 'SNIPPET',
    status: 'COMPLETED',
    progress_percent: 100,
    error_message: null,
    total_files: 1,
    total_findings: 0,
    created_at: '2026-10-05T10:00:00Z',
    started_at: '2026-10-05T10:00:01Z',
    completed_at: '2026-10-05T10:02:00Z',
    ...overrides,
  };
}

export function makeScanList(scans: Scan[], overrides: Partial<ScanList> = {}): ScanList {
  return { scans, total: scans.length, limit: 10, offset: 0, ...overrides };
}

export function makeScanFile(overrides: Partial<ScanFile> = {}): ScanFile {
  return {
    id: nextId(),
    filename: 'app.py',
    relative_path: 'app.py',
    language: 'python',
    size_bytes: 120,
    loc: 5,
    ...overrides,
  };
}

export function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: nextId(),
    scan_file_id: null,
    title: 'SQL injection',
    severity: 'HIGH',
    confidence: 0.9,
    cwe_id: 'CWE-89',
    owasp_category: null,
    attack_technique_id: null,
    file_path: 'app.py',
    line_start: 4,
    line_end: 5,
    vulnerable_snippet:
      '    query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n    return conn.execute(query)',
    explanation: 'User input is concatenated into the SQL query.',
    recommendation: 'Use a parameterized query.',
    fixed_code: 'conn.execute("SELECT * FROM users WHERE name = ?", (name,))',
    references: [
      {
        source: 'CWE',
        ref_id: 'CWE-89',
        title: 'SQL Injection',
        url: 'https://cwe.mitre.org/data/definitions/89.html',
      },
    ],
    ...overrides,
  };
}

export function makeReport(
  scan: Scan = makeScan(),
  findings: Finding[] = [],
  files: ScanFile[] = [makeScanFile()],
): ScanReport {
  const severity_counts: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };
  for (const finding of findings) {
    severity_counts[finding.severity] += 1;
  }
  return { scan: { ...scan, total_findings: findings.length }, severity_counts, files, findings };
}

export function makeSummary(overrides: Partial<DashboardSummary> = {}): DashboardSummary {
  return {
    total_scans: 0,
    scans_by_status: { PENDING: 0, RUNNING: 0, COMPLETED: 0, FAILED: 0 },
    total_findings: 0,
    findings_by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
    top_cwes: [],
    recent_scans: [],
    ...overrides,
  };
}
