/** report.json — built from Findings (which carry no raw secrets) and measured stats. */
import {
  SEVERITIES,
  type Finding,
  type Report,
  type ScanOptions,
  type ScanStats,
} from '../types.js';
import { VERSION } from '../version.js';

export interface ReportParts {
  target: string;
  head: string | null;
  startedAt: Date;
  finishedAt: Date;
  configHash: string;
  options: ScanOptions;
  stats: ScanStats;
  findings: Finding[];
}

export function buildReport(p: ReportParts): Report {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of p.findings) bySeverity[f.severity]++;
  const inHead = p.findings.filter((f) => f.presence === 'in-HEAD').length;
  return {
    schemaVersion: '1.0',
    tool: { name: 'git-leak-hunter', version: VERSION },
    repository: { target: p.target, head: p.head },
    scan: {
      startedAt: p.startedAt.toISOString(),
      finishedAt: p.finishedAt.toISOString(),
      configHash: p.configHash,
      options: p.options,
    },
    summary: {
      total: p.findings.length,
      bySeverity,
      inHead,
      historyOnly: p.findings.length - inHead,
    },
    stats: p.stats,
    findings: p.findings,
  };
}

export function renderJson(report: Report): string {
  return JSON.stringify(report, null, 2) + '\n';
}

export function severityLine(report: Report): string {
  return SEVERITIES.map((s) => `${report.summary.bySeverity[s]} ${s}`).join(', ');
}
