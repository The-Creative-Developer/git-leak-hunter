/**
 * Severity classification: a pure, table-driven function. The first matching row wins.
 * Documented in docs/RULES.md; per-rule overrides come from the config file.
 */
import type { Detector, Presence, Severity, VerificationStatus } from '../types.js';
import type { PathClass } from './fileKind.js';

export interface SeverityInput {
  ruleId: string;
  detector: Detector;
  presence: Presence;
  verificationStatus: VerificationStatus;
  pathClass: PathClass;
  weak: boolean;
}

export interface SeverityRow {
  id: string;
  severity: Severity;
  when: (f: SeverityInput) => boolean;
  description: string;
}

const REAL_FORMAT_RULES = new Set([
  'aws-access-key-id',
  'aws-secret-access-key',
  'github-token',
  'github-fine-grained-pat',
  'slack-token',
  'slack-webhook',
  'stripe-live-key',
  'private-key',
]);

export const SEVERITY_TABLE: readonly SeverityRow[] = [
  {
    id: 'verified-active',
    severity: 'critical',
    when: (f) => f.verificationStatus === 'ACTIVE',
    description: 'Live verification returned ACTIVE',
  },
  {
    id: 'private-key-at-head',
    severity: 'critical',
    when: (f) => f.ruleId === 'private-key' && f.presence === 'in-HEAD',
    description: 'Private key still present at HEAD',
  },
  {
    id: 'live-payment-key-at-head',
    severity: 'critical',
    when: (f) => f.ruleId === 'stripe-live-key' && f.presence === 'in-HEAD',
    description: 'Live payment key (sk_live_/rk_live_) still present at HEAD',
  },
  {
    id: 'weak-literal',
    severity: 'low',
    when: (f) => f.weak,
    description: 'Secret-like key with a low-entropy literal value (weak generic match)',
  },
  {
    id: 'real-format-credential',
    severity: 'high',
    when: (f) => f.detector === 'signature' && REAL_FORMAT_RULES.has(f.ruleId),
    description:
      'Signature-matched real-format credential (incl. private keys / live keys in history only)',
  },
  {
    id: 'ci-literal',
    severity: 'high',
    when: (f) => f.detector === 'ci',
    description: 'Literal secret in CI/CD configuration (GitHub Actions, GitLab CI, Dockerfile)',
  },
  {
    id: 'credential-file',
    severity: 'high',
    when: (f) => f.detector === 'credential-file',
    description:
      'Secret in a committed credential file (.env, id_rsa, .npmrc, credentials.json, …)',
  },
  {
    id: 'test-payment-key',
    severity: 'medium',
    when: (f) => f.ruleId === 'stripe-test-key',
    description: 'Stripe test-mode key',
  },
  {
    id: 'entropy-non-app',
    severity: 'low',
    when: (f) => f.detector === 'entropy' && f.pathClass !== 'app',
    description: 'Entropy-only candidate in tests, docs, examples or fixtures',
  },
  {
    id: 'entropy-app',
    severity: 'medium',
    when: (f) => f.detector === 'entropy',
    description: 'Entropy-only candidate in application code',
  },
  {
    id: 'default',
    severity: 'low',
    when: () => true,
    description: 'Anything else',
  },
];

export type SeverityOverrides = Readonly<Record<string, Severity>>;

export function classifySeverity(f: SeverityInput, overrides: SeverityOverrides = {}): Severity {
  if (f.verificationStatus === 'ACTIVE') return 'critical';
  const override = overrides[f.ruleId];
  if (override) return override;
  for (const row of SEVERITY_TABLE) if (row.when(f)) return row.severity;
  return 'low';
}
