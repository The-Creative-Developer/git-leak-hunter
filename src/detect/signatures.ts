/**
 * Layer 1 — deterministic signatures for known credential formats. Patterns are written with
 * character classes so this file never contains a token-shaped literal.
 */
import type { Candidate } from './types.js';
import { computeLineOffsets, lineColumn } from '../text.js';

export interface SignatureRule {
  id: string;
  secretType: string;
  /** Global regex; capture group 1 is the secret. */
  pattern: RegExp;
}

export const SIGNATURE_RULES: readonly SignatureRule[] = [
  {
    id: 'aws-access-key-id',
    secretType: 'AWS Access Key',
    pattern: /(?<![A-Za-z0-9])((?:AKIA|ASIA|AIDA)[A-Z0-9]{16})(?![A-Za-z0-9])/g,
  },
  {
    id: 'github-token',
    secretType: 'GitHub Token',
    pattern: /(?<![A-Za-z0-9_])((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})(?![A-Za-z0-9])/g,
  },
  {
    id: 'github-fine-grained-pat',
    secretType: 'GitHub Fine-grained Token',
    pattern: /(?<![A-Za-z0-9_])(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})(?![A-Za-z0-9])/g,
  },
  {
    id: 'stripe-live-key',
    secretType: 'Stripe Live Key',
    pattern: /(?<![A-Za-z0-9_])((?:sk|rk)_live_[A-Za-z0-9]{16,})(?![A-Za-z0-9])/g,
  },
  {
    id: 'stripe-test-key',
    secretType: 'Stripe Test Key',
    pattern: /(?<![A-Za-z0-9_])((?:sk|rk)_test_[A-Za-z0-9]{16,})(?![A-Za-z0-9])/g,
  },
  {
    id: 'slack-token',
    secretType: 'Slack Token',
    pattern: /(?<![A-Za-z0-9])(xox[abprs]-[0-9A-Za-z]{6,}(?:-[0-9A-Za-z]+)+)(?![A-Za-z0-9-])/g,
  },
  {
    id: 'slack-webhook',
    secretType: 'Slack Webhook',
    pattern:
      /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{6,}\/B[A-Z0-9]{6,}\/[A-Za-z0-9]{16,})/g,
  },
];

/** Private keys: header through matching footer (or 200 lines if the footer is missing). */
const PRIVATE_KEY_HEADER = /-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----/g;
const MAX_KEY_LINES = 200;

/** 40-char AWS secret access key; only considered within AWS_PAIR_WINDOW lines of a key ID. */
const AWS_SECRET = /(?<![A-Za-z0-9/+=])([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])/g;
export const AWS_PAIR_WINDOW = 5;
/** Character cap on the pairing window, so one huge line cannot make pairing quadratic. */
export const AWS_PAIR_MAX_CHARS = 1024;

export function findSignatureCandidates(content: string): Candidate[] {
  const out: Candidate[] = [];

  for (const rule of SIGNATURE_RULES) {
    for (const m of content.matchAll(rule.pattern)) {
      const value = m[1] ?? '';
      const start = (m.index ?? 0) + m[0].indexOf(value);
      out.push({
        ruleId: rule.id,
        secretType: rule.secretType,
        detector: 'signature',
        start,
        end: start + value.length,
        value,
        entropyRequired: false,
      });
    }
  }

  for (const m of content.matchAll(PRIVATE_KEY_HEADER)) {
    const label = m[1] ?? 'PRIVATE KEY';
    const start = m.index ?? 0;
    const footer = `-----END ${label}-----`;
    const footerAt = content.indexOf(footer, start);
    let end: number;
    if (footerAt >= 0) {
      end = footerAt + footer.length;
    } else {
      end = start;
      for (let i = 0; i < MAX_KEY_LINES; i++) {
        const nl = content.indexOf('\n', end + 1);
        if (nl < 0) {
          end = content.length;
          break;
        }
        end = nl;
      }
    }
    const value = content.slice(start, end);
    const lines = value.split(/\\n|\n/).length;
    out.push({
      ruleId: 'private-key',
      secretType: 'Private Key',
      detector: 'signature',
      start,
      end,
      value,
      entropyRequired: false,
      // Header label only, without the PEM armor dashes, so reports never look like a key file.
      preview: `BEGIN ${label} [REDACTED, ${lines} lines]`,
    });
  }

  addAwsSecretPairs(content, out);
  return out;
}

function addAwsSecretPairs(content: string, out: Candidate[]): void {
  const keyIds = out.map((c, i) => ({ c, i })).filter(({ c }) => c.ruleId === 'aws-access-key-id');
  if (keyIds.length === 0) return;
  const offsets = computeLineOffsets(content);
  const taken = new Set<number>();
  for (const { c, i } of keyIds) {
    const { line } = lineColumn(offsets, c.start);
    const from = Math.max(
      offsets[Math.max(0, line - 1 - AWS_PAIR_WINDOW)] ?? 0,
      c.start - AWS_PAIR_MAX_CHARS,
    );
    const to = Math.min(
      offsets[line + AWS_PAIR_WINDOW] ?? content.length,
      c.end + AWS_PAIR_MAX_CHARS,
    );
    const window = content.slice(from, to);
    let best: { start: number; value: string; distance: number } | null = null;
    for (const m of window.matchAll(AWS_SECRET)) {
      const value = m[1] ?? '';
      const start = from + (m.index ?? 0);
      if (taken.has(start) || /^[0-9a-f]+$/i.test(value)) continue;
      const distance = Math.abs(start - c.start);
      if (!best || distance < best.distance) best = { start, value, distance };
    }
    if (!best) continue;
    taken.add(best.start);
    out.push({
      ruleId: 'aws-secret-access-key',
      secretType: 'AWS Secret Access Key',
      detector: 'signature',
      start: best.start,
      end: best.start + best.value.length,
      value: best.value,
      entropyRequired: true,
      pairWith: i,
    });
    c.pairWith = out.length - 1;
  }
}
