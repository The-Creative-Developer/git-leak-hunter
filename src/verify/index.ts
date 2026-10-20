/**
 * Stage 3b — optional live verification. Opt-in only (`--verify --confirm-authorized`). Calls are
 * sequential with a delay, never retried, capped per provider, and stop as soon as a provider
 * signals rate limiting. Each unique credential is checked at most once. The vault is cleared
 * when this function returns, whatever happens.
 */
import type { Finding, VerificationStatus } from '../types.js';
import { sortFindings } from '../analyze.js';
import { checkAws, type CheckResult } from './aws.js';
import { checkGitHub } from './github.js';
import type { FetchLike } from './http.js';
import type { Vault } from './vault.js';

export {
  VERIFY_HOST_ALLOWLIST,
  HostNotAllowedError,
  assertAllowedUrl,
  guardedFetch,
} from './http.js';
export { Vault, VERIFIABLE_RULES } from './vault.js';

export interface VerifyOptions {
  fetchImpl?: FetchLike;
  /** Pause between network calls. */
  delayMs?: number;
  maxCallsPerProvider?: number;
  now?: () => Date;
}

export interface VerifySummary {
  active: number;
  inactive: number;
  unverifiable: number;
  calls: { aws: number; github: number };
}

export const DEFAULT_VERIFY_DELAY_MS = 250;
export const DEFAULT_MAX_CALLS_PER_PROVIDER = 25;

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export async function verifyFindings(
  findings: readonly Finding[],
  vaultRefs: ReadonlyMap<string, string>,
  vault: Vault,
  opts: VerifyOptions = {},
): Promise<{ findings: Finding[]; summary: VerifySummary }> {
  const fetchImpl: FetchLike = opts.fetchImpl ?? ((url, init) => globalThis.fetch(url, init));
  const delay = opts.delayMs ?? DEFAULT_VERIFY_DELAY_MS;
  const maxCalls = opts.maxCallsPerProvider ?? DEFAULT_MAX_CALLS_PER_PROVIDER;
  const calls = { aws: 0, github: 0 };
  const stopped = { aws: false, github: false };
  const cache = new Map<string, CheckResult>();
  const results = new Map<string, CheckResult>();
  let first = true;

  const call = async (
    provider: 'aws' | 'github',
    key: string,
    run: () => Promise<CheckResult>,
  ): Promise<CheckResult> => {
    const cached = cache.get(key);
    if (cached) return cached;
    if (stopped[provider])
      return { status: 'UNVERIFIABLE', note: 'skipped: provider rate limit reached' };
    if (calls[provider] >= maxCalls)
      return { status: 'UNVERIFIABLE', note: `skipped: ${maxCalls}-call cap reached` };
    if (!first && delay > 0) await sleep(delay);
    first = false;
    calls[provider]++;
    const result = await run();
    if (result.stop) stopped[provider] = true;
    cache.set(key, result);
    return result;
  };
  const unverifiable = (note: string): CheckResult => ({ status: 'UNVERIFIABLE', note });
  const byFp = new Map(findings.map((f) => [f.fingerprint, f]));

  try {
    for (const f of findings) {
      if (results.has(f.fingerprint)) continue;
      const ref = vaultRefs.get(f.fingerprint);
      const raw = ref === undefined ? undefined : vault.get(ref);

      if (f.ruleId === 'github-token' || f.ruleId === 'github-fine-grained-pat') {
        results.set(
          f.fingerprint,
          raw
            ? await call('github', `gh:${ref}`, () => checkGitHub(fetchImpl, raw))
            : unverifiable('raw value unavailable'),
        );
      } else if (f.ruleId === 'aws-access-key-id' || f.ruleId === 'aws-secret-access-key') {
        const pair = f.pairedFingerprint ? byFp.get(f.pairedFingerprint) : undefined;
        const [idF, secretF] = f.ruleId === 'aws-access-key-id' ? [f, pair] : [pair, f];
        const idRef = idF ? vaultRefs.get(idF.fingerprint) : undefined;
        const secretRef = secretF ? vaultRefs.get(secretF.fingerprint) : undefined;
        const keyId = idRef ? vault.get(idRef) : undefined;
        const secret = secretRef ? vault.get(secretRef) : undefined;
        let result: CheckResult;
        if (!keyId || !secret) result = unverifiable('no paired AWS key ID / secret access key');
        else if (!keyId.startsWith('AKIA'))
          result = unverifiable('temporary or non-user key: needs a session token');
        else
          result = await call('aws', `aws:${idRef}|${secretRef}`, () =>
            checkAws(fetchImpl, keyId, secret, opts.now?.()),
          );
        for (const x of [idF, secretF]) if (x) results.set(x.fingerprint, result);
      }
    }
  } finally {
    vault.clear();
  }

  const count = (s: VerificationStatus): number =>
    [...results.values()].filter((r) => r.status === s).length;
  const updated = findings.map((f): Finding => {
    const r = results.get(f.fingerprint);
    if (!r) return f;
    return {
      ...f,
      verificationStatus: r.status,
      verificationNote: r.note,
      ...(r.status === 'ACTIVE' ? { severity: 'critical' as const } : {}),
    };
  });
  return {
    findings: sortFindings(updated),
    summary: {
      active: count('ACTIVE'),
      inactive: count('INACTIVE'),
      unverifiable: count('UNVERIFIABLE'),
      calls,
    },
  };
}
