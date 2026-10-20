/**
 * AWS: exactly one read-only call, `sts:GetCallerIdentity`, signed with the paired key ID and
 * secret. The response body is inspected only for an error code; the account ID and ARN it
 * contains are discarded and never stored.
 */
import type { VerificationStatus } from '../types.js';
import { guardedFetch, type FetchLike } from './http.js';
import { amzDateOf, signRequest } from './sigv4.js';

export const STS_URL = 'https://sts.amazonaws.com/';
const BODY = 'Action=GetCallerIdentity&Version=2011-06-15';
const INACTIVE_CODES = new Set([
  'InvalidClientTokenId',
  'SignatureDoesNotMatch',
  'ExpiredToken',
  'AccessDenied',
]);

export interface CheckResult {
  status: VerificationStatus;
  note: string;
  /** Provider asked us to slow down: stop making further calls to it. */
  stop?: boolean;
}

export async function checkAws(
  fetchImpl: FetchLike,
  accessKeyId: string,
  secretAccessKey: string,
  now = new Date(),
): Promise<CheckResult> {
  const { headers } = signRequest({
    method: 'POST',
    host: 'sts.amazonaws.com',
    path: '/',
    query: '',
    headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
    body: BODY,
    region: 'us-east-1',
    service: 'sts',
    accessKeyId,
    secretAccessKey,
    amzDate: amzDateOf(now),
  });
  let res: Response;
  try {
    res = await guardedFetch(fetchImpl, STS_URL, { method: 'POST', headers, body: BODY });
  } catch (err) {
    if (err instanceof Error && err.name === 'HostNotAllowedError') throw err;
    return { status: 'UNVERIFIABLE', note: 'STS request failed (network/timeout)' };
  }
  const text = await res.text().catch(() => '');
  const code = /<Code>([A-Za-z]+)<\/Code>/.exec(text)?.[1];
  if (res.status === 200) return { status: 'ACTIVE', note: 'STS GetCallerIdentity succeeded' };
  if (code && /Throttl/.test(code))
    return { status: 'UNVERIFIABLE', note: 'STS throttled', stop: true };
  if (code && INACTIVE_CODES.has(code))
    return { status: 'INACTIVE', note: `STS rejected the key (${code})` };
  return { status: 'UNVERIFIABLE', note: `STS returned HTTP ${res.status}` };
}
