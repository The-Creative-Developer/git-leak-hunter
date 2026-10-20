/**
 * GitHub: exactly one read-only call, `GET https://api.github.com/user`. The response body (which
 * names the account) is never read; only the status code and rate-limit headers are used.
 */
import { VERSION } from '../version.js';
import type { CheckResult } from './aws.js';
import { guardedFetch, type FetchLike } from './http.js';

export const GITHUB_USER_URL = 'https://api.github.com/user';

export async function checkGitHub(fetchImpl: FetchLike, token: string): Promise<CheckResult> {
  let res: Response;
  try {
    res = await guardedFetch(fetchImpl, GITHUB_USER_URL, {
      method: 'GET',
      headers: {
        authorization: `Bearer ${token}`,
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
        'user-agent': `git-leak-hunter/${VERSION}`,
      },
    });
  } catch (err) {
    if (err instanceof Error && err.name === 'HostNotAllowedError') throw err;
    return { status: 'UNVERIFIABLE', note: 'GitHub request failed (network/timeout)' };
  }
  await res.body?.cancel().catch(() => undefined);
  const remaining = res.headers.get('x-ratelimit-remaining');
  if (res.status === 200) return { status: 'ACTIVE', note: 'GitHub GET /user returned 200' };
  if (res.status === 401) return { status: 'INACTIVE', note: 'GitHub GET /user returned 401' };
  if (
    res.status === 429 ||
    (res.status === 403 && (remaining === '0' || res.headers.has('retry-after')))
  ) {
    return { status: 'UNVERIFIABLE', note: 'GitHub rate limit reached', stop: true };
  }
  return { status: 'UNVERIFIABLE', note: `GitHub GET /user returned ${res.status}` };
}
