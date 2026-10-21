/**
 * The only network path in the tool besides `git clone` (used by `--verify` and `dork`). Hard allowlist of exact hosts, https
 * only, no redirects (a redirect could point anywhere), 10 s timeout, no retries.
 */
export const VERIFY_HOST_ALLOWLIST: ReadonlySet<string> = new Set([
  'sts.amazonaws.com',
  'api.github.com',
]);
export const VERIFY_TIMEOUT_MS = 10_000;

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export class HostNotAllowedError extends Error {
  constructor(host: string) {
    super(`network request refused: host "${host}" is not on the allowlist`);
    this.name = 'HostNotAllowedError';
  }
}

export function assertAllowedUrl(url: string): URL {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new HostNotAllowedError('(invalid URL)');
  }
  if (
    u.protocol !== 'https:' ||
    u.username ||
    u.password ||
    u.port ||
    !VERIFY_HOST_ALLOWLIST.has(u.hostname)
  ) {
    throw new HostNotAllowedError(u.hostname || '(none)');
  }
  return u;
}

export async function guardedFetch(
  fetchImpl: FetchLike,
  url: string,
  init: RequestInit,
): Promise<Response> {
  assertAllowedUrl(url);
  return fetchImpl(url, {
    ...init,
    redirect: 'error',
    signal: AbortSignal.timeout(VERIFY_TIMEOUT_MS),
  });
}
