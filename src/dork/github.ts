/**
 * Minimal GitHub REST client for `dork`. Every request goes through the same host allowlist as
 * verification (api.github.com only, https, no redirects, 10 s timeout). Requests are sequential
 * and paced per rate-limit bucket (code search allows 10 requests/minute); a rate-limit response
 * stops the run instead of retrying. The token is sent only in the Authorization header and never
 * appears in messages.
 */
import { OID_RE } from '../git/exec.js';
import { guardedFetch, type FetchLike } from '../verify/http.js';
import { VERSION } from '../version.js';
import { DorkScopeError, type OwnerType } from './queries.js';

export const API = 'https://api.github.com';
/** Code search: 10 requests per minute → one every 6.5 s with margin. */
export const DEFAULT_SEARCH_DELAY_MS = 6_500;
export const DEFAULT_CORE_DELAY_MS = 250;

export class RateLimitedError extends Error {
  constructor(readonly resource: 'search' | 'core') {
    super(`GitHub ${resource} rate limit reached; stopping (no retries)`);
    this.name = 'RateLimitedError';
  }
}

export class GitHubApiError extends Error {
  constructor(
    readonly status: number,
    what: string,
  ) {
    super(`GitHub API ${what} failed with HTTP ${status}`);
    this.name = 'GitHubApiError';
  }
}

export interface CodeSearchItem {
  path: string;
  sha: string;
  repository: { full_name: string; fork?: boolean };
}

export interface CommitInfo {
  sha: string;
  commit: { author?: { name?: string; email?: string; date?: string }; message?: string };
}

export interface GitHubApiOptions {
  token: string;
  fetchImpl?: FetchLike;
  searchDelayMs?: number;
  coreDelayMs?: number;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
const FULL_NAME = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/;

export class GitHubApi {
  private readonly fetchImpl: FetchLike;
  private readonly last: Record<'search' | 'core', number> = { search: 0, core: 0 };
  calls = { search: 0, core: 0 };

  constructor(private readonly opts: GitHubApiOptions) {
    this.fetchImpl = opts.fetchImpl ?? ((url, init) => globalThis.fetch(url, init));
  }

  private async get<T>(
    path: string,
    resource: 'search' | 'core',
    what: string,
    accept = 'application/vnd.github+json',
  ): Promise<{ status: number; data: T | null }> {
    const gap =
      resource === 'search'
        ? (this.opts.searchDelayMs ?? DEFAULT_SEARCH_DELAY_MS)
        : (this.opts.coreDelayMs ?? DEFAULT_CORE_DELAY_MS);
    const wait = this.last[resource] + gap - Date.now();
    if (this.last[resource] > 0 && wait > 0) await sleep(wait);
    this.last[resource] = Date.now();
    this.calls[resource]++;
    const res = await guardedFetch(this.fetchImpl, `${API}${path}`, {
      method: 'GET',
      headers: {
        authorization: `Bearer ${this.opts.token}`,
        accept,
        'x-github-api-version': '2022-11-28',
        'user-agent': `git-leak-hunter/${VERSION}`,
      },
    });
    const limited =
      res.status === 429 ||
      (res.status === 403 &&
        (res.headers.get('x-ratelimit-remaining') === '0' || res.headers.has('retry-after')));
    if (limited) {
      await res.body?.cancel().catch(() => undefined);
      throw new RateLimitedError(resource);
    }
    if (res.status !== 200) {
      await res.body?.cancel().catch(() => undefined);
      if (res.status === 404 || res.status === 403) return { status: res.status, data: null };
      throw new GitHubApiError(res.status, what);
    }
    return { status: 200, data: (await res.json()) as T };
  }

  /** Refuse unless the token's account is the owner itself, or an admin of the owner org. */
  async assertControls(owner: string, ownerType: OwnerType): Promise<void> {
    if (ownerType === 'user') {
      const { data } = await this.get<{ login?: string }>('/user', 'core', 'GET /user');
      if (!data?.login) throw new GitHubApiError(401, 'GET /user (is the token valid?)');
      if (data.login.toLowerCase() !== owner.toLowerCase()) {
        throw new DorkScopeError(
          `refusing: the token's account is not "${owner}". dork only searches an owner you control`,
        );
      }
      return;
    }
    const { status, data } = await this.get<{ state?: string; role?: string }>(
      `/user/memberships/orgs/${encodeURIComponent(owner)}`,
      'core',
      'GET /user/memberships/orgs/{org}',
    );
    if (status !== 200 || data?.state !== 'active' || data.role !== 'admin') {
      throw new DorkScopeError(
        `refusing: the token's account is not an active admin of org "${owner}" (needs read:org)`,
      );
    }
  }

  async searchCode(
    q: string,
    perPage: number,
  ): Promise<{ items: CodeSearchItem[]; incomplete: boolean }> {
    const params = new URLSearchParams({
      q,
      per_page: String(Math.min(100, Math.max(1, perPage))),
    });
    const { data } = await this.get<{ items?: CodeSearchItem[]; incomplete_results?: boolean }>(
      `/search/code?${params.toString()}`,
      'search',
      'code search',
    );
    const items = (data?.items ?? []).filter(
      (i) =>
        typeof i.path === 'string' &&
        OID_RE.test(i.sha) &&
        FULL_NAME.test(i.repository?.full_name ?? ''),
    );
    return { items, incomplete: Boolean(data?.incomplete_results) };
  }

  async blob(fullName: string, sha: string): Promise<Buffer | null> {
    const { data } = await this.get<{ content?: string; encoding?: string }>(
      `/repos/${fullName}/git/blobs/${sha}`,
      'core',
      'GET blob',
    );
    if (!data?.content || data.encoding !== 'base64') return null;
    return Buffer.from(data.content, 'base64');
  }

  async lastCommit(fullName: string, path: string): Promise<CommitInfo | null> {
    const params = new URLSearchParams({ path, per_page: '1' });
    const { data } = await this.get<CommitInfo[]>(
      `/repos/${fullName}/commits?${params.toString()}`,
      'core',
      'GET commits',
    );
    const c = data?.[0];
    return c && OID_RE.test(c.sha) ? c : null;
  }
}
