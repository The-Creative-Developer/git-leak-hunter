/**
 * GitHub code-search "dorks" — always scoped to exactly one owner. The scope qualifier is added
 * here, never taken from user input, and `assertScopedQuery` refuses anything else.
 */

export type OwnerType = 'user' | 'org';

/** GitHub login rules: alphanumerics and single hyphens, ≤ 39 chars. */
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;

export function validateOwner(owner: string): void {
  if (!OWNER_RE.test(owner))
    throw new DorkScopeError(`invalid GitHub owner name: ${JSON.stringify(owner.slice(0, 50))}`);
}

export class DorkScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DorkScopeError';
  }
}

const j = (...p: string[]): string => p.join('');

/**
 * Search terms for known secret formats and credential files. Prefixes are assembled from
 * fragments (rule 4: no token-shaped literals in this repository).
 */
export const DORK_TERMS: readonly string[] = [
  j('AK', 'IA'),
  j('gh', 'p_'),
  j('github', '_pat_'),
  j('sk', '_live_'),
  j('xo', 'xb-'),
  j('hooks.slack', '.com/services'),
  j('PRIVATE', ' KEY'),
  'filename:.env',
  'filename:id_rsa',
  'filename:.npmrc _authToken',
  'filename:credentials.json',
  'path:.github/workflows password',
  'filename:.gitlab-ci.yml password',
  'filename:Dockerfile password',
];

const SCOPE_QUALIFIER = /(?:^|\s)-?(user|org|repo|owner):(\S+)/gi;

/** Build `<term> user:<owner>` (or org:). Extra user terms may not carry scope qualifiers. */
export function buildQuery(term: string, owner: string, ownerType: OwnerType): string {
  validateOwner(owner);
  if (/(?:^|\s)-?(user|org|repo|owner):/i.test(term)) {
    throw new DorkScopeError(
      'search terms may not contain user:/org:/repo: qualifiers; the owner scope is added automatically',
    );
  }
  const q = `${term.trim()} ${ownerType}:${owner}`;
  assertScopedQuery(q, owner, ownerType);
  return q;
}

/** Refuse any query that is not scoped to exactly this one owner. */
export function assertScopedQuery(q: string, owner: string, ownerType: OwnerType): void {
  const scopes = [...q.matchAll(SCOPE_QUALIFIER)].map(
    (m) => `${(m[1] ?? '').toLowerCase()}:${m[2] ?? ''}`,
  );
  const expected = `${ownerType}:${owner}`;
  if (
    scopes.length !== 1 ||
    scopes[0]?.toLowerCase() !== expected.toLowerCase() ||
    /(?:^|\s)-(user|org):/i.test(q)
  ) {
    throw new DorkScopeError(
      `refusing unscoped or multi-scope query; it must contain exactly "${expected}"`,
    );
  }
  if (/\bOR\b/.test(q))
    throw new DorkScopeError('refusing query with OR: the owner scope must apply to every term');
}
