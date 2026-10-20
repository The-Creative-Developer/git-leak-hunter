/** Decide how a path is parsed. The result is part of the blob-cache key. */
import type { FileKind } from './types.js';
import { isLockfilePath } from './suppress.js';

const ENV_TEMPLATE_SUFFIX = /\.(example|sample|template|tmpl|dist|defaults?|schema)$/i;
const SSH_KEY_NAMES = new Set([
  'id_rsa',
  'id_dsa',
  'id_ecdsa',
  'id_ed25519',
  'id_ecdsa_sk',
  'id_ed25519_sk',
]);

export interface FileKindOptions {
  /** Extra in-repo GitLab CI files discovered from `include:` entries. */
  gitlabIncludes?: ReadonlySet<string>;
  /** Set to false by `--no-ci`. */
  ci?: boolean;
}

export function fileKindOf(filePath: string, opts: FileKindOptions = {}): FileKind {
  const ci = opts.ci !== false;
  const base = filePath.split('/').pop() ?? filePath;

  if (isLockfilePath(filePath)) return 'lockfile';

  if (ci) {
    if (/^\.github\/workflows\/[^/]+\.ya?ml$/.test(filePath)) return 'github-actions';
    if (
      base === '.gitlab-ci.yml' ||
      base.endsWith('.gitlab-ci.yml') ||
      /^\.gitlab\/.+\.ya?ml$/.test(filePath) ||
      opts.gitlabIncludes?.has(filePath)
    ) {
      return 'gitlab-ci';
    }
    if (
      base === 'Dockerfile' ||
      base === 'Containerfile' ||
      base.endsWith('.Dockerfile') ||
      base.startsWith('Dockerfile.')
    ) {
      return 'dockerfile';
    }
  }

  if (base === '.env' || (base.startsWith('.env.') && !ENV_TEMPLATE_SUFFIX.test(base)))
    return 'dotenv';
  if (base === '.npmrc') return 'npmrc';
  if (base === '.pgpass') return 'pgpass';
  if (base === '.netrc' || base === '_netrc') return 'netrc';
  if (base === '.git-credentials') return 'git-credentials';
  if (SSH_KEY_NAMES.has(base)) return 'ssh-key';
  if (base === '.dockercfg' || /(^|\/)\.docker\/config\.json$/.test(filePath))
    return 'docker-config';
  if (/^(credentials|client_secrets?|service[-_]account)[^/]*\.json$/i.test(base))
    return 'credentials-json';
  return 'generic';
}

/** Path class used by the severity table. */
export type PathClass = 'app' | 'test' | 'docs' | 'example' | 'fixture';

export function pathClassOf(filePath: string): PathClass {
  const p = filePath.toLowerCase();
  if (/(^|\/)(fixtures?|testdata|test-data|__fixtures__|mocks?|__mocks__)\//.test(p))
    return 'fixture';
  if (/(^|\/)(tests?|__tests__|specs?|e2e)\//.test(p) || /\.(test|spec)\.[a-z0-9]+$/.test(p))
    return 'test';
  if (/(^|\/)(examples?|samples?|demo)\//.test(p) || /(^|[._-])(example|sample)[._-]/.test(p))
    return 'example';
  if (/(^|\/)docs?\//.test(p) || /\.(md|mdx|rst|adoc|txt)$/.test(p)) return 'docs';
  return 'app';
}
