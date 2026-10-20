/** Open a local repository, or clone a remote URL into a temp dir (bare, no hooks, no checkout). */
import { mkdtemp, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { GitError, OID_RE, runGit, stripUrlCredentials } from './exec.js';

export interface OpenedRepo {
  /** Directory git commands run in (`git -C dir`). */
  dir: string;
  /** Target as given, with URL credentials stripped. Safe to display. */
  target: string;
  displayName: string;
  head: string | null;
  isRemote: boolean;
  cleanup(): Promise<void>;
}

const SCP_LIKE = /^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[A-Za-z0-9._~/-]+$/;

export function isRemoteTarget(target: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(target) || SCP_LIKE.test(target);
}

/** Accept only https://, ssh:// and scp-like ssh URLs. Rejects ext::, file://, option injection. */
export function validateRemoteUrl(target: string): void {
  if (target.startsWith('-') || target.includes('::') || /\s/.test(target)) {
    throw new GitError('refusing suspicious repository URL', null);
  }
  if (SCP_LIKE.test(target)) return;
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    throw new GitError('invalid repository URL', null);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'ssh:') {
    throw new GitError(`unsupported URL scheme ${url.protocol} (use https:// or ssh://)`, null);
  }
}

function displayNameOf(target: string): string {
  const cleaned = stripUrlCredentials(target).replace(/\/+$/, '');
  const base = cleaned.split(/[/:]/).pop() ?? cleaned;
  return base.replace(/\.git$/, '') || cleaned;
}

export async function resolveHead(dir: string): Promise<string | null> {
  const res = await runGit(['rev-parse', '--verify', '--quiet', 'HEAD^{commit}'], {
    dir,
    allowFail: true,
  });
  const oid = res.stdout.toString('utf8').trim();
  return res.code === 0 && OID_RE.test(oid) ? oid : null;
}

export interface OpenOptions {
  /** Called before any network access, e.g. to print the authorization notice. */
  onBeforeClone?: (safeUrl: string) => void;
}

export async function openRepository(target: string, opts: OpenOptions = {}): Promise<OpenedRepo> {
  if (isRemoteTarget(target)) {
    validateRemoteUrl(target);
    const safe = stripUrlCredentials(target);
    opts.onBeforeClone?.(safe);
    const tmp = await mkdtemp(path.join(os.tmpdir(), 'glh-clone-'));
    const cleanup = (): Promise<void> => rm(tmp, { recursive: true, force: true });
    try {
      const dir = path.join(tmp, 'repo.git');
      await runGit(['clone', '--bare', '--quiet', '--template=', '--', target, dir]);
      return {
        dir,
        target: safe,
        displayName: displayNameOf(safe),
        head: await resolveHead(dir),
        isRemote: true,
        cleanup,
      };
    } catch (err) {
      await cleanup();
      throw err;
    }
  }

  const dir = path.resolve(target);
  const st = await stat(dir).catch(() => null);
  if (!st?.isDirectory()) throw new GitError(`not a directory: ${target}`, null);
  const probe = await runGit(['rev-parse', '--git-dir'], { dir, allowFail: true });
  if (probe.code !== 0) throw new GitError(`not a git repository: ${target}`, probe.code);
  return {
    dir,
    target,
    displayName: path.basename(dir),
    head: await resolveHead(dir),
    isRemote: false,
    cleanup: async () => undefined,
  };
}

/** Resolve a user-supplied branch/ref name to a commit id, refusing option-like input. */
export async function resolveRef(dir: string, ref: string): Promise<string> {
  if (ref.startsWith('-') || /[\0\s]/.test(ref)) throw new GitError('invalid ref name', null);
  const res = await runGit(
    ['rev-parse', '--verify', '--quiet', '--end-of-options', `${ref}^{commit}`],
    {
      dir,
      allowFail: true,
    },
  );
  const oid = res.stdout.toString('utf8').trim();
  if (res.code !== 0 || !OID_RE.test(oid))
    throw new GitError(`unknown branch or ref: ${ref}`, res.code);
  return oid;
}
