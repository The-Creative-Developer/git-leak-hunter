/**
 * Streaming walk of commit history with `git log --raw -z`: commit metadata plus every changed
 * path and its new blob hash. Merges are diffed against each parent (`-m`) so content introduced
 * only in a conflict resolution or an "evil merge" is not missed.
 */
import { randomBytes } from 'node:crypto';
import { GitError, OID_RE, spawnGit } from './exec.js';
import type { CommitMeta } from '../types.js';

export interface LogEntry {
  commit: CommitMeta;
  path: string;
  blob: string;
  mode: string;
}

export interface WalkOptions {
  /** Commit ids to start from; defaults to all refs (`--all`). */
  revs?: string[];
  maxCommits?: number;
  since?: string;
}

/** Modes whose new side is a blob we can scan: regular, executable, symlink. Gitlinks are skipped. */
const BLOB_MODES = new Set(['100644', '100755', '120000']);
const RAW_META = /^:(\d{6}) (\d{6}) ([0-9a-f]{40,64}) ([0-9a-f]{40,64}) ([A-Z])\d*$/;
const HEADER_FIELDS = 6;

export function buildLogArgs(marker: string, opts: WalkOptions): string[] {
  const args = [
    'log',
    '--topo-order',
    '--reverse',
    '-m',
    '--root',
    '--raw',
    '-z',
    '--no-abbrev',
    '--no-renames',
    '--no-ext-diff',
    '--no-textconv',
    '--no-color',
    `--format=%x00${marker}%x00%H%x00%P%x00%an%x00%ae%x00%aI%x00%s%x00`,
  ];
  if (opts.maxCommits !== undefined) args.push(`--max-count=${opts.maxCommits}`);
  if (opts.since !== undefined) args.push(`--since=${opts.since}`);
  if (opts.revs && opts.revs.length > 0) {
    for (const r of opts.revs) {
      if (!OID_RE.test(r)) throw new GitError('internal: walk revisions must be commit ids', null);
    }
    args.push('--end-of-options', ...opts.revs);
  } else {
    args.push('--all');
  }
  args.push('--');
  return args;
}

/** Splits a byte stream into NUL-terminated UTF-8 tokens. */
async function* nulTokens(stream: AsyncIterable<Buffer>): AsyncGenerator<string> {
  let pending: Buffer = Buffer.alloc(0);
  for await (const chunk of stream) {
    pending = pending.length ? Buffer.concat([pending, chunk]) : chunk;
    let start = 0;
    let idx: number;
    while ((idx = pending.indexOf(0, start)) !== -1) {
      yield pending.subarray(start, idx).toString('utf8');
      start = idx + 1;
    }
    pending = pending.subarray(start);
  }
  if (pending.length > 0) yield pending.toString('utf8');
}

/**
 * Parse the token stream. The commit marker carries a random per-run nonce, so attacker-controlled
 * subjects or paths cannot forge a commit boundary.
 */
export async function* parseLogTokens(
  tokens: AsyncIterable<string>,
  marker: string,
): AsyncGenerator<LogEntry> {
  let commit: CommitMeta | null = null;
  let header: string[] | null = null;
  let meta: RegExpMatchArray | null = null;

  for await (const raw of tokens) {
    if (header) {
      header.push(raw);
      if (header.length === HEADER_FIELDS) {
        const [hash, parents, an, ae, date, subject] = header as [
          string,
          string,
          string,
          string,
          string,
          string,
        ];
        if (!OID_RE.test(hash)) throw new GitError('unexpected git log output (commit id)', null);
        commit = {
          hash,
          parents: parents.split(' ').filter(Boolean),
          author: { name: an, email: ae },
          date,
          subject,
        };
        header = null;
      }
      continue;
    }
    if (meta) {
      const newMode = meta[2] ?? '';
      const newBlob = meta[4] ?? '';
      const status = meta[5];
      meta = null;
      if (commit && status !== 'D' && BLOB_MODES.has(newMode) && !/^0+$/.test(newBlob)) {
        yield { commit, path: raw, blob: newBlob, mode: newMode };
      }
      continue;
    }
    const token = raw.startsWith('\n') ? raw.slice(1) : raw;
    if (token === marker) {
      header = [];
    } else if (token.startsWith(':')) {
      meta = RAW_META.exec(token);
      if (!meta) throw new GitError('unexpected git log output (raw diff line)', null);
    }
    // Empty separator tokens are ignored.
  }
}

export async function* walkLog(dir: string, opts: WalkOptions = {}): AsyncGenerator<LogEntry> {
  const marker = `GLH${randomBytes(12).toString('hex')}`;
  const child = spawnGit(buildLogArgs(marker, opts), dir);
  child.stdin.end();
  const stderr: Buffer[] = [];
  child.stderr.on('data', (d: Buffer) => stderr.push(d));
  const exited = new Promise<number | null>((resolve, reject) => {
    child.on('error', reject);
    child.on('close', resolve);
  });
  let completed = false;
  try {
    yield* parseLogTokens(nulTokens(child.stdout), marker);
    completed = true;
  } finally {
    if (!completed) child.kill();
  }
  const code = await exited;
  if (code !== 0) {
    const first = Buffer.concat(stderr).toString('utf8').split('\n')[0] ?? '';
    throw new GitError(`git log failed: ${first.slice(0, 300)}`, code);
  }
}

export interface TreeEntry {
  path: string;
  blob: string;
  mode: string;
}

/** All blob entries of a commit's tree (`ls-tree -r -z --full-tree`). */
export async function listTree(dir: string, commit: string): Promise<TreeEntry[]> {
  if (!OID_RE.test(commit)) throw new GitError('internal: tree-ish must be a commit id', null);
  const child = spawnGit(['ls-tree', '-r', '-z', '--full-tree', '--end-of-options', commit], dir);
  child.stdin.end();
  const out: TreeEntry[] = [];
  const exited = new Promise<number | null>((resolve, reject) => {
    child.on('error', reject);
    child.on('close', resolve);
  });
  for await (const token of nulTokens(child.stdout)) {
    // "<mode> SP <type> SP <object> TAB <path>"
    const tab = token.indexOf('\t');
    if (tab < 0) continue;
    const [mode, type, oid] = token.slice(0, tab).split(' ');
    if (type === 'blob' && mode && oid && BLOB_MODES.has(mode)) {
      out.push({ path: token.slice(tab + 1), blob: oid, mode });
    }
  }
  if ((await exited) !== 0) throw new GitError('git ls-tree failed', null);
  return out;
}
