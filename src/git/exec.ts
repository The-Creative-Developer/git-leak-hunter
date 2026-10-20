/**
 * The only place that spawns `git`. Always an argv array (never a shell), with config overrides
 * that stop a hostile repository's own config from running commands during read-only operations.
 */
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';

/**
 * `-c` overrides applied to every invocation. They win over the target repo's `.git/config`.
 * - hooksPath: no hooks ever run.
 * - fsmonitor: a repo-configured fsmonitor command would otherwise run on index access.
 * - pager: never spawn a pager.
 * - protocol.*: only https and ssh transports (blocks `ext::` command transports and file://).
 */
export const SAFE_GIT_CONFIG: readonly string[] = [
  '-c',
  'core.hooksPath=/dev/null',
  '-c',
  'core.fsmonitor=false',
  '-c',
  'core.pager=cat',
  '-c',
  'protocol.allow=never',
  '-c',
  'protocol.https.allow=always',
  '-c',
  'protocol.ssh.allow=always',
  '-c',
  'submodule.recurse=false',
];

/** Environment for git: strips variables that redirect git to other repositories. */
export function gitEnv(): NodeJS.ProcessEnv {
  const keep = ['GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_ASKPASS', 'GIT_EXEC_PATH'];
  const env: NodeJS.ProcessEnv = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_') || keep.includes(key)),
  );
  env.GIT_TERMINAL_PROMPT = '0';
  env.GIT_OPTIONAL_LOCKS = '0';
  env.LC_ALL = 'C';
  return env;
}

export class GitError extends Error {
  constructor(
    message: string,
    readonly exitCode: number | null,
  ) {
    super(message);
    this.name = 'GitError';
  }
}

/** Remove URL credentials (`https://user:token@host`) from any text before it is shown. */
export function stripUrlCredentials(text: string): string {
  return text.replace(/([a-z][a-z0-9+.-]*:\/\/)[^/\s@]+@/gi, '$1');
}

/** First line of git's stderr, credentials stripped, length-capped. Never includes file content. */
function summariseStderr(stderr: string): string {
  const line = stderr.split('\n').find((l) => l.trim().length > 0) ?? '';
  return stripUrlCredentials(line.trim()).slice(0, 300);
}

export interface RunGitOptions {
  /** Repository directory (`git -C <dir>`); omitted for clone. */
  dir?: string;
  input?: string | Buffer;
  /** Return instead of throwing on non-zero exit. */
  allowFail?: boolean;
}

export interface RunGitResult {
  code: number;
  stdout: Buffer;
  stderr: string;
}

export function spawnGit(args: readonly string[], dir?: string): ChildProcessWithoutNullStreams {
  const argv = [...SAFE_GIT_CONFIG, ...(dir ? ['-C', dir] : []), '--no-pager', ...args];
  const child = spawn('git', argv, { env: gitEnv(), stdio: ['pipe', 'pipe', 'pipe'] });
  // git may exit before reading stdin; the resulting EPIPE is reported via the exit code instead.
  child.stdin.on('error', () => undefined);
  return child;
}

/** Run git to completion, buffering stdout. Use `spawnGit` for large/streaming output. */
export function runGit(args: readonly string[], opts: RunGitOptions = {}): Promise<RunGitResult> {
  return new Promise((resolve, reject) => {
    const child = spawnGit(args, opts.dir);
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on('data', (d: Buffer) => out.push(d));
    child.stderr.on('data', (d: Buffer) => err.push(d));
    child.on('error', (e) => reject(new GitError(`could not run git: ${e.message}`, null)));
    child.on('close', (code) => {
      const stderr = Buffer.concat(err).toString('utf8');
      if (code !== 0 && !opts.allowFail) {
        reject(new GitError(`git ${args[0] ?? ''} failed: ${summariseStderr(stderr)}`, code));
        return;
      }
      resolve({ code: code ?? -1, stdout: Buffer.concat(out), stderr });
    });
    child.stdin.end(opts.input ?? '');
  });
}

export async function gitText(args: readonly string[], dir: string): Promise<string> {
  return (await runGit(args, { dir })).stdout.toString('utf8');
}

export const OID_RE = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
