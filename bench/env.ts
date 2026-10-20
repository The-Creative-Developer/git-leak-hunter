/** Environment captured at benchmark run time, embedded in every results file. */
import { execFile } from 'node:child_process';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const ROOT = fileURLToPath(new URL('..', import.meta.url));

export interface BenchEnv {
  ranAt: string;
  os: string;
  cpu: string;
  cores: number;
  memoryGiB: number;
  node: string;
  git: string;
  gitLeakHunterCommit: string;
}

async function out(cmd: string, args: string[]): Promise<string> {
  try {
    return (await run(cmd, args, { cwd: ROOT })).stdout.trim();
  } catch {
    return 'unknown';
  }
}

export async function collectEnv(): Promise<BenchEnv> {
  return {
    ranAt: new Date().toISOString(),
    os: `${os.type()} ${os.release()} ${os.arch()}`,
    cpu: os.cpus()[0]?.model ?? 'unknown',
    cores: os.cpus().length,
    memoryGiB: Math.round(os.totalmem() / 2 ** 30),
    node: process.version,
    git: await out('git', ['--version']),
    gitLeakHunterCommit: await out('git', ['rev-parse', '--short', 'HEAD']),
  };
}
