import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { VERSION } from '../../src/version.js';

const CLI = fileURLToPath(new URL('../../src/cli.ts', import.meta.url));

function run(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      ['--import', 'tsx', CLI, ...args],
      { encoding: 'utf8' },
      (err, stdout, stderr) => {
        const code = err ? (typeof err.code === 'number' ? err.code : 1) : 0;
        resolve({ code, stdout, stderr });
      },
    );
  });
}

describe('cli skeleton', () => {
  it('prints help with the responsible-use rules', async () => {
    const res = await run(['--help']);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain('Responsible use');
    expect(res.stdout).toContain('Never exploit discovered credentials');
  });

  it('documents every scan option', async () => {
    const res = await run(['scan', '--help']);
    expect(res.code).toBe(0);
    for (const flag of [
      '--out',
      '--format',
      '--max-commits',
      '--since',
      '--branch',
      '--no-ci',
      '--no-cache',
      '--entropy-hex',
      '--entropy-base64',
      '--min-length',
      '--ignore',
      '--fail-on',
      '--verify',
      '--confirm-authorized',
      '--quiet',
      '--verbose',
    ]) {
      expect(res.stdout).toContain(flag);
    }
  });

  it('prints the version', async () => {
    const res = await run(['--version']);
    expect(res.stdout.trim()).toBe(VERSION);
  });

  it('exits 2 on usage errors', async () => {
    expect((await run(['scan', '.', '--fail-on', 'urgent'])).code).toBe(2);
    expect((await run(['scan', '.', '--format', 'pdf'])).code).toBe(2);
    expect((await run(['scan'])).code).toBe(2);
  });
});
