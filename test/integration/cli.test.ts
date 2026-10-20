import { execFile } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { FIXTURE_NAMES } from '../fixtures/buildRepos.js';
import { main } from '../../src/cli.js';
import { VERSION } from '../../src/version.js';
import { useFixtures } from '../helpers/fixtures.js';
import { expectNoLeak } from '../helpers/noLeak.js';

const CLI = fileURLToPath(new URL('../../src/cli.ts', import.meta.url));
const fx = useFixtures();

function run(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      ['--import', 'tsx', CLI, ...args],
      { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } },
      (err, stdout, stderr) => {
        const code = err ? (typeof err.code === 'number' ? err.code : 1) : 0;
        resolve({ code, stdout, stderr });
      },
    );
  });
}

describe('cli basics', () => {
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
    expect((await run(['--version'])).stdout.trim()).toBe(VERSION);
  });

  it('exits 2 on usage errors', async () => {
    expect((await run(['scan', '.', '--fail-on', 'urgent'])).code).toBe(2);
    expect((await run(['scan', '.', '--format', 'pdf'])).code).toBe(2);
    expect((await run(['scan'])).code).toBe(2);
  });
});

describe('cli scan end-to-end', () => {
  it.each(FIXTURE_NAMES.map((n) => [n]))(
    '%s: console mirrors the demo and never leaks',
    async (name) => {
      const f = fx.get().fixtures[name];
      const out = path.join(fx.tmp(), 'cli', name);
      const res = await run(['scan', f.dir, '--out', out, '--verbose']);
      expect(res.code).toBe(0);
      expectNoLeak(res.stdout + res.stderr, f.rawSecrets, `${name} stdout/stderr`);
      for (const line of [
        'walking commit history',
        'regex signature scan',
        'entropy analysis',
        'CI/CD config scan',
        'report.html generated',
      ]) {
        expect(res.stdout).toContain(line);
      }
      const n = f.items.filter((i) => i.kind === 'secret').length;
      expect(res.stdout).toContain(`${n} finding${n === 1 ? '' : 's'} detected`);
      expectNoLeak(
        await readFile(path.join(out, 'report.html'), 'utf8'),
        f.rawSecrets,
        `${name} html`,
      );
    },
  );

  it('--fail-on sets exit code 1 at/above the threshold only', async () => {
    const fixtures = fx.get().fixtures;
    const out = path.join(fx.tmp(), 'cli-fail');
    expect(
      (
        await run([
          'scan',
          fixtures['head-secrets'].dir,
          '--out',
          out,
          '--quiet',
          '--fail-on',
          'critical',
        ])
      ).code,
    ).toBe(1);
    expect(
      (
        await run([
          'scan',
          fixtures['history-only'].dir,
          '--out',
          out,
          '--quiet',
          '--fail-on',
          'critical',
        ])
      ).code,
    ).toBe(0);
    expect(
      (
        await run([
          'scan',
          fixtures['history-only'].dir,
          '--out',
          out,
          '--quiet',
          '--fail-on',
          'high',
        ])
      ).code,
    ).toBe(1);
    expect(
      (await run(['scan', fixtures.clean.dir, '--out', out, '--quiet', '--fail-on', 'low'])).code,
    ).toBe(0);
  });

  it('--format json writes only JSON', async () => {
    const out = path.join(fx.tmp(), 'cli-json');
    const res = await run(['scan', fx.get().fixtures.clean.dir, '--out', out, '--format', 'json']);
    expect(res.stdout).toContain('report.json generated');
    expect(res.stdout).not.toContain('report.html generated');
  });

  it('refuses --verify without --confirm-authorized', async () => {
    const res = await run(['scan', fx.get().fixtures.clean.dir, '--out', fx.tmp(), '--verify']);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('--confirm-authorized');
  });

  it('exits 2 with a clean message for a missing repository', async () => {
    const res = await run(['scan', path.join(fx.tmp(), 'does-not-exist')]);
    expect(res.code).toBe(2);
    expect(res.stderr).toMatch(/^error: not a directory/m);
    expect(res.stderr).not.toMatch(/\n\s+at /);
  });

  it('rejects dangerous remote URLs before touching the network', async () => {
    for (const url of [
      'ext::sh -c touch% /tmp/pwned',
      'file:///etc',
      'http://example.test/x.git',
    ]) {
      const res = await run(['scan', url, '--out', fx.tmp()]);
      expect(res.code, url).toBe(2);
    }
  });
});

describe('cli in-process (main)', () => {
  async function capture(args: string[]) {
    let out = '';
    let err = '';
    const code = await main(['node', 'git-leak-hunter', ...args], {
      out: (s) => (out += s),
      err: (s) => (err += s),
    });
    return { code, out, err };
  }

  it('runs a scan with config, ignore and threshold flags', async () => {
    const f = fx.get().fixtures['head-secrets'];
    const cfg = path.join(fx.tmp(), 'cfg.json');
    const ign = path.join(fx.tmp(), 'ign.txt');
    await writeFile(cfg, JSON.stringify({ severity: { 'stripe-test-key': 'critical' } }));
    await writeFile(ign, 'docs/\n');
    const res = await capture([
      'scan',
      f.dir,
      '--out',
      path.join(fx.tmp(), 'inproc'),
      '--config',
      cfg,
      '--ignore',
      ign,
      '--entropy-hex',
      '3',
      '--entropy-base64',
      '4.5',
      '--min-length',
      '20',
      '--max-commits',
      '50',
      '--since',
      '2000-01-01',
      '--branch',
      'main',
      '--no-cache',
      '--verbose',
      '--fail-on',
      'critical',
    ]);
    expect(res.code).toBe(1);
    expect(res.out).toContain('6 findings detected');
    expect(res.out).toContain('3 critical');
    expect(res.out).toContain('skipped: 0 binary, 0 oversize, 1 ignored');
    expectNoLeak(res.out + res.err, f.rawSecrets, 'in-process output');
  });

  it('prints a quiet summary and the --no-ci note', async () => {
    const f = fx.get().fixtures.clean;
    const quiet = await capture(['scan', f.dir, '--out', path.join(fx.tmp(), 'q'), '--quiet']);
    expect(quiet.code).toBe(0);
    expect(quiet.out).not.toContain('walking commit history');
    expect(quiet.out).toContain('0 findings detected');
    const noCi = await capture(['scan', f.dir, '--out', path.join(fx.tmp(), 'q2'), '--no-ci']);
    expect(noCi.out).toContain('CI/CD config scan skipped');
  });

  it('rejects bad --since values and unimplemented --verify', async () => {
    const f = fx.get().fixtures.clean;
    expect((await capture(['scan', f.dir, '--since', '--all'])).code).toBe(2);
    const v = await capture(['scan', f.dir, '--verify', '--confirm-authorized']);
    expect(v.code).toBe(2);
    expect(v.err).toContain('not available');
  });

  it('handles --help and --version in-process', async () => {
    expect((await capture(['--help'])).code).toBe(0);
    expect((await capture(['--version'])).out.trim()).toBe(VERSION);
  });
});
