/**
 * Accuracy benchmark: Git Leak Hunter vs Gitleaks vs TruffleHog on the same fixture repos.
 * Each tool runs with its default rules, in a non-network mode, without live verification.
 * Findings are matched to ground-truth.json by (repo, file path, line).
 *
 *   npx tsx bench/accuracy.ts            → bench/results/accuracy.json
 *
 * A tool that is not installed is recorded as "not run" — nothing is estimated.
 * Results hold rule ids, paths and line numbers only; never secret values.
 */
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { buildAllFixtures, type GroundTruth } from '../test/fixtures/buildRepos.js';
import { VERSION } from '../src/version.js';
import { collectEnv, type BenchEnv } from './env.js';

const run = promisify(execFile);
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const RESULTS = path.join(ROOT, 'bench', 'results');

interface ToolFinding {
  repo: string;
  path: string;
  line: number;
  rule: string;
}

interface ToolSpec {
  name: string;
  /** Returns version string, or null if the tool is not installed. */
  version(): Promise<string | null>;
  /** Command template shown in the docs (`<repo>`, `<out>` placeholders). */
  command: string;
  scan(repoDir: string, repoName: string, outDir: string): Promise<ToolFinding[]>;
  install?: string;
}

async function which(bin: string): Promise<string | null> {
  try {
    const { stdout } = await run('which', [bin]);
    return stdout.trim() || null;
  } catch {
    return null;
  }
}

const gitLeakHunter: ToolSpec = {
  name: 'git-leak-hunter',
  async version() {
    const { stdout } = await run('git', ['rev-parse', '--short', 'HEAD'], { cwd: ROOT }).catch(
      () => ({ stdout: 'unknown' }),
    );
    return `${VERSION} (commit ${stdout.trim()})`;
  },
  command: 'node --import tsx src/cli.ts scan <repo> --format json --out <out> --quiet',
  async scan(repoDir, repoName, outDir) {
    await run(
      process.execPath,
      [
        '--import',
        'tsx',
        path.join(ROOT, 'src/cli.ts'),
        'scan',
        repoDir,
        '--format',
        'json',
        '--out',
        outDir,
        '--quiet',
      ],
      { cwd: ROOT, maxBuffer: 64 << 20 },
    );
    const report = JSON.parse(await readFile(path.join(outDir, 'report.json'), 'utf8')) as {
      findings: Array<{ filePath: string; line: number; ruleId: string }>;
    };
    return report.findings.map((f) => ({
      repo: repoName,
      path: f.filePath,
      line: f.line,
      rule: f.ruleId,
    }));
  },
};

const gitleaks: ToolSpec = {
  name: 'gitleaks',
  async version() {
    if (!(await which('gitleaks'))) return null;
    const { stdout } = await run('gitleaks', ['version']);
    return stdout.trim();
  },
  command:
    'gitleaks git <repo> --report-format json --report-path <out>/gitleaks.json --redact --no-banner --exit-code 0 --log-level error',
  install: 'brew install gitleaks  (or see https://github.com/gitleaks/gitleaks#installing)',
  async scan(repoDir, repoName, outDir) {
    const report = path.join(outDir, 'gitleaks.json');
    await run(
      'gitleaks',
      [
        'git',
        repoDir,
        '--report-format',
        'json',
        '--report-path',
        report,
        '--redact',
        '--no-banner',
        '--exit-code',
        '0',
        '--log-level',
        'error',
      ],
      { maxBuffer: 64 << 20 },
    );
    const findings = JSON.parse(await readFile(report, 'utf8')) as Array<{
      File: string;
      StartLine: number;
      RuleID: string;
    }>;
    return findings.map((f) => ({
      repo: repoName,
      path: f.File,
      line: f.StartLine,
      rule: f.RuleID,
    }));
  },
};

const trufflehog: ToolSpec = {
  name: 'trufflehog',
  async version() {
    if (!(await which('trufflehog'))) return null;
    const { stdout, stderr } = await run('trufflehog', ['--version']);
    return (stdout || stderr).trim();
  },
  command: 'trufflehog git file://<repo> --json --no-verification --no-update',
  install:
    'brew install trufflehog  (or see https://github.com/trufflesecurity/trufflehog#floppy_disk-installation)',
  async scan(repoDir, repoName) {
    const { stdout } = await run(
      'trufflehog',
      ['git', `file://${repoDir}`, '--json', '--no-verification', '--no-update'],
      { maxBuffer: 64 << 20 },
    );
    const out: ToolFinding[] = [];
    for (const line of stdout.split('\n')) {
      if (!line.trim().startsWith('{')) continue;
      const r = JSON.parse(line) as {
        DetectorName?: string;
        SourceMetadata?: { Data?: { Git?: { file?: string; line?: number } } };
      };
      const g = r.SourceMetadata?.Data?.Git;
      if (g?.file && typeof g.line === 'number')
        out.push({ repo: repoName, path: g.file, line: g.line, rule: r.DetectorName ?? 'unknown' });
    }
    return out;
  },
};

interface RepoScore {
  repo: string;
  planted: number;
  tp: number;
  fp: number;
  fn: number;
  fnIds: string[];
  /** Planted secret id → rule ids the tool reported at its location. */
  matched: Record<string, string[]>;
  fpLocations: Array<{ path: string; line: number; rules: string[]; onBait: boolean }>;
  rawFindings: number;
  durationMs: number;
}

export interface ToolResult {
  tool: string;
  status: 'ran' | 'not run' | 'failed';
  version: string | null;
  command: string;
  install?: string;
  error?: string;
  totals?: {
    planted: number;
    tp: number;
    fp: number;
    fn: number;
    precision: number | null;
    recall: number | null;
    rawFindings: number;
  };
  repos?: RepoScore[];
}

export interface AccuracyResults {
  generatedAt: string;
  env: BenchEnv;
  seed: number;
  matching: string;
  tools: ToolResult[];
}

function score(
  gt: GroundTruth['repos'][number],
  findings: ToolFinding[],
  durationMs: number,
): RepoScore {
  const key = (p: string, l: number) => `${p}\0${l}`;
  const secrets = gt.items.filter((i) => i.kind === 'secret');
  const secretKeys = new Set(secrets.map((s) => key(s.filePath, s.line)));
  const baitKeys = new Set(
    gt.items.filter((i) => i.kind === 'bait').map((b) => key(b.filePath, b.line)),
  );
  const toolKeys = new Map<string, Set<string>>();
  for (const f of findings) {
    const k = key(f.path, f.line);
    toolKeys.set(k, (toolKeys.get(k) ?? new Set()).add(f.rule));
  }
  const matched = secrets.filter((s) => toolKeys.has(key(s.filePath, s.line)));
  const fpLocations = [...toolKeys.entries()]
    .filter(([k]) => !secretKeys.has(k))
    .map(([k, rules]) => {
      const [p, l] = k.split('\0') as [string, string];
      return { path: p, line: Number(l), rules: [...rules].sort(), onBait: baitKeys.has(k) };
    });
  return {
    repo: gt.name,
    planted: secrets.length,
    tp: matched.length,
    fp: fpLocations.length,
    fn: secrets.length - matched.length,
    fnIds: secrets.filter((s) => !matched.includes(s)).map((s) => `${s.id} (${s.category})`),
    matched: Object.fromEntries(
      matched.map((s) => [s.id, [...(toolKeys.get(key(s.filePath, s.line)) ?? [])].sort()]),
    ),
    fpLocations,
    rawFindings: findings.length,
    durationMs: Math.round(durationMs),
  };
}

async function main(): Promise<void> {
  const tmp = await mkdtemp(path.join(os.tmpdir(), 'glh-bench-acc-'));
  try {
    const seed = 1337;
    const built = await buildAllFixtures(path.join(tmp, 'repos'), seed);
    const gt = JSON.parse(await readFile(built.manifestPath, 'utf8')) as GroundTruth;
    const tools: ToolResult[] = [];
    for (const tool of [gitLeakHunter, gitleaks, trufflehog]) {
      const version = await tool.version();
      const base = {
        tool: tool.name,
        version,
        command: tool.command,
        ...(tool.install ? { install: tool.install } : {}),
      };
      if (version === null) {
        tools.push({ ...base, status: 'not run' });
        process.stderr.write(`${tool.name}: not installed — not run\n`);
        continue;
      }
      try {
        const repos: RepoScore[] = [];
        for (const repo of gt.repos) {
          const out = path.join(tmp, 'out', tool.name, repo.name);
          await mkdir(out, { recursive: true });
          const t0 = performance.now();
          const findings = await tool.scan(path.join(tmp, 'repos', repo.path), repo.name, out);
          repos.push(score(repo, findings, performance.now() - t0));
        }
        const sum = (k: 'planted' | 'tp' | 'fp' | 'fn' | 'rawFindings') =>
          repos.reduce((a, r) => a + r[k], 0);
        const tp = sum('tp');
        const fp = sum('fp');
        const fn = sum('fn');
        tools.push({
          ...base,
          status: 'ran',
          totals: {
            planted: sum('planted'),
            tp,
            fp,
            fn,
            precision: tp + fp > 0 ? tp / (tp + fp) : null,
            recall: tp + fn > 0 ? tp / (tp + fn) : null,
            rawFindings: sum('rawFindings'),
          },
          repos,
        });
        process.stderr.write(`${tool.name}: TP=${tp} FP=${fp} FN=${fn}\n`);
      } catch (err) {
        tools.push({
          ...base,
          status: 'failed',
          error: err instanceof Error ? err.message.split('\n')[0]! : String(err),
        });
      }
    }
    const results: AccuracyResults = {
      generatedAt: new Date().toISOString(),
      env: await collectEnv(),
      seed,
      matching:
        'A tool finding is a true positive when its (repo, file path, line) equals a planted secret in ground-truth.json; several reports of the same planted secret count once. Each distinct unmatched (repo, path, line) is one false positive. Planted secrets never matched are false negatives.',
      tools,
    };
    await mkdir(RESULTS, { recursive: true });
    await writeFile(path.join(RESULTS, 'accuracy.json'), JSON.stringify(results, null, 2) + '\n');
    process.stderr.write(`wrote ${path.relative(ROOT, path.join(RESULTS, 'accuracy.json'))}\n`);
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
}

await main();
