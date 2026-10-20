import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * Rule 4: this repository must never contain a token-shaped literal. Fixture secrets are assembled
 * at runtime from fragments; this test guards against someone pasting one in.
 */
const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SCAN_DIRS = ['src', 'test', 'bench', 'docs', 'schema', 'examples', '.github'];
const SCAN_FILES = ['README.md', 'CLAUDE.md', 'package.json'];

const TOKEN_SHAPES: Array<[string, RegExp]> = [
  ['aws-key-id', /\b(?:AKIA|ASIA|AIDA)[0-9A-Z]{16}\b/],
  ['github', /\bgh[pousr]_[A-Za-z0-9]{36}\b/],
  ['github-pat', /\bgithub_pat_[A-Za-z0-9_]{22,}/],
  ['stripe', /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}/],
  ['slack-token', /\bxox[abprs]-[0-9]+-/],
  ['slack-webhook', /hooks\.slack\.com\/services\/T[A-Z0-9]+\/B/],
  ['private-key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
];

async function walk(dir: string): Promise<string[]> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const out: string[] = [];
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...(await walk(p)));
    else out.push(p);
  }
  return out;
}

describe('repository hygiene', () => {
  it('contains no token-shaped literals', async () => {
    const files = [
      ...(await Promise.all(SCAN_DIRS.map((d) => walk(path.join(ROOT, d))))).flat(),
      ...SCAN_FILES.map((f) => path.join(ROOT, f)),
    ];
    const hits: string[] = [];
    for (const file of files) {
      let content: string;
      try {
        content = await readFile(file, 'utf8');
      } catch {
        continue;
      }
      for (const [name, re] of TOKEN_SHAPES) {
        if (re.test(content)) hits.push(`${path.relative(ROOT, file)} (${name})`);
      }
    }
    expect(hits).toEqual([]);
  });
});

describe('dogfooding', () => {
  it('this repository’s own committed history scans clean with git-leak-hunter', async () => {
    const { runScan } = await import('../../src/pipeline.js');
    const { defaultOptions } = await import('../helpers/scan.js');
    const res = await runScan({ target: ROOT, outDir: '', formats: [], options: defaultOptions() });
    expect(res.report.findings.map((f) => `${f.ruleId} ${f.filePath}:${f.line}`)).toEqual([]);
  });
});
