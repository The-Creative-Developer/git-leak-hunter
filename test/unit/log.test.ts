import { describe, expect, it } from 'vitest';
import { buildLogArgs, parseLogTokens } from '../../src/git/log.js';

async function* from(tokens: string[]) {
  yield* tokens;
}

const H1 = '1'.repeat(40);
const H2 = '2'.repeat(40);
const B = (c: string) => c.repeat(40);
const meta = (mode: string, blob: string, status: string) =>
  `\n:000000 ${mode} ${'0'.repeat(40)} ${blob} ${status}`;

describe('parseLogTokens', () => {
  it('parses commits and changed blobs; skips deletions and gitlinks', async () => {
    const M = 'GLHnonce';
    const tokens = [
      '',
      M,
      H1,
      '',
      'Ann',
      'ann@example.test',
      '2025-01-01T00:00:00Z',
      'first',
      '',
      meta('100644', B('a'), 'A'),
      'src/a.ts',
      meta('160000', B('b'), 'A'),
      'vendor/sub',
      meta('000000', '0'.repeat(40), 'D'),
      'gone.txt',
      '',
      M,
      H2,
      H1,
      'Bob',
      'bob@example.test',
      '2025-01-02T00:00:00Z',
      'second',
      '',
      meta('100755', B('c'), 'M'),
      'bin/run',
    ];
    const out = [];
    for await (const e of parseLogTokens(from(tokens), M))
      out.push([e.commit.hash, e.path, e.blob]);
    expect(out).toEqual([
      [H1, 'src/a.ts', B('a')],
      [H2, 'bin/run', B('c')],
    ]);
  });

  it('is not confused by subjects or paths that look like markers or raw lines', async () => {
    const M = 'GLHreal';
    const tokens = [
      '',
      M,
      H1,
      '',
      'Eve',
      'e@example.test',
      '2025-01-01T00:00:00Z',
      'GLHfake',
      '',
      meta('100644', B('a'), 'A'),
      ':100644 100644 x y M',
    ];
    const out = [];
    for await (const e of parseLogTokens(from(tokens), M)) out.push(e.path);
    expect(out).toEqual([':100644 100644 x y M']);
  });
});

describe('buildLogArgs', () => {
  it('walks all refs by default and puts -- last', () => {
    const args = buildLogArgs('M', {});
    expect(args).toContain('--all');
    expect(args).toContain('-m');
    expect(args.at(-1)).toBe('--');
  });

  it('only accepts commit ids as revisions', () => {
    expect(() => buildLogArgs('M', { revs: ['--output=/tmp/x'] })).toThrow();
    expect(buildLogArgs('M', { revs: [H1] })).toEqual(
      expect.arrayContaining(['--end-of-options', H1]),
    );
  });
});
