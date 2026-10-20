import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { VERSION } from '../../src/version.js';

describe('version', () => {
  it('matches package.json', async () => {
    const pkg = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8'));
    expect(VERSION).toBe(pkg.version);
  });
});
