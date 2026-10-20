import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { ConfigError, DEFAULT_MAX_FILE_BYTES, loadConfig, parseConfig } from '../../src/config.js';

const dirs: string[] = [];
afterAll(async () => Promise.all(dirs.map((d) => rm(d, { recursive: true, force: true }))));

describe('config', () => {
  it('uses spec defaults', async () => {
    const cfg = await loadConfig(undefined);
    expect(cfg.entropy).toEqual({ hex: 3, base64: 4.5, minLength: 20 });
    expect(cfg.maxFileBytes).toBe(DEFAULT_MAX_FILE_BYTES);
  });

  it('parses every supported key', () => {
    const cfg = parseConfig({
      entropy: { hex: 3.2, base64: 4.2, minLength: 24 },
      maxFileBytes: 1000,
      severity: { 'stripe-test-key': 'high' },
      ignore: ['docs/', 'fingerprint:0123456789abcdef'],
    });
    expect(cfg.entropy).toEqual({ hex: 3.2, base64: 4.2, minLength: 24 });
    expect(cfg.maxFileBytes).toBe(1000);
    expect(cfg.severity).toEqual({ 'stripe-test-key': 'high' });
    expect(cfg.ignore).toHaveLength(2);
  });

  it.each([
    [[], /top level/],
    [{ nope: 1 }, /unknown key/],
    [{ entropy: 1 }, /entropy must be an object/],
    [{ entropy: { hex: -1 } }, /entropy.hex/],
    [{ entropy: { minLength: 2.5 } }, /minLength/],
    [{ maxFileBytes: 0 }, /maxFileBytes/],
    [{ severity: { x: 'urgent' } }, /severity.x/],
    [{ severity: [] }, /severity must be an object/],
    [{ ignore: [1] }, /ignore must be an array of strings/],
  ])('rejects %j', (json, msg) => {
    expect(() => parseConfig(json)).toThrow(msg);
  });

  it('reports unreadable and invalid files without echoing their content', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'glh-cfg-'));
    dirs.push(dir);
    const bad = path.join(dir, 'bad.json');
    await writeFile(bad, '{ "secret": oops');
    await expect(loadConfig(bad)).rejects.toThrow(ConfigError);
    await expect(loadConfig(bad)).rejects.not.toThrow(/oops/);
    await expect(loadConfig(path.join(dir, 'missing.json'))).rejects.toThrow(/cannot read/);
  });
});
