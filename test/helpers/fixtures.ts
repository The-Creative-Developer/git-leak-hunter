import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll } from 'vitest';
import { buildAllFixtures, type BuiltFixtures } from '../fixtures/buildRepos.js';

/** Build all fixture repos once for the calling test file; removed afterwards. */
export function useFixtures(): { get: () => BuiltFixtures; tmp: () => string } {
  let tmp = '';
  let built: BuiltFixtures | undefined;
  beforeAll(async () => {
    tmp = await mkdtemp(path.join(os.tmpdir(), 'glh-test-'));
    built = await buildAllFixtures(path.join(tmp, 'repos'));
  });
  afterAll(async () => {
    if (tmp) await rm(tmp, { recursive: true, force: true });
  });
  return {
    get: () => {
      if (!built) throw new Error('fixtures not built');
      return built;
    },
    tmp: () => tmp,
  };
}
