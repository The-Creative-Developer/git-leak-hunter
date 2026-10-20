/**
 * `npm run fixtures -- <outDir> [seed]` — build every fixture repo plus ground-truth.json into
 * <outDir> (for demos and benchmarks). Prints counts only, never secret values.
 */
import path from 'node:path';
import { buildAllFixtures } from './buildRepos.js';

const [outArg, seedArg] = process.argv.slice(2);
if (!outArg) {
  process.stderr.write('usage: npm run fixtures -- <outDir> [seed]\n');
  process.exit(2);
}
const seed = seedArg === undefined ? 1337 : Number(seedArg);
if (!Number.isInteger(seed)) {
  process.stderr.write('seed must be an integer\n');
  process.exit(2);
}

const built = await buildAllFixtures(path.resolve(outArg), seed);
for (const f of Object.values(built.fixtures)) {
  const secrets = f.items.filter((i) => i.kind === 'secret').length;
  const baits = f.items.length - secrets;
  process.stdout.write(
    `${f.name.padEnd(16)} secrets=${secrets} baits=${baits} head=${f.head.slice(0, 7)}\n`,
  );
}
process.stdout.write(`ground truth: ${built.manifestPath}\n`);
