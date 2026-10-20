/**
 * Entropy calibration: how often do random secrets of a given length/charset fail the entropy
 * check, and which ordinary identifiers pass it? Prints a Markdown report with the exact
 * environment so the numbers in docs/RULES.md are reproducible.
 *
 *   npx tsx bench/entropy-calibration.ts [samples]
 */
import os from 'node:os';
import {
  DEFAULT_ENTROPY,
  LENGTH_FACTOR,
  classifyCharset,
  scoreEntropy,
  shannonEntropy,
} from '../src/detect/entropy.js';
import { ALNUM, BASE64, HEX, Rng } from '../test/fixtures/secretFactory.js';

const samples = Number(process.argv[2] ?? 10000);
const rng = new Rng(2026);
const lengths = [16, 20, 24, 28, 32, 40, 48, 64];
const alphabets: Array<[string, string]> = [
  ['alnum (62)', ALNUM],
  ['base64 (64)', BASE64],
  ['hex (16)', HEX],
];

const out: string[] = [];
out.push(
  `Generated ${new Date().toISOString()} by \`npx tsx bench/entropy-calibration.ts ${samples}\``,
);
out.push(
  `Node ${process.version}, ${os.type()} ${os.release()} ${os.arch()}, ${os.cpus()[0]?.model ?? 'unknown CPU'}`,
);
out.push(
  `Thresholds: hex ${DEFAULT_ENTROPY.hex}, base64 ${DEFAULT_ENTROPY.base64}, minLength ${DEFAULT_ENTROPY.minLength}, LENGTH_FACTOR ${LENGTH_FACTOR}; ${samples} seeded random strings per cell (seed 2026).`,
);
out.push('');
out.push(`| Charset | Threshold | ${lengths.map((n) => `n=${n}`).join(' | ')} |`);
out.push(`| --- | --- | ${lengths.map(() => '---').join(' | ')} |`);
/** The spec's starting point without length handling: H >= 3.0 (hex) or 4.5 (other). */
const fixedPasses = (s: string): boolean =>
  shannonEntropy(s) >=
  (classifyCharset(s) === 'hex' ? DEFAULT_ENTROPY.hex : DEFAULT_ENTROPY.base64);

for (const [name, alphabet] of alphabets) {
  const normalised: string[] = [];
  const fixed: string[] = [];
  for (const n of lengths) {
    let missN = 0;
    let missF = 0;
    for (let i = 0; i < samples; i++) {
      const s = rng.chars(alphabet, n);
      if (!scoreEntropy(s, DEFAULT_ENTROPY).passes) missN++;
      if (!fixedPasses(s)) missF++;
    }
    normalised.push(`${((100 * missN) / samples).toFixed(2)}%`);
    fixed.push(`${((100 * missF) / samples).toFixed(2)}%`);
  }
  out.push(`| ${name} | length-normalised (shipped) | ${normalised.join(' | ')} |`);
  out.push(`| ${name} | fixed threshold (no normalisation) | ${fixed.join(' | ')} |`);
}
out.push('');
out.push('Share of random strings that FAIL the entropy check (i.e. would be missed).');
out.push('');
const words = [
  'getUserAccountSettingsForTenant',
  'this_is_not_a_secret_value',
  'ProductionDatabaseHostname',
  'AbstractSingletonProxyFactoryBean',
  'Password1234567890Password',
  'com.example.service.Config',
  'abcdefghijklmnopqrstuvwxyz',
];
out.push('| Ordinary string | Length | Entropy | Threshold | Passes (would be reported) |');
out.push('| --- | --- | --- | --- | --- |');
for (const w of words) {
  const v = scoreEntropy(w, DEFAULT_ENTROPY);
  out.push(
    `| \`${w}\` | ${w.length} | ${v.entropy.toFixed(3)} | ${v.threshold.toFixed(3)} | ${v.passes ? 'yes' : 'no'} |`,
  );
}
process.stdout.write(out.join('\n') + '\n');
