/**
 * Optional JSON config file (`--config <file>`). Read from the invoker's side only — never from the
 * scanned repository, which is untrusted and could otherwise switch detection off.
 *
 * {
 *   "entropy": { "hex": 3.0, "base64": 4.5, "minLength": 20 },
 *   "maxFileBytes": 2097152,
 *   "severity": { "<ruleId>": "critical" | "high" | "medium" | "low" },
 *   "ignore": ["glob", "fingerprint:<hex>"]
 * }
 */
import { readFile } from 'node:fs/promises';
import { SEVERITIES, type EntropyThresholds, type Severity } from './types.js';
import { DEFAULT_ENTROPY } from './detect/entropy.js';

export const DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024;

export interface FileConfig {
  entropy: EntropyThresholds;
  maxFileBytes: number;
  severity: Record<string, Severity>;
  ignore: string[];
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

function num(v: unknown, name: string, min: number, integer = false): number {
  if (
    typeof v !== 'number' ||
    !Number.isFinite(v) ||
    v < min ||
    (integer && !Number.isInteger(v))
  ) {
    throw new ConfigError(
      `config: ${name} must be ${integer ? 'an integer' : 'a number'} >= ${min}`,
    );
  }
  return v;
}

export function defaultConfig(): FileConfig {
  return {
    entropy: { ...DEFAULT_ENTROPY },
    maxFileBytes: DEFAULT_MAX_FILE_BYTES,
    severity: {},
    ignore: [],
  };
}

export function parseConfig(json: unknown): FileConfig {
  const cfg = defaultConfig();
  if (!isObj(json)) throw new ConfigError('config: top level must be an object');
  for (const key of Object.keys(json)) {
    if (!['entropy', 'maxFileBytes', 'severity', 'ignore'].includes(key))
      throw new ConfigError(`config: unknown key "${key}"`);
  }
  if (json.entropy !== undefined) {
    if (!isObj(json.entropy)) throw new ConfigError('config: entropy must be an object');
    const e = json.entropy;
    if (e.hex !== undefined) cfg.entropy.hex = num(e.hex, 'entropy.hex', 0);
    if (e.base64 !== undefined) cfg.entropy.base64 = num(e.base64, 'entropy.base64', 0);
    if (e.minLength !== undefined)
      cfg.entropy.minLength = num(e.minLength, 'entropy.minLength', 1, true);
  }
  if (json.maxFileBytes !== undefined)
    cfg.maxFileBytes = num(json.maxFileBytes, 'maxFileBytes', 1, true);
  if (json.severity !== undefined) {
    if (!isObj(json.severity)) throw new ConfigError('config: severity must be an object');
    for (const [rule, sev] of Object.entries(json.severity)) {
      if (!SEVERITIES.includes(sev as Severity))
        throw new ConfigError(`config: severity.${rule} must be one of ${SEVERITIES.join(', ')}`);
      cfg.severity[rule] = sev as Severity;
    }
  }
  if (json.ignore !== undefined) {
    if (!Array.isArray(json.ignore) || !json.ignore.every((x) => typeof x === 'string')) {
      throw new ConfigError('config: ignore must be an array of strings');
    }
    cfg.ignore = json.ignore as string[];
  }
  return cfg;
}

export async function loadConfig(file: string | undefined): Promise<FileConfig> {
  if (!file) return defaultConfig();
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch {
    throw new ConfigError(`cannot read config file: ${file}`);
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new ConfigError(`config file is not valid JSON: ${file}`);
  }
  return parseConfig(json);
}
