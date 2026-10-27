/**
 * Folder browser for the web UI: lists sub-directories (never files, never file contents) of an
 * absolute path and marks which of them are Git repositories.
 */
import { stat, readdir } from 'node:fs/promises';
import path from 'node:path';
import { ValidationError } from './scans.js';

export interface BrowseEntry {
  name: string;
  path: string;
  isRepo: boolean;
}

export interface BrowseResult {
  path: string;
  parent: string | null;
  isRepo: boolean;
  entries: BrowseEntry[];
  truncated: boolean;
}

export const MAX_ENTRIES = 400;

async function exists(p: string): Promise<boolean> {
  return stat(p).then(
    () => true,
    () => false,
  );
}

/** A working tree with `.git`, or a bare repository (HEAD + objects/ + refs/). */
export async function isGitRepo(dir: string): Promise<boolean> {
  if (await exists(path.join(dir, '.git'))) return true;
  const found = await Promise.all(
    ['HEAD', 'objects', 'refs'].map((n) => exists(path.join(dir, n))),
  );
  return found.every(Boolean);
}

export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NotFoundError';
  }
}

export async function listDirectory(input: string): Promise<BrowseResult> {
  if (!input || !path.isAbsolute(input) || /\0/.test(input))
    throw new ValidationError('path must be absolute');
  const dir = path.resolve(input);
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    throw new NotFoundError('folder not found or not readable');
  }
  const dirs = entries.filter((e) => e.isDirectory() && !e.name.startsWith('.'));
  const listed = await Promise.all(
    dirs.slice(0, MAX_ENTRIES).map(async (e) => {
      const p = path.join(dir, e.name);
      return { name: e.name, path: p, isRepo: await isGitRepo(p) };
    }),
  );
  listed.sort((a, b) => Number(b.isRepo) - Number(a.isRepo) || a.name.localeCompare(b.name));
  const parent = path.dirname(dir);
  return {
    path: dir,
    parent: parent === dir ? null : parent,
    isRepo: await isGitRepo(dir),
    entries: listed,
    truncated: dirs.length > MAX_ENTRIES,
  };
}
