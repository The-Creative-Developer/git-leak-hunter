/**
 * Reads blobs by hash through one long-lived `git cat-file --batch-command` process (git ≥ 2.36).
 * `info` is asked first so oversize blobs are never transferred.
 */
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { GitError, OID_RE, spawnGit } from './exec.js';

export interface BlobInfo {
  type: string;
  size: number;
}

interface Pending {
  kind: 'info' | 'contents';
  resolve: (v: { info: BlobInfo | null; content?: Buffer }) => void;
  reject: (e: Error) => void;
}

export class CatFile {
  private readonly child: ChildProcessWithoutNullStreams;
  private buf: Buffer = Buffer.alloc(0);
  private readonly queue: Pending[] = [];
  private failed: Error | null = null;

  constructor(dir: string) {
    this.child = spawnGit(['cat-file', '--batch-command'], dir);
    this.child.stdout.on('data', (d: Buffer) => {
      this.buf = this.buf.length ? Buffer.concat([this.buf, d]) : d;
      this.drain();
    });
    this.child.stderr.resume();
    this.child.stdin.on('error', (e) => this.fail(e));
    this.child.on('error', (e) => this.fail(e));
    this.child.on('close', () => this.fail(new GitError('git cat-file exited', null)));
  }

  private fail(err: Error): void {
    if (this.failed) return;
    this.failed = err;
    for (const p of this.queue.splice(0)) p.reject(err);
  }

  private drain(): void {
    while (this.queue.length > 0) {
      const nl = this.buf.indexOf(0x0a);
      if (nl < 0) return;
      const header = this.buf.subarray(0, nl).toString('utf8');
      const head = this.queue[0];
      if (!head) return;
      if (header.endsWith(' missing') || header.endsWith(' ambiguous')) {
        this.buf = this.buf.subarray(nl + 1);
        this.queue.shift();
        head.resolve({ info: null });
        continue;
      }
      const [, type, sizeStr] = header.split(' ');
      const size = Number(sizeStr);
      if (!type || !Number.isFinite(size)) {
        this.fail(new GitError('unexpected git cat-file output', null));
        return;
      }
      if (head.kind === 'info') {
        this.buf = this.buf.subarray(nl + 1);
        this.queue.shift();
        head.resolve({ info: { type, size } });
        continue;
      }
      const end = nl + 1 + size;
      if (this.buf.length < end + 1) return; // content + trailing LF not complete yet
      const content = Buffer.from(this.buf.subarray(nl + 1, end));
      this.buf = this.buf.subarray(end + 1);
      this.queue.shift();
      head.resolve({ info: { type, size }, content });
    }
  }

  private send(kind: 'info' | 'contents', oid: string) {
    if (!OID_RE.test(oid)) return Promise.reject(new GitError('internal: invalid object id', null));
    if (this.failed) return Promise.reject(this.failed);
    return new Promise<{ info: BlobInfo | null; content?: Buffer }>((resolve, reject) => {
      this.queue.push({ kind, resolve, reject });
      this.child.stdin.write(`${kind} ${oid}\n`);
    });
  }

  async info(oid: string): Promise<BlobInfo | null> {
    return (await this.send('info', oid)).info;
  }

  async contents(oid: string): Promise<Buffer | null> {
    return (await this.send('contents', oid)).content ?? null;
  }

  async close(): Promise<void> {
    if (this.failed) return;
    await new Promise<void>((resolve) => {
      this.child.once('close', () => resolve());
      this.child.stdin.end();
    });
  }
}
