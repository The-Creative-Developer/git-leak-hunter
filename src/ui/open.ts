/** Open a URL in the default browser (best effort; argv spawn, never a shell string). */
import { execFile } from 'node:child_process';

export function openBrowser(url: string): void {
  const [cmd, args] =
    process.platform === 'darwin'
      ? ['open', [url]]
      : process.platform === 'win32'
        ? ['cmd', ['/c', 'start', '""', url]]
        : ['xdg-open', [url]];
  try {
    const child = execFile(cmd, args, { windowsHide: true }, () => undefined);
    child.unref();
  } catch {
    // No browser available (e.g. headless server): the printed link still works.
  }
}
