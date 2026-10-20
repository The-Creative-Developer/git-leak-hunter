/** Line-offset helpers shared by the detectors. Offsets are string indices (UTF-16 code units). */

export function computeLineOffsets(content: string): number[] {
  const offsets = [0];
  for (let i = content.indexOf('\n'); i !== -1; i = content.indexOf('\n', i + 1)) {
    offsets.push(i + 1);
  }
  return offsets;
}

/** 1-based line and column for a string index. */
export function lineColumn(
  offsets: readonly number[],
  index: number,
): { line: number; column: number } {
  let lo = 0;
  let hi = offsets.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if ((offsets[mid] ?? 0) <= index) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, column: index - (offsets[lo] ?? 0) + 1 };
}

/** Text of 1-based line `line`, without its newline. */
export function lineText(content: string, offsets: readonly number[], line: number): string {
  const start = offsets[line - 1];
  if (start === undefined) return '';
  const next = offsets[line];
  const end = next === undefined ? content.length : next - 1;
  return content.slice(start, end).replace(/\r$/, '');
}
