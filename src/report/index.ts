// Stage 4 — Report Engine. Input: enriched Finding[]. Output: report.json + report.html.
export { redact, redactLine, maskResidual } from './redact.js';
export { buildReport, renderJson } from './json.js';
export { renderHtml, esc } from './html.js';
