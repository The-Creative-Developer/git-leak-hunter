// Stage 4 — Report Engine. Input: enriched Finding[]. Output: report.json + report.html.
// Implemented in Phase 2: redaction, severity/recency sort, schema-valid JSON, self-contained HTML.
import type { Report } from '../types.js';

export type RenderFn = (report: Report) => string;
