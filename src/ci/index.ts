// Stage 3a — CI/CD scanning. Input: ContentUnit for workflow/CI/Docker/credential files.
// Output: additional Finding[]. Implemented in Phase 2 (GitHub Actions, GitLab CI, Dockerfile,
// credential files), across history via the same ContentUnit/blob-cache path.
import type { ContentUnit, Finding } from '../types.js';

export type CiScanFn = (unit: ContentUnit) => Finding[];
