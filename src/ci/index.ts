// Stage 3a — CI/CD and credential-file scanning. Produces candidates from parsed config so that
// findings come from structure (env:, variables:, ENV/ARG, .env keys), not only regex over text.
// Malformed YAML falls back to generic text scanning (handled by the detection engine).
import type { Candidate, FileKind } from '../detect/types.js';
import { credentialFileCandidates } from './credentialFiles.js';
import { dockerfileCandidates } from './dockerfile.js';
import { githubActionsCandidates } from './githubActions.js';
import { gitlabCiCandidates } from './gitlabCi.js';

export { CiParseError, isSecretLikeKey } from './common.js';
export { gitlabLocalIncludes } from './gitlabCi.js';

/** Candidates from structured parsing of `kind`. Throws CiParseError on malformed YAML. */
export function structuredCandidates(kind: FileKind, content: string): Candidate[] {
  switch (kind) {
    case 'github-actions':
      return githubActionsCandidates(content);
    case 'gitlab-ci':
      return gitlabCiCandidates(content);
    case 'dockerfile':
      return dockerfileCandidates(content);
    default:
      return credentialFileCandidates(kind, content);
  }
}
