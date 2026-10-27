/**
 * Static remediation guidance shown on each finding card. Generic, provider-neutral steps; no
 * links (the report is offline and makes no network requests).
 */
import type { Finding } from '../types.js';

function base(f: Finding): string {
  const r = f.ruleId;
  if (r.startsWith('aws-')) {
    return 'Deactivate and delete the access key in IAM, issue a new one, and review CloudTrail for any use of the old key.';
  }
  if (r.startsWith('github-')) {
    return 'Revoke the token where it was issued (user settings, GitHub App or organization), then create a replacement with the minimum scopes.';
  }
  if (r === 'stripe-live-key')
    return 'Roll the key in the Stripe dashboard immediately and redeploy with the new key from a secret store.';
  if (r === 'stripe-test-key')
    return 'Roll the test key. Test-mode keys still expose account data and configuration.';
  if (r === 'slack-token')
    return 'Revoke the token in the Slack app configuration and reinstall or reissue it.';
  if (r === 'slack-webhook')
    return 'Regenerate the incoming-webhook URL in the Slack app; anyone holding the old URL can post to the channel.';
  if (r === 'private-key' || r === 'ssh-private-key-file') {
    return 'Treat the key pair as compromised: remove its public key from every system that trusts it, generate a new pair, and re-issue any certificate.';
  }
  if (r === 'dockerfile-literal') {
    return 'ENV/ARG values persist in image layers and history. Use build secrets or runtime environment variables, rebuild and re-push images, and rotate the value.';
  }
  if (f.detector === 'ci') {
    return "Move the value into the CI provider's secret store (e.g. ${{ secrets.NAME }} or a masked CI/CD variable) and rotate it.";
  }
  if (f.detector === 'credential-file') {
    return 'Remove the file from the repository, add it to .gitignore, and rotate every credential it contains.';
  }
  return 'Confirm whether this is a real credential. If it is, rotate it and load it from the environment or a secret manager instead of source code.';
}

export function remediationFor(f: Finding): string[] {
  const steps = [base(f)];
  if (f.presence === 'history-only') {
    steps.push(
      'It was deleted in a later commit but is still recoverable from Git history: rotate first, then rewrite history (e.g. git filter-repo) only if policy requires it.',
    );
  } else {
    steps.push(
      'Remove it from the current tree as well; afterwards it will remain in history, so rotation is what actually closes the exposure.',
    );
  }
  if (f.otherCommitCount > 0) {
    steps.push(
      `It appears in ${f.otherCommitCount} other commit${f.otherCommitCount === 1 ? '' : 's'} at this path; a history rewrite must cover all of them.`,
    );
  }
  return steps;
}
