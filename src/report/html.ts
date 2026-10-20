/**
 * report.html — one self-contained file: inline CSS and vanilla JS, restrictive CSP, no external
 * resources, opens by double-click. Every dynamic value is attacker-controlled (paths, commit
 * messages, author names) and goes through `esc()`. Severity is always shown as a text label.
 */
import { SEVERITIES, type Finding, type Report, type Severity } from '../types.js';

export function esc(value: unknown): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Paths may contain control characters (newline, tab): show them visibly. */
/** Short display name: last path/URL segment without `.git`. */
function repoName(target: string): string {
  const trimmed = target.replace(/[/\\]+$/, '');
  return (trimmed.split(/[/\\:]/).pop() ?? trimmed).replace(/\.git$/, '') || trimmed;
}

function visiblePath(p: string): string {
  return p.replace(
    // eslint-disable-next-line no-control-regex -- matching control characters is the point
    /[\u0000-\u001f\u007f]/g,
    (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`,
  );
}

const SEVERITY_LABEL: Readonly<Record<Severity, string>> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
};

const STATUS_LABEL = {
  NOT_CHECKED: 'NOT CHECKED',
  ACTIVE: 'ACTIVE',
  INACTIVE: 'INACTIVE',
  UNVERIFIABLE: 'UNVERIFIABLE',
} as const;

const CSS = `
:root{--bg:#f6f7f9;--card:#fff;--ink:#14171c;--muted:#5b6370;--line:#dde1e7;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
--critical:#b3261e;--high:#c2410c;--medium:#a16207;--low:#2f6f4f;--accent:#1f4fd1;--hist:#6d28d9}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#181b21;--ink:#e8eaee;--muted:#9aa3b2;--line:#2a2f38;
--critical:#ff6b61;--high:#ff8a4c;--medium:#e3b341;--low:#5cc48d;--accent:#7aa2ff;--hist:#b794f6}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:13px;letter-spacing:.14em;color:var(--muted);margin:0 0 4px;font-weight:600}
h2{font-size:13px;letter-spacing:.12em;color:var(--muted);margin:32px 0 12px;font-weight:600}
.title{font-size:26px;font-weight:700;margin:0 0 20px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:16px}
.box{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;min-width:0}
.k{font-size:11px;letter-spacing:.12em;color:var(--muted);font-weight:600;text-transform:uppercase}
.v{font-size:15px;overflow-wrap:anywhere}
.mono{font-family:var(--mono);font-size:13px}
.counts{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
.count{border-left:6px solid var(--c);}
.count .n{font-size:30px;font-weight:700;color:var(--c)}
.sev-critical{--c:var(--critical)}.sev-high{--c:var(--high)}.sev-medium{--c:var(--medium)}.sev-low{--c:var(--low)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px}
.controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0 16px}
.controls button,.controls select{font:inherit;font-size:13px;padding:6px 12px;border-radius:999px;border:1px solid var(--line);background:var(--card);color:var(--ink);cursor:pointer}
.controls button[aria-pressed="true"]{border-color:var(--accent);color:var(--accent);font-weight:600}
.card{background:var(--card);border:1px solid var(--line);border-left:6px solid var(--c);border-radius:10px;padding:16px;margin-bottom:14px;break-inside:avoid}
.card-head{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;margin-bottom:12px}
.badge{display:inline-block;font-size:12px;font-weight:700;letter-spacing:.1em;padding:3px 10px;border-radius:6px;border:2px solid var(--c);color:var(--c)}
.type{font-size:17px;font-weight:700;text-transform:uppercase;letter-spacing:.04em}
.presence{font-size:12px;font-weight:700;letter-spacing:.06em;padding:3px 10px;border-radius:6px;border:1px dashed var(--line);color:var(--muted)}
.presence.hist{border:2px solid var(--hist);color:var(--hist)}
.fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px 18px}
.preview{font-family:var(--mono);font-size:14px;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:2px 8px;display:inline-block;overflow-wrap:anywhere}
details{margin-top:12px}
summary{cursor:pointer;color:var(--accent);font-size:13px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font-family:var(--mono);font-size:12.5px;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px 10px;margin:8px 0 0}
.empty{padding:28px;text-align:center;color:var(--muted)}
.warn{border:1px solid var(--line);border-radius:10px;padding:10px 14px;color:var(--muted);font-size:13px;margin-top:24px}
footer{margin-top:32px;color:var(--muted);font-size:12px}
@media (max-width:640px){.counts{grid-template-columns:repeat(2,minmax(0,1fr))}.title{font-size:22px}}
@media print{body{background:#fff;color:#000}.controls{display:none}.card,.box{border-color:#999}details{display:block}details>*{display:block}}
`;

const SCRIPT = `
(function(){
  var sev='all', pres='all';
  var cards=[].slice.call(document.querySelectorAll('.card'));
  var list=document.getElementById('findings');
  function apply(){
    var shown=0;
    cards.forEach(function(c){
      var ok=(sev==='all'||c.getAttribute('data-severity')===sev)&&(pres==='all'||c.getAttribute('data-presence')===pres);
      c.hidden=!ok; if(ok)shown++;
    });
    document.getElementById('shown').textContent=String(shown);
  }
  document.querySelectorAll('[data-filter-sev]').forEach(function(b){
    b.addEventListener('click',function(){
      sev=b.getAttribute('data-filter-sev');
      document.querySelectorAll('[data-filter-sev]').forEach(function(x){x.setAttribute('aria-pressed',String(x===b));});
      apply();
    });
  });
  var p=document.getElementById('presence');
  if(p)p.addEventListener('change',function(){pres=p.value;apply();});
  var s=document.getElementById('sort');
  if(s)s.addEventListener('change',function(){
    var key=s.value;
    cards.sort(function(a,b){
      if(key==='recent')return Number(b.getAttribute('data-time'))-Number(a.getAttribute('data-time'));
      return Number(a.getAttribute('data-order'))-Number(b.getAttribute('data-order'));
    });
    cards.forEach(function(c){list.appendChild(c);});
  });
})();
`;

function field(label: string, value: string, opts: { mono?: boolean; raw?: boolean } = {}): string {
  const v = opts.raw ? value : esc(value);
  return `<div><div class="k">${esc(label)}</div><div class="v${opts.mono ? ' mono' : ''}">${v}</div></div>`;
}

function card(f: Finding, order: number): string {
  const hist = f.presence === 'history-only';
  const presenceLabel = hist ? 'HISTORY-ONLY · deleted but still recoverable' : 'PRESENT AT HEAD';
  const time = Date.parse(f.date);
  const extra = [
    field('Rule', f.ruleId, { mono: true }),
    field('Detector', f.detector),
    ...(f.entropy === undefined ? [] : [field('Entropy', `${f.entropy.toFixed(2)} bits/char`)]),
    field('First seen commit', f.firstSeenCommit, { mono: true }),
    field('Other commits containing it', String(f.otherCommitCount)),
    field('Author', `${f.author.name} <${f.author.email}>`),
    field('Date', f.date),
    field('Blob', f.blobHash, { mono: true }),
    field('Fingerprint', f.fingerprint, { mono: true }),
    ...(f.pairedFingerprint ? [field('Paired with', f.pairedFingerprint, { mono: true })] : []),
  ].join('');
  return `<article class="card sev-${f.severity}" data-severity="${f.severity}" data-presence="${f.presence}" data-order="${order}" data-time="${Number.isFinite(time) ? time : 0}">
<div class="card-head"><span class="badge">${SEVERITY_LABEL[f.severity]}</span><span class="type">${esc(f.secretType)}</span><span class="presence${hist ? ' hist' : ''}">${presenceLabel}</span></div>
<div class="fields">
${field('File path', visiblePath(f.filePath), { mono: true })}
${field('Commit hash', f.commitHash.slice(0, 7), { mono: true })}
${field('Line number', String(f.line))}
<div><div class="k">Redacted preview</div><div class="v"><span class="preview">${esc(f.redactedPreview)}</span></div></div>
${field('Verification status', STATUS_LABEL[f.verificationStatus])}
</div>
<details><summary>Details</summary>
<div class="fields" style="margin-top:10px">${extra}</div>
<div class="k" style="margin-top:12px">Commit message</div><pre>${esc(f.commitSubject)}</pre>
${f.redactedContext ? `<div class="k" style="margin-top:12px">Context (redacted)</div><pre>${esc(f.redactedContext)}</pre>` : ''}
</details>
</article>`;
}

export function renderHtml(report: Report): string {
  const s = report.stats;
  const counts = SEVERITIES.map(
    (sev) =>
      `<div class="box count sev-${sev}"><div class="k">${SEVERITY_LABEL[sev]}</div><div class="n">${report.summary.bySeverity[sev]}</div></div>`,
  ).join('');
  const stat = (k: string, v: string | number): string =>
    `<div class="box"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`;
  const stats = [
    stat('Commits walked', s.commitsWalked),
    stat('File versions seen', s.fileVersionsSeen),
    stat('Unique blobs scanned', s.uniqueBlobsScanned),
    stat('Cache hits', s.cacheHits),
    stat('Bytes scanned', s.bytesScanned),
    stat('Duration', `${s.durationMs} ms`),
    stat(
      'Skipped (binary / oversize / ignored)',
      `${s.skipped.binary} / ${s.skipped.oversize} / ${s.skipped.ignored}`,
    ),
    stat('History-only findings', report.summary.historyOnly),
  ].join('');
  const filterButtons = ['all', ...SEVERITIES]
    .map(
      (sev) =>
        `<button type="button" data-filter-sev="${sev}" aria-pressed="${sev === 'all'}">${sev === 'all' ? 'All' : SEVERITY_LABEL[sev as Severity]}</button>`,
    )
    .join('');
  const cards = report.findings.map((f, i) => card(f, i)).join('\n');
  const head = report.repository.head ? report.repository.head.slice(0, 12) : '(empty repository)';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer">
<title>Git Leak Hunter Report</title>
<style>${CSS}</style>
</head>
<body>
<main>
<h1>GIT LEAK HUNTER · SECURITY REPORT</h1>
<p class="title">${esc(repoName(report.repository.target))}</p>
<section class="meta">
<div class="box"><div class="k">Repository</div><div class="v mono">${esc(report.repository.target)}</div></div>
<div class="box"><div class="k">Scan date</div><div class="v">${esc(report.scan.finishedAt)}</div></div>
<div class="box"><div class="k">HEAD</div><div class="v mono">${esc(head)}</div></div>
<div class="box"><div class="k">Total findings</div><div class="v">${report.summary.total}</div></div>
</section>
<section class="counts" aria-label="Findings by severity">${counts}</section>
<h2>SCAN STATS</h2>
<section class="stats">${stats}</section>
<h2>FINDINGS (<span id="shown">${report.findings.length}</span>)</h2>
<div class="controls" role="toolbar" aria-label="Filter findings">${filterButtons}
<select id="presence" aria-label="Presence"><option value="all">In HEAD + history-only</option><option value="in-HEAD">Present at HEAD</option><option value="history-only">History-only</option></select>
<select id="sort" aria-label="Sort"><option value="severity">Sort: severity</option><option value="recent">Sort: most recent</option></select>
</div>
<section id="findings">
${cards || '<div class="box empty">No findings.</div>'}
</section>
<p class="warn">Secrets are redacted. A history-only secret is still recoverable from Git history until the history is rewritten — rotate the credential, do not just delete it. Report genuinely live findings privately to the repository owner.</p>
<footer>Generated by git-leak-hunter ${esc(report.tool.version)} · config ${esc(report.scan.configHash)} · schema ${esc(report.schemaVersion)}</footer>
</main>
<script>${SCRIPT}</script>
</body>
</html>
`;
}
