/**
 * report.html — one self-contained file: inline CSS and one inline vanilla-JS block, restrictive
 * CSP, no external resources, opens by double-click. Every dynamic value is attacker-controlled
 * (paths, commit messages, author names) and goes through `esc()`. Severity is always shown as a
 * text label; colour is a secondary cue. Charts are inline SVG/CSS rendered here, so they print.
 */
import {
  SEVERITIES,
  type Detector,
  type Finding,
  type Report,
  type Severity,
  type VerificationStatus,
} from '../types.js';
import { remediationFor } from './guidance.js';
import { CSS, SCRIPT } from './htmlAssets.js';

export function esc(value: unknown): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Short display name: last path/URL segment without `.git`. */
function repoName(target: string): string {
  const trimmed = target.replace(/[/\\]+$/, '').replace(/\s+\(.*\)$/, '');
  return (trimmed.split(/[/\\:]/).pop() ?? trimmed).replace(/\.git$/, '') || trimmed;
}

/** Paths may contain control characters (newline, tab): show them visibly. */
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

const STATUS_LABEL: Readonly<Record<VerificationStatus, string>> = {
  NOT_CHECKED: 'NOT CHECKED',
  ACTIVE: 'ACTIVE',
  INACTIVE: 'INACTIVE',
  UNVERIFIABLE: 'UNVERIFIABLE',
};

const DETECTOR_LABEL: Readonly<Record<Detector, string>> = {
  signature: 'Signature',
  entropy: 'Entropy',
  ci: 'CI/CD config',
  'credential-file': 'Credential file',
};

const VERDICT: Readonly<Record<Severity, string>> = {
  critical: 'Critical exposure',
  high: 'High risk',
  medium: 'Moderate risk',
  low: 'Low risk',
};

const pct = (n: number, d: number): number => (d > 0 ? (100 * n) / d : 0);
const fmtPct = (n: number, d: number): string =>
  `${pct(n, d).toFixed(pct(n, d) < 10 && n > 0 ? 1 : 0)}%`;
const num = (n: number): string => n.toLocaleString('en-US');

function fmtBytes(n: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  let v = n;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  return `${u === 0 ? v : v.toFixed(1)} ${units[u]}`;
}

function fmtDate(iso: string, withTime = true): string {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return iso;
  const s = new Date(t).toISOString();
  return withTime ? `${s.slice(0, 10)} ${s.slice(11, 16)} UTC` : s.slice(0, 10);
}

function fmtMs(ms: number): string {
  return ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${Math.round(ms)} ms`;
}

const ICON = {
  mark: `<svg width="26" height="26" viewBox="0 0 32 32" aria-hidden="true"><circle cx="13" cy="13" r="9" fill="none" stroke="currentColor" stroke-width="2.4"/><path d="M19.6 19.6 28 28" stroke="currentColor" stroke-width="3" stroke-linecap="round"/><circle cx="9.5" cy="10" r="1.8" fill="currentColor"/><circle cx="16.5" cy="16" r="1.8" fill="currentColor"/><path d="M9.5 11.8v2.4a3 3 0 0 0 3 3h2.2" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>`,
  moon: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5Z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>`,
  print: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 9V3h10v6M7 17H4v-7h16v7h-3M7 14h10v7H7z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>`,
  search: `<svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6.5" fill="none" stroke="currentColor" stroke-width="2"/><path d="m16 16 4.5 4.5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>`,
};

/** Film-grain overlay: an inline SVG filter (no image fetch, CSP-safe). */
const GRAIN = `<svg class="grain" aria-hidden="true" preserveAspectRatio="none"><filter id="glh-grain"><feTurbulence type="fractalNoise" baseFrequency=".85" numOctaves="2" stitchTiles="stitch"/><feColorMatrix values="0 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 .9 0"/></filter><rect width="100%" height="100%" filter="url(#glh-grain)"/></svg>`;

/** Redacted preview as text with the starred run drawn as a redaction bar (stars stay in the DOM). */
function redactionBar(preview: string): string {
  const stars = /^(.*?)(\*{3,})(.*)$/s.exec(preview);
  if (stars) {
    return `<span class="redact" title="Redacted preview — the full secret is never stored in this report">${esc(stars[1] ?? '')}<span class="blk" aria-label="redacted">${esc(stars[2] ?? '')}</span>${esc(stars[3] ?? '')}</span>`;
  }
  const bracket = /^(.*?)(\[REDACTED[^\]]*\])(.*)$/s.exec(preview);
  if (bracket) {
    return `<span class="redact">${esc(bracket[1] ?? '')}<span class="blk" aria-label="redacted">${esc(bracket[2] ?? '')}</span>${esc(bracket[3] ?? '')}</span>`;
  }
  return `<span class="redact">${esc(preview)}</span>`;
}

function countBy<T extends string>(
  items: readonly Finding[],
  key: (f: Finding) => T,
): Map<T, number> {
  const m = new Map<T, number>();
  for (const f of items) m.set(key(f), (m.get(key(f)) ?? 0) + 1);
  return m;
}

function barList(entries: Array<[string, number]>, cls = ''): string {
  if (entries.length === 0) return '<p class="empty-mini">Nothing to show.</p>';
  const max = Math.max(...entries.map(([, n]) => n));
  return `<ul class="bars ${cls}">${entries
    .map(
      ([label, n]) =>
        `<li><span class="lbl" title="${esc(label)}">${esc(label)}</span><span class="val">${num(n)}</span><span class="track"><span class="fill" style="width:${pct(n, max).toFixed(2)}%"></span></span></li>`,
    )
    .join('')}</ul>`;
}

/** First-introduced timeline: one dot per finding on a time axis, stacked where they collide. */
function timeline(findings: readonly Finding[]): string {
  const pts = findings
    .map((f) => ({ f, t: Date.parse(f.date) }))
    .filter((p) => Number.isFinite(p.t))
    .sort((a, b) => a.t - b.t);
  const first = pts[0];
  const last = pts[pts.length - 1];
  if (!first || !last) return '<p class="empty-mini">No dated findings.</p>';
  const W = 1000;
  const PAD = 16;
  const R = 7;
  const STEP = 17;
  const min = first.t;
  const max = last.t;
  const span = max - min;
  const xOf = (t: number): number =>
    span === 0 ? W / 2 : PAD + ((t - min) / span) * (W - 2 * PAD);
  const stacks = new Map<number, number>();
  const placed = pts.map((p) => {
    const x = xOf(p.t);
    const bin = Math.round(x / (2 * R + 3));
    const level = stacks.get(bin) ?? 0;
    stacks.set(bin, level + 1);
    return { ...p, x: bin * (2 * R + 3), level };
  });
  const levels = Math.max(...placed.map((p) => p.level)) + 1;
  const base = 12 + levels * STEP;
  const H = base + 30;
  const dots = placed
    .map(
      (p) =>
        `<circle class="dot sev-${p.f.severity}${p.f.presence === 'history-only' ? ' hist' : ''}" cx="${p.x.toFixed(1)}" cy="${(base - 10 - p.level * STEP).toFixed(1)}" r="${R}"><title>${esc(`${SEVERITY_LABEL[p.f.severity]} · ${p.f.secretType} · ${visiblePath(p.f.filePath)} · ${fmtDate(p.f.date)} · ${p.f.presence}`)}</title></circle>`,
    )
    .join('');
  const ticks =
    span === 0
      ? `<text class="tick" x="${W / 2}" y="${base + 20}" text-anchor="middle">${esc(fmtDate(new Date(min).toISOString()))}</text>`
      : `<text class="tick" x="${PAD}" y="${base + 20}">${esc(fmtDate(new Date(min).toISOString()))}</text><text class="tick" x="${W - PAD}" y="${base + 20}" text-anchor="end">${esc(fmtDate(new Date(max).toISOString()))}</text>`;
  return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Timeline of when each finding was first committed, ${pts.length} findings"><line class="axis" x1="0" x2="${W}" y1="${base}" y2="${base}"/>${dots}${ticks}</svg>`;
}

function card(f: Finding, i: number): string {
  const hist = f.presence === 'history-only';
  const time = Date.parse(f.date);
  const path = visiblePath(f.filePath);
  const search = [
    path,
    f.secretType,
    f.ruleId,
    f.detector,
    f.commitHash,
    f.author.name,
    f.commitSubject,
    f.presence,
    f.severity,
  ]
    .join(' ')
    .toLowerCase();
  const steps = remediationFor(f)
    .map((s) => `<li>${esc(s)}</li>`)
    .join('');
  const entropy =
    f.entropy === undefined
      ? ''
      : `<div class="k">Shannon entropy</div><div class="meter"><span class="m"><span style="width:${Math.min(100, pct(f.entropy, 6)).toFixed(1)}%"></span></span><span class="mono">${f.entropy.toFixed(2)} bits/char</span></div>`;
  return `<article class="card sev-${f.severity}" id="f-${esc(f.fingerprint)}" data-sev="${f.severity}" data-presence="${f.presence}" data-detector="${f.detector}" data-order="${i}" data-time="${Number.isFinite(time) ? time : 0}" data-path="${esc(path.toLowerCase())}" data-search="${esc(search)}">
<div class="rail" aria-hidden="true"><span class="idx">#${String(i + 1).padStart(2, '0')}</span><span class="sevtxt">${SEVERITY_LABEL[f.severity]}</span><span></span></div>
<div class="body">
<span class="sr">Severity: ${SEVERITY_LABEL[f.severity]}.</span>
<h4>${esc(f.secretType)}</h4>
<div class="tags"><span class="tag ${hist ? 'hist' : 'head'}">${hist ? 'History-only · deleted, still recoverable' : 'Present at HEAD'}</span><span class="tag">${DETECTOR_LABEL[f.detector]}</span><span class="tag">${esc(f.ruleId)}</span>${f.otherCommitCount > 0 ? `<span class="tag">+${f.otherCommitCount} commit${f.otherCommitCount === 1 ? '' : 's'}</span>` : ''}</div>
<div class="path"><span>${esc(path)}<span class="ln">:${f.line}</span></span><button class="copy" type="button" data-copy="${esc(f.filePath)}" aria-label="Copy file path">Copy</button></div>
<dl class="facts">
<div><dt>Commit</dt><dd class="mono">${esc(f.commitHash.slice(0, 10))}</dd></div>
<div><dt>Line</dt><dd>${f.line}<span class="mono" style="color:var(--muted)"> col ${f.column}</span></dd></div>
<div><dt>Introduced</dt><dd>${esc(fmtDate(f.date, false))}</dd></div>
<div><dt>Author</dt><dd>${esc(f.author.name || '—')}</dd></div>
</dl>
<div class="evidence"><span class="k" style="margin:0">Evidence</span>${redactionBar(f.redactedPreview)}<span class="pill v-${f.verificationStatus}"><i></i>${STATUS_LABEL[f.verificationStatus]}</span></div>
<details class="more"><summary>Investigate &amp; remediate</summary>
<div class="drawer">
<div>
${f.redactedContext ? `<div class="k">Context (redacted)</div><div class="code"><span class="g">${f.line}</span><pre>${esc(f.redactedContext)}</pre></div>` : ''}
<div class="k">Commit message</div><p class="msg">${esc(f.commitSubject || '(empty)')}</p>
<div class="k">Remediation</div><ol class="steps">${steps}</ol>
</div>
<div>
${entropy}
<div class="k">Provenance</div>
<dl class="kv">
<dt>First seen</dt><dd class="mono">${esc(f.firstSeenCommit)}</dd>
<dt>Author</dt><dd>${esc(`${f.author.name} <${f.author.email}>`)}</dd>
<dt>Date</dt><dd>${esc(fmtDate(f.date))}</dd>
<dt>Blob</dt><dd class="mono">${esc(f.blobHash)}</dd>
<dt>Fingerprint</dt><dd class="mono">${esc(f.fingerprint)} <button class="copy" type="button" data-copy="${esc(`fingerprint:${f.fingerprint}`)}" aria-label="Copy ignore rule for this finding">Copy ignore rule</button></dd>
${f.pairedFingerprint ? `<dt>Paired with</dt><dd class="mono"><a href="#f-${esc(f.pairedFingerprint)}">${esc(f.pairedFingerprint)}</a></dd>` : ''}
<dt>Verification</dt><dd>${STATUS_LABEL[f.verificationStatus]}${f.verificationNote ? ` — ${esc(f.verificationNote)}` : ''}</dd>
</dl>
</div>
</div>
</details>
</div>
</article>`;
}

export function renderHtml(report: Report): string {
  const F = report.findings;
  const s = report.stats;
  const sum = report.summary;
  const total = sum.total;
  const name = repoName(report.repository.target);
  const top = SEVERITIES.find((sev) => sum.bySeverity[sev] > 0);
  const caseId = `GLH-${report.scan.configHash.slice(0, 4).toUpperCase()}-${(report.repository.head ?? '0000000').slice(0, 7).toUpperCase()}`;
  let i = 0;
  const r = (): string => `class="reveal" style="--i:${i++}"`;

  // ---- header -------------------------------------------------------------------------------
  const stamp = top
    ? `<div class="stamp sev-${top}" role="img" aria-label="Verdict: ${VERDICT[top]}"><b>${VERDICT[top]}</b><small>${num(total)} finding${total === 1 ? '' : 's'} · ${num(sum.historyOnly)} history-only</small></div>`
    : `<div class="stamp clean" role="img" aria-label="Verdict: no findings"><b>No findings</b><small>${num(s.uniqueBlobsScanned)} blobs examined</small></div>`;
  const header = `<p class="classified eyebrow">Confidential · Secret-exposure assessment</p>
<header class="case">
<div>
<div class="eyebrow">Case ${esc(caseId)}</div>
<h1>${esc(name)}</h1>
<div class="target">${esc(report.repository.target)}</div>
<dl class="meta">
<div><dt>Scanned</dt><dd>${esc(fmtDate(report.scan.finishedAt))}</dd></div>
<div><dt>HEAD</dt><dd class="mono">${esc(report.repository.head ? report.repository.head.slice(0, 12) : '—')}</dd></div>
<div><dt>History</dt><dd>${num(s.commitsWalked)} commits</dd></div>
<div><dt>Duration</dt><dd>${esc(fmtMs(s.durationMs))}</dd></div>
<div><dt>Engine</dt><dd>git-leak-hunter ${esc(report.tool.version)}</dd></div>
</dl>
</div>
${stamp}
</header>`;

  // ---- overview -----------------------------------------------------------------------------
  const tiles = SEVERITIES.map(
    (sev) =>
      `<a href="#findings" data-jump="${sev}" class="panel tile span-3 sev-${sev}${sum.bySeverity[sev] === 0 ? ' zero' : ''}" style="text-decoration:none;color:inherit;--i:${i++}" aria-label="${SEVERITY_LABEL[sev]}: ${sum.bySeverity[sev]} findings — show them"><div class="label"><span class="sw"></span>${SEVERITY_LABEL[sev]}</div><div class="count">${num(sum.bySeverity[sev])}</div><div class="share">${total ? `${fmtPct(sum.bySeverity[sev], total)} of findings` : 'none'}</div></a>`,
  ).join('');
  const stack = total
    ? `<div class="stack" role="img" aria-label="Severity distribution">${SEVERITIES.filter(
        (sev) => sum.bySeverity[sev] > 0,
      )
        .map(
          (sev) =>
            `<span class="sev-${sev}" style="flex:${sum.bySeverity[sev]}" title="${SEVERITY_LABEL[sev]}: ${sum.bySeverity[sev]}"></span>`,
        )
        .join('')}</div>`
    : '<div class="stack" aria-hidden="true"></div>';
  const legend = `<ul class="legend">${SEVERITIES.map(
    (sev) =>
      `<li><span class="sw sev-${sev}"></span>${SEVERITY_LABEL[sev].charAt(0)}${SEVERITY_LABEL[sev].slice(1).toLowerCase()}<b>${num(sum.bySeverity[sev])}</b><em>${total ? fmtPct(sum.bySeverity[sev], total) : '—'}</em></li>`,
  ).join('')}</ul>`;
  const exposure = `<div class="expo"><div><div class="n">${num(sum.inHead)}</div><div class="k"><span class="keyink"></span>Present at HEAD</div></div><div><div class="n">${num(sum.historyOnly)}</div><div class="k"><span class="keyhatch"></span>History-only</div></div></div>
<div class="split" role="img" aria-label="${sum.inHead} present at HEAD, ${sum.historyOnly} history-only">${sum.inHead ? `<span class="head" style="flex:${sum.inHead}"></span>` : ''}${sum.historyOnly ? `<span class="hist" style="flex:${sum.historyOnly}"></span>` : ''}</div>
<p class="note">History-only secrets were deleted in a later commit but stay recoverable from Git history until it is rewritten. Rotation is what closes the exposure; deleting the line does not.</p>`;

  const byType = [...countBy(F, (f) => f.secretType)].sort(
    (a, b) => b[1] - a[1] || a[0].localeCompare(b[0]),
  );
  const byFile = [...countBy(F, (f) => visiblePath(f.filePath))]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 8);
  const byDetector = [...countBy(F, (f) => DETECTOR_LABEL[f.detector] as string)].sort(
    (a, b) => b[1] - a[1],
  );
  const vCounts = countBy(F, (f) => f.verificationStatus);
  const verified =
    (vCounts.get('ACTIVE') ?? 0) +
    (vCounts.get('INACTIVE') ?? 0) +
    (vCounts.get('UNVERIFIABLE') ?? 0);
  const verification = `<ul class="vlist">${(
    ['ACTIVE', 'INACTIVE', 'UNVERIFIABLE', 'NOT_CHECKED'] as const
  )
    .map(
      (v) =>
        `<li><span class="pill v-${v}"><i></i>${STATUS_LABEL[v]}</span><b>${num(vCounts.get(v) ?? 0)}</b></li>`,
    )
    .join('')}</ul><p class="note">${
    report.scan.options.verify
      ? `${num(verified)} credential finding${verified === 1 ? '' : 's'} checked with read-only calls (AWS GetCallerIdentity, GitHub GET /user).`
      : 'Live verification was not run. It is opt-in: <span class="mono">--verify --confirm-authorized</span>.'
  }</p>`;

  const overview = `<section id="overview" aria-labelledby="h-overview">
<div class="sechead"><span class="num">01</span><h2 id="h-overview">Overview</h2><p>What was found, how severe it is, and whether it is still in the current tree.</p></div>
<div class="grid">${tiles}
<div class="panel span-7" ${r()}><h3>Severity distribution</h3>${stack}${legend}</div>
<div class="panel span-5" ${r()}><h3>Exposure</h3>${exposure}</div>
<div class="panel span-12 timeline" ${r()}><h3>When each secret was first committed</h3>${timeline(F)}<div class="tl-legend"><span><i class="solid"></i>Present at HEAD</span><span><i class="ring"></i>History-only</span>${SEVERITIES.map((sev) => `<span><span class="sw sev-${sev}"></span>${SEVERITY_LABEL[sev]}</span>`).join('')}<span style="color:var(--muted)">Hover a dot for details</span></div></div>
<div class="panel span-4" ${r()}><h3>By secret type</h3>${barList(byType)}</div>
<div class="panel span-4" ${r()}><h3>Most affected files</h3>${barList(byFile, 'files')}</div>
<div class="panel span-4" ${r()}><h3>Detection layer</h3>${barList(byDetector)}<div class="k" style="margin-top:20px">Live verification</div>${verification}</div>
</div>
</section>`;

  // ---- findings -----------------------------------------------------------------------------
  const detectorsPresent = (['signature', 'entropy', 'ci', 'credential-file'] as const).filter(
    (d) => F.some((f) => f.detector === d),
  );
  const toolbar = `<div class="toolbar" role="search">
<div class="trow">
<label class="search">${ICON.search}<span class="sr">Filter findings</span><input id="q" type="search" placeholder="Filter by path, type, rule, commit, author…" autocomplete="off" spellcheck="false"><kbd>/</kbd></label>
<div class="seg" role="group" aria-label="Presence"><button type="button" data-presence-btn="all" aria-pressed="true">All</button><button type="button" data-presence-btn="in-HEAD" aria-pressed="false">At HEAD</button><button type="button" data-presence-btn="history-only" aria-pressed="false">History-only</button></div>
</div>
<div class="trow">
${SEVERITIES.map((sev) => `<button type="button" class="chip" data-sev-chip="${sev}" aria-pressed="false"><span class="sw sev-${sev}"></span>${SEVERITY_LABEL[sev]} <span class="n">${sum.bySeverity[sev]}</span></button>`).join('')}
<select id="detector" aria-label="Detector"><option value="all">All detectors</option>${detectorsPresent.map((d) => `<option value="${d}">${DETECTOR_LABEL[d]}</option>`).join('')}</select>
<select id="sort" aria-label="Sort"><option value="severity">Sort: severity</option><option value="newest">Sort: newest first</option><option value="oldest">Sort: oldest first</option><option value="path">Sort: file path</option></select>
<button type="button" class="tiny" id="expand">Expand all</button><button type="button" class="tiny" id="collapse">Collapse all</button>
<span class="count-line" aria-live="polite">Showing <b id="shown">${total}</b> of ${total}</span>
</div>
</div>`;
  const findingsBody = total
    ? `${toolbar}<div class="list" id="list">${F.map((f, n) => card(f, n)).join('\n')}<div class="none" id="none">No findings match these filters.</div></div>`
    : `<div class="panel clean">${ICON.mark.replace('width="26" height="26"', 'width="54" height="54"')}<h3>No secrets found</h3><p>${num(s.commitsWalked)} commits and ${num(s.uniqueBlobsScanned)} unique blobs were examined; ${num(Object.values(s.suppressed).reduce((a, b) => a + (b ?? 0), 0))} candidate${Object.values(s.suppressed).reduce((a, b) => a + (b ?? 0), 0) === 1 ? ' was' : 's were'} ruled out as false positives. Absence of findings is not proof of absence: keep secrets out of source control.</p></div>`;
  const findings = `<section id="findings" aria-labelledby="h-findings">
<div class="sechead"><span class="num">02</span><h2 id="h-findings">Findings</h2><p>Each card is one secret at one path, attributed to the commit that introduced it. Values are redacted.</p></div>
${findingsBody}
</section>`;

  // ---- scan details ---------------------------------------------------------------------------
  const suppressedTotal = Object.values(s.suppressed).reduce((a, b) => a + (b ?? 0), 0);
  const suppressed = Object.entries(s.suppressed)
    .map(([k, v]) => [k, v ?? 0] as [string, number])
    .sort((a, b) => b[1] - a[1]);
  const hitRate = s.fileVersionsSeen ? fmtPct(s.cacheHits, s.fileVersionsSeen) : '—';
  const stat = (label: string, v: string, sub: string): string =>
    `<div class="panel stat span-3" ${r()}><h3>${esc(label)}</h3><div class="v">${v}</div><div class="s">${sub}</div></div>`;
  const o = report.scan.options;
  const opt = (k: string, v: string): string => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`;
  const details = `<section id="details" aria-labelledby="h-details">
<div class="sechead"><span class="num">03</span><h2 id="h-details">Scan details</h2><p>Measured counters from this run. Each unique blob is scanned once and reused across commits and paths.</p></div>
<div class="grid">
${stat('Commits walked', num(s.commitsWalked), 'every reachable ref unless limited')}
${stat('File versions seen', num(s.fileVersionsSeen), 'changed files across all commits')}
${stat('Unique blobs scanned', num(s.uniqueBlobsScanned), `${num(s.cacheHits)} cache hits · ${hitRate} reused`)}
${stat('Bytes scanned', esc(fmtBytes(s.bytesScanned)), `in ${esc(fmtMs(s.durationMs))}`)}
<div class="panel span-6" ${r()}><h3>False positives filtered (${num(suppressedTotal)})</h3>${barList(suppressed)}</div>
<div class="panel span-6" ${r()}><h3>Configuration</h3><table class="opts"><tbody>
${opt('Entropy thresholds (hex / base64)', `${o.entropy.hex} / ${o.entropy.base64} bits/char`)}
${opt('Minimum candidate length', String(o.entropy.minLength))}
${opt('Max file size', fmtBytes(o.maxFileBytes))}
${opt('CI/CD parsing', o.ci ? 'on' : 'off (--no-ci)')}
${opt('Blob cache', o.cache ? 'on' : 'off (--no-cache)')}
${opt('Live verification', o.verify ? 'on (opt-in)' : 'off')}
${o.branch ? opt('Branch', o.branch) : ''}${o.since ? opt('Since', o.since) : ''}${o.maxCommits ? opt('Max commits', String(o.maxCommits)) : ''}
${opt('Skipped (binary / oversize / ignored / missing)', `${s.skipped.binary} / ${s.skipped.oversize} / ${s.skipped.ignored} / ${s.skipped.missing}`)}
${opt('Config hash · schema', `${report.scan.configHash} · ${report.schemaVersion}`)}
${opt('Started → finished', `${fmtDate(report.scan.startedAt)} → ${fmtDate(report.scan.finishedAt)}`)}
</tbody></table></div>
</div>
</section>`;

  const footer = `<footer>
<div><h5>Responsible use</h5><ul>
<li>Secrets are redacted. Share reports, not secrets.</li>
<li>A history-only secret is still recoverable: rotate the credential, do not just delete it.</li>
<li>Report genuinely live findings privately to the repository owner. Never use a discovered credential.</li>
</ul></div>
<div class="sig">Generated by git-leak-hunter ${esc(report.tool.version)}<br>config ${esc(report.scan.configHash)} · schema ${esc(report.schemaVersion)}<br>Self-contained · no network requests</div>
</footer>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light dark">
<title>Git Leak Hunter Report — ${esc(name)}</title>
<style>${CSS}</style>
</head>
<body>
${GRAIN}
<a class="skip" href="#findings">Skip to findings</a>
<div class="bar"><div class="wrap">
<span class="brand">${ICON.mark}<span>Git Leak Hunter<span class="full" style="color:var(--muted);font-family:var(--sans);font-weight:400;font-size:13px"> · security report</span></span></span>
<nav class="nav" aria-label="Sections"><a href="#overview">Overview</a><a href="#findings">Findings <span class="mono">${total}</span></a><a href="#details">Scan details</a></nav>
<span class="spacer"></span>
<button type="button" class="iconbtn" id="theme" aria-label="Toggle theme">${ICON.moon}<span class="t">Dark</span></button>
<button type="button" class="iconbtn" id="print" aria-label="Print or save as PDF">${ICON.print}<span>Print</span></button>
</div></div>
<main class="wrap">
${header}
${overview}
${findings}
${details}
${footer}
</main>
<script>${SCRIPT}</script>
</body>
</html>
`;
}
