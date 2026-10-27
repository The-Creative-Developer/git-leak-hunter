/**
 * Static assets of the local web UI: the HTML shell, stylesheet and script, served as separate
 * same-origin files so the page CSP needs no 'unsafe-inline'. The script builds every dynamic
 * element with textContent (never innerHTML), so scan data cannot inject markup.
 */
import { THEME_CSS } from '../report/theme.js';

const MARK = `<svg class="mark" width="28" height="28" viewBox="0 0 32 32" aria-hidden="true"><circle cx="13" cy="13" r="9" fill="none" stroke="currentColor" stroke-width="2.4"/><path d="M19.6 19.6 28 28" stroke="currentColor" stroke-width="3" stroke-linecap="round"/><circle cx="9.5" cy="10" r="1.8" fill="currentColor"/><circle cx="16.5" cy="16" r="1.8" fill="currentColor"/><path d="M9.5 11.8v2.4a3 3 0 0 0 3 3h2.2" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>`;

export const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#1c1a16"/><g transform="translate(3 3) scale(.82)" color="#efe9dd">${MARK.replace(/<svg[^>]*>|<\/svg>/g, '')}</g></svg>`;

export const PAGE_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="referrer" content="no-referrer">
<title>Git Leak Hunter — Local console</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/app.css">
<script src="/app.js" defer></script>
</head>
<body>
<div class="bar"><div class="wrap">
  <span class="brand">${MARK}<span>Git Leak Hunter</span><span class="sub">Local console</span></span>
  <span class="spacer"></span>
  <span class="live" title="This console only listens on your own machine and requires the session link"><i></i><span id="addr">127.0.0.1</span><span class="hide-sm"> · session secured</span></span>
  <button type="button" class="iconbtn" id="theme" aria-label="Toggle theme"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5Z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg><span class="t">Dark</span></button>
</div></div>

<main class="wrap">
  <section class="intro">
    <p class="eyebrow">New investigation</p>
    <h1>Scan a repository’s <em>entire</em> history.</h1>
    <p class="lede">Every commit on every branch, CI/CD configuration and committed credential files — checked for leaked secrets, then summarised in a redacted report. Nothing leaves this machine.</p>
  </section>

  <div class="layout">
    <aside class="col-form">
      <form id="scan-form" class="panel form" novalidate>
        <label for="target" class="lbl">Repository</label>
        <div class="field-row">
          <input id="target" name="target" type="text" class="input mono" placeholder="/path/to/repo or https://github.com/org/repo.git" autocomplete="off" spellcheck="false" required>
          <button type="button" id="browse" class="btn ghost">Browse…</button>
        </div>
        <p class="hint">A local folder, or an <span class="mono">https://</span> / <span class="mono">ssh://</span> URL to clone (bare, hooks disabled, deleted afterwards).</p>
        <div class="quick" id="quick"></div>

        <div class="callout" id="remote-callout" hidden>
          <p><b>Remote repository.</b> It will be cloned into a temporary folder for this scan only.</p>
          <label class="check"><input type="checkbox" id="authorized"><span>I own this repository or am explicitly authorized to scan it.</span></label>
        </div>

        <details class="opts">
          <summary>Scan scope</summary>
          <div class="opt-grid">
            <label><span>Branch</span><input id="branch" class="input" type="text" placeholder="all refs" autocomplete="off" spellcheck="false"></label>
            <label><span>Since</span><input id="since" class="input" type="date"></label>
            <label><span>Max commits</span><input id="maxCommits" class="input" type="number" min="1" step="1" placeholder="no limit"></label>
          </div>
          <label class="switch"><input type="checkbox" id="ci" checked><span class="track"></span><span>Parse CI/CD config (GitHub Actions, GitLab CI, Dockerfile)</span></label>
          <label class="switch"><input type="checkbox" id="cache" checked><span class="track"></span><span>Blob cache — scan each unique file version once</span></label>
        </details>

        <details class="opts">
          <summary>Detection thresholds</summary>
          <div class="opt-grid">
            <label><span>Hex entropy</span><input id="entropyHex" class="input" type="number" min="0" step="0.1" placeholder="3.0"></label>
            <label><span>Base64 entropy</span><input id="entropyBase64" class="input" type="number" min="0" step="0.1" placeholder="4.5"></label>
            <label><span>Min length</span><input id="minLength" class="input" type="number" min="1" step="1" placeholder="20"></label>
          </div>
          <p class="hint">Bits per character. Defaults are the documented, measured values; leave blank to use them.</p>
        </details>

        <details class="opts warnbox">
          <summary>Live verification <span class="tagline">opt-in</span></summary>
          <label class="check"><input type="checkbox" id="verify"><span>Check AWS and GitHub credentials with read-only calls</span></label>
          <label class="check"><input type="checkbox" id="confirm"><span>I am authorized to test these credentials</span></label>
          <p class="hint">Only <span class="mono">sts:GetCallerIdentity</span> and GitHub <span class="mono">GET /user</span>, once per credential, to an allowlist of two hosts. Never use a live credential you discover.</p>
        </details>

        <p class="form-error" id="form-error" role="alert" hidden></p>
        <button class="btn primary big" id="go" type="submit"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6.5" fill="none" stroke="currentColor" stroke-width="2.2"/><path d="m16 16 4.5 4.5" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg><span>Scan repository</span></button>
        <p class="hint center">Secrets are always redacted — reports never contain a full value.</p>
      </form>

      <div class="panel history">
        <h3>This session</h3>
        <ol id="history"><li class="nothing">No scans yet.</li></ol>
      </div>
    </aside>

    <section class="col-result" aria-live="polite">
      <div id="view-empty" class="panel stage empty-stage">
        <svg class="folder" viewBox="0 0 160 120" aria-hidden="true"><path d="M14 30h44l10 12h78v62a6 6 0 0 1-6 6H20a6 6 0 0 1-6-6V30Z" fill="none" stroke="currentColor" stroke-width="2.5"/><path d="M14 42h132" stroke="currentColor" stroke-width="2.5" stroke-dasharray="4 5"/><rect x="34" y="58" width="58" height="9" rx="2" class="bar1"/><rect x="34" y="74" width="80" height="9" rx="2" class="bar2"/><rect x="34" y="90" width="40" height="9" rx="2" class="bar3"/><circle cx="118" cy="76" r="15" fill="none" stroke="currentColor" stroke-width="3"/><path d="m129 87 12 12" stroke="currentColor" stroke-width="4" stroke-linecap="round"/></svg>
        <h2>Ready when you are</h2>
        <p>Pick a repository on the left and press <b>Scan repository</b>. The report opens right here.</p>
        <ul class="facts">
          <li><b>Full history</b><span>Every reachable commit, including secrets that were deleted later.</span></li>
          <li><b>CI/CD aware</b><span>Workflow env, pipeline variables, Dockerfile ENV/ARG, credential files.</span></li>
          <li><b>Redacted</b><span>Previews like <span class="mono">AKIA████WXYZ</span> — never the full secret.</span></li>
        </ul>
      </div>

      <div id="view-running" class="panel stage" hidden>
        <p class="eyebrow">Scanning</p>
        <h2 id="run-name">repository</h2>
        <p class="target mono" id="run-target"></p>
        <div class="scanner" aria-hidden="true"><span></span></div>
        <ol class="steps" id="steps">
          <li data-phase="opening"><i></i>Open repository</li>
          <li data-phase="walking"><i></i>Walk history &amp; detect</li>
          <li data-phase="analyzing"><i></i>Attribute &amp; classify</li>
          <li data-phase="verifying"><i></i>Verify (opt-in)</li>
          <li data-phase="writing"><i></i>Write report</li>
        </ol>
        <dl class="counters">
          <div><dt>Commits</dt><dd id="c-commits">0</dd></div>
          <div><dt>File versions</dt><dd id="c-files">0</dd></div>
          <div><dt>Unique blobs</dt><dd id="c-blobs">0</dd></div>
          <div><dt>Cache hits</dt><dd id="c-hits">0</dd></div>
        </dl>
        <p class="hint" id="elapsed">Elapsed 0.0 s</p>
      </div>

      <div id="view-error" class="panel stage" hidden>
        <p class="eyebrow">Scan failed</p>
        <h2 id="err-name">Something went wrong</h2>
        <p class="err-msg mono" id="err-msg"></p>
        <button class="btn ghost" type="button" id="err-retry">Edit and try again</button>
      </div>

      <div id="view-done" hidden>
        <div class="panel result">
          <div class="result-head">
            <div>
              <p class="eyebrow" id="done-when">Completed</p>
              <h2 id="done-name">repository</h2>
              <p class="target mono" id="done-target"></p>
            </div>
            <div class="stamp" id="done-stamp"><b id="stamp-text">No findings</b><small id="stamp-sub"></small></div>
          </div>
          <div class="sev-row" id="sev-row"></div>
          <div class="result-meta" id="done-meta"></div>
          <div class="actions">
            <a class="btn primary" id="open-report" target="_blank" rel="noopener noreferrer">Open full report ↗</a>
            <a class="btn ghost" id="dl-html">Download HTML</a>
            <a class="btn ghost" id="dl-json">Download JSON</a>
            <button class="btn ghost" type="button" id="new-scan">New scan</button>
          </div>
        </div>
        <div class="panel top" id="top-panel">
          <h3>Top findings</h3>
          <ol class="toplist" id="toplist"></ol>
          <p class="hint" id="top-more"></p>
        </div>
        <div class="frame"><iframe id="frame" title="Full scan report"></iframe></div>
      </div>
    </section>
  </div>
</main>

<dialog id="picker" aria-labelledby="picker-title">
  <form method="dialog" class="picker">
    <header>
      <h3 id="picker-title">Choose a repository</h3>
      <p class="mono crumb" id="picker-path"></p>
      <div class="picker-nav">
        <button type="button" class="btn ghost sm" id="pk-up">↑ Up</button>
        <button type="button" class="btn ghost sm" id="pk-home">Home</button>
        <button type="button" class="btn ghost sm" id="pk-cwd">Launch folder</button>
      </div>
    </header>
    <ul class="dirs" id="pk-list"></ul>
    <footer>
      <span class="hint" id="pk-note">Folders only. <b>git</b> marks a repository.</span>
      <span class="spacer"></span>
      <button type="submit" class="btn ghost" value="cancel">Cancel</button>
      <button type="button" class="btn primary" id="pk-use">Use this folder</button>
    </footer>
  </form>
</dialog>

<div class="noauth" id="noauth" hidden>
  <div class="panel">
    <p class="eyebrow">Session required</p>
    <h2>Open the link from your terminal</h2>
    <p>For your safety this console only works through the private link printed when you ran <span class="mono">git-leak-hunter ui</span>. Copy that full link (it contains <span class="mono">#token=…</span>) into this tab.</p>
  </div>
</div>
</body>
</html>
`;

export const APP_CSS = String.raw`${THEME_CSS}
*,*::before,*::after{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 var(--sans);-webkit-font-smoothing:antialiased;
  background-image:radial-gradient(circle at 12% -10%,var(--sheet) 0,transparent 42%),radial-gradient(circle at 110% 30%,var(--sheet-2) 0,transparent 38%)}
[hidden]{display:none!important}
.wrap{max-width:1320px;margin:0 auto;padding:0 28px}
.mono{font-family:var(--mono);font-size:.88em;letter-spacing:-.01em}
.eyebrow{font:600 11px/1 var(--mono);letter-spacing:.18em;text-transform:uppercase;color:var(--muted);margin:0 0 10px}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px;border-radius:6px}
.bar{position:sticky;top:0;z-index:10;background:color-mix(in srgb,var(--paper) 86%,transparent);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);border-bottom:1px solid var(--rule)}
.bar .wrap{display:flex;align-items:center;gap:14px;height:60px}
.brand{display:flex;align-items:center;gap:10px;font:600 16px/1 var(--serif);white-space:nowrap}
.brand .sub{font:500 11px/1 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--muted);border-left:1px solid var(--rule);padding-left:10px;margin-left:2px}
.spacer{flex:1}
.live{display:inline-flex;align-items:center;gap:8px;font:500 12px/1 var(--mono);color:var(--ink-2);border:1px solid var(--rule);background:var(--sheet);padding:7px 11px;border-radius:999px}
.live i{width:8px;height:8px;border-radius:50%;background:#2f9e58;box-shadow:0 0 0 3px color-mix(in srgb,#2f9e58 25%,transparent);animation:pulse 2.4s ease-in-out infinite}
@keyframes pulse{50%{box-shadow:0 0 0 6px color-mix(in srgb,#2f9e58 0%,transparent)}}
.iconbtn{display:inline-flex;align-items:center;gap:8px;font:500 13px/1 var(--sans);color:var(--ink);background:var(--sheet);border:1px solid var(--rule);padding:8px 12px;border-radius:999px;cursor:pointer}
.iconbtn svg{width:15px;height:15px}

.intro{padding:46px 0 26px;max-width:860px}
.intro h1{font:500 clamp(34px,5vw,58px)/1.02 var(--serif);letter-spacing:-.02em;margin:0 0 14px}
.intro h1 em{font-style:italic;color:var(--accent)}
.lede{color:var(--ink-2);font-size:16.5px;max-width:64ch;margin:0}

.layout{display:grid;grid-template-columns:minmax(340px,430px) minmax(0,1fr);gap:22px;align-items:start;padding-bottom:60px}
.col-form{display:grid;gap:18px;position:sticky;top:78px}
.panel{background:var(--sheet);border:1px solid var(--rule);border-radius:16px;box-shadow:var(--shadow);padding:22px}
.panel h3{font:600 11px/1 var(--mono);letter-spacing:.16em;text-transform:uppercase;color:var(--muted);margin:0 0 14px}

.form{display:grid;gap:12px}
.lbl{font:600 11px/1 var(--mono);letter-spacing:.16em;text-transform:uppercase;color:var(--muted)}
.field-row{display:flex;gap:8px}
.input{width:100%;min-width:0;font:14px var(--sans);color:var(--ink);background:var(--paper);border:1px solid var(--rule);border-radius:10px;padding:11px 12px}
.input.mono{font-family:var(--mono);font-size:13.5px}
.input:focus{outline:none;border-color:var(--focus);box-shadow:0 0 0 3px var(--accent-soft)}
.input[aria-invalid="true"]{border-color:var(--sev-critical)}
.hint{font-size:12.5px;color:var(--muted);margin:0}
.hint.center{text-align:center}
.quick{display:flex;flex-wrap:wrap;gap:6px}
.quick button{font:500 12px/1 var(--sans);color:var(--ink-2);background:var(--sheet-2);border:1px dashed var(--rule);border-radius:999px;padding:7px 10px;cursor:pointer;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.quick button:hover{border-style:solid;color:var(--ink)}
.callout{border:1px solid var(--rule);border-left:4px solid var(--sev-medium);border-radius:10px;padding:12px 14px;background:var(--sheet-2);font-size:13.5px}
.callout p{margin:0 0 8px}
.check{display:flex;gap:10px;align-items:flex-start;font-size:13.5px;cursor:pointer;margin:8px 0}
.check input{margin-top:3px;accent-color:var(--accent);width:16px;height:16px;flex:none}
details.opts{border:1px solid var(--rule-2);border-radius:12px;padding:0 14px;background:var(--sheet)}
details.opts[open]{padding-bottom:12px}
details.opts summary{cursor:pointer;list-style:none;padding:12px 0;font:600 12.5px/1 var(--sans);display:flex;align-items:center;gap:8px}
details.opts summary::-webkit-details-marker{display:none}
details.opts summary::before{content:"+";font:600 14px/1 var(--mono);width:12px;color:var(--muted)}
details.opts[open] summary::before{content:"\2212"}
.tagline{font:600 10px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--muted);border:1px solid var(--rule);padding:3px 6px;border-radius:999px}
.warnbox{border-left:4px solid var(--sev-high)}
.opt-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-bottom:10px}
.opt-grid label{display:grid;gap:6px;font-size:12px;color:var(--muted)}
.opt-grid .input{padding:9px 10px;font-size:13px}
.switch{display:flex;align-items:center;gap:10px;font-size:13.5px;margin:8px 0;cursor:pointer}
.switch input{position:absolute;opacity:0;width:1px;height:1px}
.switch .track{flex:none;width:34px;height:20px;border-radius:999px;background:var(--rule);position:relative;transition:background .2s}
.switch .track::after{content:"";position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:var(--sheet);box-shadow:0 1px 2px rgba(0,0,0,.25);transition:transform .2s}
.switch input:checked+.track{background:var(--accent)}
.switch input:checked+.track::after{transform:translateX(14px)}
.switch input:focus-visible+.track{outline:2px solid var(--focus);outline-offset:2px}
.form-error{margin:0;padding:10px 12px;border-radius:10px;background:color-mix(in srgb,var(--sev-critical) 12%,var(--sheet));border:1px solid color-mix(in srgb,var(--sev-critical) 45%,transparent);font-size:13.5px}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:9px;font:600 14px/1 var(--sans);text-decoration:none;border-radius:11px;padding:11px 15px;cursor:pointer;border:1px solid var(--rule);white-space:nowrap}
.btn svg{width:18px;height:18px}
.btn.primary{background:var(--ink);color:var(--sheet);border-color:var(--ink)}
.btn.primary:hover{background:color-mix(in srgb,var(--ink) 86%,var(--accent))}
.btn.ghost{background:var(--sheet);color:var(--ink)}
.btn.ghost:hover{border-color:var(--ink-2)}
.btn.big{padding:15px 18px;font-size:15.5px;border-radius:13px}
.btn.sm{padding:7px 10px;font-size:12.5px;border-radius:8px}
.btn[disabled]{opacity:.55;cursor:progress}

.history ol{list-style:none;margin:0;padding:0;display:grid;gap:8px}
.history .nothing{color:var(--muted);font-size:13px}
.history button{width:100%;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:3px 10px;text-align:left;font:inherit;color:inherit;background:var(--sheet-2);border:1px solid var(--rule-2);border-radius:10px;padding:10px 12px;cursor:pointer}
.history button:hover,.history button[aria-current="true"]{border-color:var(--ink-2)}
.history .h-name{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.history .h-sub{grid-column:1/-1;font-size:12px;color:var(--muted)}
.badge{display:inline-flex;align-items:center;gap:6px;font:600 10px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;padding:4px 7px;border-radius:999px;border:1px solid var(--rule);color:var(--ink-2);background:var(--sheet)}
.badge i{width:7px;height:7px;border-radius:50%;background:var(--c,var(--muted))}

.stage{min-height:520px;display:flex;flex-direction:column;justify-content:center}
.stage h2,.result h2{font:500 34px/1.1 var(--serif);letter-spacing:-.01em;margin:0 0 8px;overflow-wrap:anywhere}
.target{color:var(--ink-2);margin:0;overflow-wrap:anywhere}
.empty-stage{align-items:center;text-align:center;background-image:repeating-linear-gradient(0deg,transparent 0 31px,var(--rule-2) 31px 32px)}
.empty-stage p{color:var(--ink-2);max-width:46ch}
.folder{width:150px;color:var(--ink-2);margin-bottom:10px}
.folder .bar1,.folder .bar2,.folder .bar3{fill:var(--redact);opacity:.85;animation:redact 3.2s ease-in-out infinite}
.folder .bar2{animation-delay:.25s}.folder .bar3{animation-delay:.5s}
@keyframes redact{0%,100%{transform:scaleX(1)}50%{transform:scaleX(.55)}}
.folder rect{transform-box:fill-box;transform-origin:left}
.facts{list-style:none;margin:22px 0 0;padding:0;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;text-align:left;max-width:720px}
.facts li{background:var(--sheet);border:1px solid var(--rule);border-radius:12px;padding:14px;font-size:13px;color:var(--ink-2);display:grid;gap:6px}
.facts b{font:600 11px/1 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--ink)}

.scanner{height:6px;border-radius:999px;background:var(--rule-2);overflow:hidden;margin:22px 0 20px;position:relative}
.scanner span{position:absolute;top:0;bottom:0;width:32%;border-radius:999px;background:linear-gradient(90deg,transparent,var(--accent),transparent);animation:sweep 1.4s ease-in-out infinite}
@keyframes sweep{from{left:-32%}to{left:100%}}
.steps{list-style:none;margin:0 0 22px;padding:0;display:grid;gap:10px}
.steps li{display:flex;align-items:center;gap:12px;font-size:14.5px;color:var(--muted)}
.steps li i{width:22px;height:22px;border-radius:50%;border:2px solid var(--rule);flex:none;position:relative}
.steps li.current{color:var(--ink);font-weight:600}
.steps li.current i{border-color:var(--accent);border-top-color:transparent;animation:spin .9s linear infinite}
.steps li.done{color:var(--ink-2)}
.steps li.done i{background:var(--ink);border-color:var(--ink)}
.steps li.done i::after{content:"";position:absolute;left:6px;top:2px;width:5px;height:10px;border:solid var(--sheet);border-width:0 2px 2px 0;transform:rotate(45deg)}
.steps li.skipped{opacity:.45;text-decoration:line-through}
@keyframes spin{to{transform:rotate(360deg)}}
.counters{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:0 0 14px}
.counters div{background:var(--sheet-2);border:1px solid var(--rule-2);border-radius:12px;padding:12px 14px}
.counters dt{font:600 10px/1 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin-bottom:8px}
.counters dd{margin:0;font:500 28px/1 var(--serif);font-variant-numeric:tabular-nums}
.err-msg{background:var(--code);border:1px solid var(--rule);border-left:4px solid var(--sev-critical);border-radius:10px;padding:12px 14px;margin:6px 0 18px;white-space:pre-wrap;overflow-wrap:anywhere}
#view-error .btn{align-self:flex-start}

.result{display:grid;gap:18px}
.result-head{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:20px;align-items:center}
.stamp{--c:var(--accent);transform:rotate(-6deg);border:3px double var(--c);color:var(--c);padding:11px 18px 9px;text-align:center;border-radius:6px;font-family:var(--mono);text-transform:uppercase;letter-spacing:.12em;animation:thunk .45s cubic-bezier(.2,1.6,.4,1) both}
.stamp b{display:block;font:700 18px/1.05 var(--mono)}
.stamp small{display:block;font-size:10px;margin-top:5px;opacity:.85}
.stamp.sev-critical{--c:var(--sev-critical)}.stamp.sev-high{--c:var(--sev-high)}.stamp.sev-medium{--c:var(--ink)}.stamp.sev-low{--c:var(--sev-low)}
@keyframes thunk{from{opacity:0;transform:rotate(-6deg) scale(1.5)}to{opacity:1;transform:rotate(-6deg) scale(1)}}
.sev-row{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.sev{position:relative;background:var(--sheet-2);border:1px solid var(--rule-2);border-radius:12px;padding:12px 14px 12px 18px;overflow:hidden}
.sev::before{content:"";position:absolute;left:0;top:0;bottom:0;width:5px;background:var(--c)}
.sev span{font:600 10.5px/1 var(--mono);letter-spacing:.14em;color:var(--ink-2)}
.sev b{display:block;font:500 32px/1 var(--serif);margin-top:8px;font-variant-numeric:tabular-nums}
.sev.zero b{color:var(--muted)}
.sev-critical{--c:var(--sev-critical)}.sev-high{--c:var(--sev-high)}.sev-medium{--c:var(--sev-medium)}.sev-low{--c:var(--sev-low)}
.result-meta{display:flex;flex-wrap:wrap;gap:8px 18px;font-size:13px;color:var(--ink-2)}
.result-meta b{color:var(--ink)}
.actions{display:flex;flex-wrap:wrap;gap:8px}
.top{margin-top:16px}
.toplist{list-style:none;margin:0;padding:0;display:grid;gap:6px}
.toplist li{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:4px 12px;align-items:center;padding:9px 12px;border-radius:10px;background:var(--sheet-2);border:1px solid var(--rule-2)}
.toplist .t{font-weight:600}
.toplist .p{grid-column:2/-1;font-family:var(--mono);font-size:12.5px;color:var(--ink-2);overflow-wrap:anywhere}
.toplist .pres{font:600 10px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;padding:4px 7px;border-radius:6px;border:1px solid var(--rule)}
.toplist .pres.hist{border-style:dashed}
.toplist .nothing{grid-template-columns:1fr;color:var(--muted)}
.frame{margin-top:16px;border:1px solid var(--rule);border-radius:16px;overflow:hidden;box-shadow:var(--shadow);background:var(--paper)}
.frame iframe{display:block;width:100%;height:82vh;min-height:620px;border:0;background:var(--paper)}

dialog{border:1px solid var(--rule);border-radius:18px;padding:0;background:var(--sheet);color:var(--ink);width:min(680px,calc(100vw - 32px));box-shadow:0 30px 80px -20px rgba(0,0,0,.45)}
dialog::backdrop{background:rgba(20,18,14,.45);backdrop-filter:blur(3px)}
.picker header{padding:20px 22px 12px;border-bottom:1px solid var(--rule)}
.picker h3{font:500 22px/1.1 var(--serif);margin:0 0 6px}
.crumb{margin:0 0 12px;color:var(--ink-2);overflow-wrap:anywhere}
.picker-nav{display:flex;gap:6px;flex-wrap:wrap}
.dirs{list-style:none;margin:0;padding:8px;max-height:min(52vh,460px);overflow:auto}
.dirs li button{width:100%;display:flex;align-items:center;gap:10px;font:14px var(--sans);color:var(--ink);background:none;border:0;border-radius:9px;padding:9px 10px;cursor:pointer;text-align:left}
.dirs li button:hover,.dirs li button:focus-visible{background:var(--sheet-2)}
.dirs .ico{width:18px;height:14px;flex:none;border:1.6px solid var(--muted);border-radius:2px 3px 3px 3px;position:relative}
.dirs .ico::before{content:"";position:absolute;left:-1.6px;top:-5px;width:8px;height:4px;border:1.6px solid var(--muted);border-bottom:0;border-radius:2px 2px 0 0}
.dirs .nm{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dirs .git{font:600 10px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;background:var(--ink);color:var(--sheet);padding:4px 7px;border-radius:999px}
.dirs .empty{padding:18px;color:var(--muted);font-size:13px;text-align:center}
.picker footer{display:flex;align-items:center;gap:8px;padding:14px 22px;border-top:1px solid var(--rule)}

.noauth{position:fixed;inset:0;z-index:30;display:grid;place-items:center;background:color-mix(in srgb,var(--paper) 88%,transparent);backdrop-filter:blur(6px);padding:16px}
.noauth .panel{max-width:520px}
.noauth h2{font:500 30px/1.1 var(--serif);margin:0 0 10px}

@media (max-width:1060px){.layout{grid-template-columns:1fr}.col-form{position:static}.stage{min-height:0;padding:32px 22px}}
@media (max-width:640px){
  .wrap{padding:0 16px}
  .hide-sm,.brand .sub,.iconbtn .t,#addr{display:none}
  .live{padding:9px}
  .bar .wrap{gap:10px}
  .intro{padding:28px 0 18px}
  .opt-grid,.facts{grid-template-columns:1fr}
  .counters,.sev-row{grid-template-columns:repeat(2,minmax(0,1fr))}
  .result-head{grid-template-columns:1fr}.stamp{justify-self:start}
  .field-row{flex-direction:column}
  .frame iframe{height:75vh;min-height:480px}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
`;

export const APP_JS = String.raw`
(function(){
  'use strict';
  var $=function(id){return document.getElementById(id);};
  var root=document.documentElement, THEME='glh-theme';
  function eff(){var t=root.getAttribute('data-theme');if(t)return t;return window.matchMedia&&matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';}
  function themeLabel(){var d=eff()==='dark';$('theme').setAttribute('aria-label',d?'Switch to light theme':'Switch to dark theme');$('theme').querySelector('.t').textContent=d?'Light':'Dark';}
  try{var sv=localStorage.getItem(THEME);if(sv==='light'||sv==='dark')root.setAttribute('data-theme',sv);}catch(e){}
  themeLabel();
  if(window.matchMedia){var mq=matchMedia('(prefers-color-scheme: dark)');if(mq.addEventListener)mq.addEventListener('change',themeLabel);}
  $('theme').addEventListener('click',function(){var n=eff()==='dark'?'light':'dark';root.setAttribute('data-theme',n);try{localStorage.setItem(THEME,n);}catch(e){}themeLabel();});
  $('addr').textContent=location.host;

  // ---- session token: from the launch link's #fragment, kept only in this tab ----
  var token=null, m=/[#&]token=([0-9a-f]{16,128})/.exec(location.hash);
  if(m){token=m[1];try{sessionStorage.setItem('glh-token',token);}catch(e){}history.replaceState(null,'',location.pathname);}
  else{try{token=sessionStorage.getItem('glh-token');}catch(e){}}
  if(!token){$('noauth').hidden=false;return;}

  function api(path,opts){
    opts=opts||{};var h={'x-glh-token':token};if(opts.body)h['content-type']='application/json';
    return fetch(path,{method:opts.method||'GET',headers:h,body:opts.body?JSON.stringify(opts.body):undefined,credentials:'omit',cache:'no-store'})
      .then(function(r){return r.json().catch(function(){return {};}).then(function(d){
        if(r.status===401){$('noauth').hidden=false;}
        if(!r.ok){var e=new Error(d.error||('HTTP '+r.status));e.status=r.status;throw e;}return d;});});
  }
  function el(tag,cls,text){var e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined&&text!==null)e.textContent=String(text);return e;}
  function fmt(n){return Number(n||0).toLocaleString('en-US');}
  var SEV=['critical','high','medium','low'], LABEL={critical:'Critical',high:'High',medium:'Medium',low:'Low'};
  var VERDICT={critical:'Critical exposure',high:'High risk',medium:'Moderate risk',low:'Low risk'};
  function reportUrl(id,kind,dl){return '/scans/'+id+'/report.'+kind+'?t='+encodeURIComponent(token)+(dl?'&download=1':'');}
  function isRemote(t){return /^[a-z][a-z0-9+.-]*:\/\//i.test(t)||/^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:/.test(t);}

  var session={cwd:'',home:''}, current=null, pollTimer=null, tickTimer=null, recent=[];

  // ---- views ----
  function show(view){['view-empty','view-running','view-error','view-done'].forEach(function(v){$(v).hidden=(v!==view);});}
  function showRunning(s){
    show('view-running');$('run-name').textContent=s.name;$('run-target').textContent=s.target;
    var order=['opening','walking','analyzing','verifying','writing'], idx=order.indexOf(s.phase);
    [].forEach.call($('steps').children,function(li){
      var p=li.getAttribute('data-phase'), i=order.indexOf(p);
      li.className=(p==='verifying'&&!s.verified)?'skipped':(idx>i||s.phase==='done'?'done':(i===idx?'current':''));
    });
    $('c-commits').textContent=fmt(s.counters.commitsWalked);$('c-files').textContent=fmt(s.counters.fileVersionsSeen);
    $('c-blobs').textContent=fmt(s.counters.uniqueBlobsScanned);$('c-hits').textContent=fmt(s.counters.cacheHits);
    clearInterval(tickTimer);
    var t0=Date.parse(s.startedAt);
    tickTimer=setInterval(function(){$('elapsed').textContent='Elapsed '+((Date.now()-t0)/1000).toFixed(1)+' s';},100);
  }
  function showError(s){clearInterval(tickTimer);show('view-error');$('err-name').textContent=s.name;$('err-msg').textContent=s.error||'Unknown error';}
  function showDone(s){
    clearInterval(tickTimer);show('view-done');
    var sum=s.summary||{total:0,bySeverity:{critical:0,high:0,medium:0,low:0},inHead:0,historyOnly:0};
    $('done-name').textContent=s.name;$('done-target').textContent=s.target;
    $('done-when').textContent='Completed '+new Date(s.finishedAt||Date.now()).toLocaleString();
    var top=SEV.filter(function(k){return sum.bySeverity[k]>0;})[0];
    var stamp=$('done-stamp');stamp.className='stamp'+(top?' sev-'+top:'');
    $('stamp-text').textContent=top?VERDICT[top]:'No findings';
    $('stamp-sub').textContent=fmt(sum.total)+' finding'+(sum.total===1?'':'s')+' · '+fmt(sum.historyOnly)+' history-only';
    var row=$('sev-row');row.textContent='';
    SEV.forEach(function(k){var d=el('div','sev sev-'+k+(sum.bySeverity[k]?'':' zero'));d.appendChild(el('span',null,LABEL[k].toUpperCase()));d.appendChild(el('b',null,fmt(sum.bySeverity[k])));row.appendChild(d);});
    var meta=$('done-meta');meta.textContent='';
    function m(k,v){var s2=el('span');s2.appendChild(el('b',null,v));s2.appendChild(document.createTextNode(' '+k));meta.appendChild(s2);}
    m('at HEAD',fmt(sum.inHead));m('history-only',fmt(sum.historyOnly));m('commits',fmt(s.counters.commitsWalked));
    m('unique blobs',fmt(s.counters.uniqueBlobsScanned));m('s',((s.durationMs||0)/1000).toFixed(2));
    if(s.verification)m('verified active',fmt(s.verification.active));
    $('open-report').href=reportUrl(s.id,'html');$('dl-html').href=reportUrl(s.id,'html',true);$('dl-json').href=reportUrl(s.id,'json');
    $('frame').src=reportUrl(s.id,'html');
    loadTop(s);
  }
  function loadTop(s){
    var ol=$('toplist');ol.textContent='';$('top-more').textContent='';
    fetch(reportUrl(s.id,'json'),{credentials:'omit',cache:'no-store'}).then(function(r){return r.json();}).then(function(rep){
      if(!current||current.id!==s.id)return;
      var f=rep.findings||[];
      if(!f.length){ol.appendChild(el('li','nothing','No secrets found in this repository’s history.'));return;}
      f.slice(0,8).forEach(function(x){
        var li=el('li');var b=el('span','badge sev-'+x.severity);b.appendChild(el('i'));b.appendChild(document.createTextNode(LABEL[x.severity]));li.appendChild(b);
        li.appendChild(el('span','t',x.secretType));
        li.appendChild(el('span','pres'+(x.presence==='history-only'?' hist':''),x.presence==='history-only'?'history-only':'at HEAD'));
        li.appendChild(el('span','p',x.filePath+':'+x.line+'  ·  '+x.redactedPreview));
        ol.appendChild(li);
      });
      if(f.length>8)$('top-more').textContent='+'+(f.length-8)+' more in the full report below.';
    }).catch(function(){});
  }
  function render(s){current=s;if(s.state==='running')showRunning(s);else if(s.state==='error')showError(s);else showDone(s);markHistory();}

  function poll(id){
    clearTimeout(pollTimer);
    api('/api/scans/'+id).then(function(s){
      if(!current||current.id===id)render(s);
      if(s.state==='running')pollTimer=setTimeout(function(){poll(id);},400);
      else{setBusy(false);refreshHistory();}
    }).catch(function(e){setBusy(false);formError(e.message);});
  }

  // ---- history ----
  function refreshHistory(){
    api('/api/scans').then(function(d){
      var ol=$('history');ol.textContent='';
      if(!d.scans.length){ol.appendChild(el('li','nothing','No scans yet.'));return;}
      d.scans.forEach(function(s){
        var li=el('li'),b=el('button');b.type='button';b.setAttribute('data-id',s.id);
        b.appendChild(el('span','h-name',s.name));
        var badge=el('span','badge');var dot=el('i');
        var sum=s.summary,top=sum?SEV.filter(function(k){return sum.bySeverity[k]>0;})[0]:null;
        if(top)badge.className='badge sev-'+top;
        badge.appendChild(dot);badge.appendChild(document.createTextNode(s.state==='running'?'running':s.state==='error'?'failed':(top?LABEL[top]:'clean')));
        b.appendChild(badge);
        b.appendChild(el('span','h-sub',(sum?fmt(sum.total)+' findings · ':'')+new Date(s.startedAt).toLocaleTimeString()+' · '+s.target));
        b.addEventListener('click',function(){api('/api/scans/'+s.id).then(function(x){render(x);if(x.state==='running')poll(x.id);});});
        li.appendChild(b);ol.appendChild(li);
      });
      markHistory();
    }).catch(function(){});
  }
  function markHistory(){[].forEach.call($('history').querySelectorAll('button[data-id]'),function(b){b.setAttribute('aria-current',String(!!current&&b.getAttribute('data-id')===current.id));});}

  // ---- form ----
  var target=$('target');
  function updateRemote(){$('remote-callout').hidden=!isRemote(target.value.trim());}
  target.addEventListener('input',function(){updateRemote();target.removeAttribute('aria-invalid');});
  function formError(msg){var e=$('form-error');e.textContent=msg||'';e.hidden=!msg;}
  function setBusy(b){$('go').disabled=b;$('go').querySelector('span').textContent=b?'Scanning…':'Scan repository';}
  function numVal(id){var v=$(id).value.trim();return v===''?undefined:Number(v);}
  $('scan-form').addEventListener('submit',function(ev){
    ev.preventDefault();formError('');
    var t=target.value.trim();
    if(!t){target.setAttribute('aria-invalid','true');formError('Enter a repository path or URL.');target.focus();return;}
    var body={target:t,ci:$('ci').checked,cache:$('cache').checked,authorized:$('authorized').checked,verify:$('verify').checked,confirmAuthorized:$('confirm').checked};
    if($('branch').value.trim())body.branch=$('branch').value.trim();
    if($('since').value)body.since=$('since').value;
    var mc=numVal('maxCommits'),eh=numVal('entropyHex'),eb=numVal('entropyBase64'),ml=numVal('minLength');
    if(mc!==undefined)body.maxCommits=mc;if(eh!==undefined)body.entropyHex=eh;if(eb!==undefined)body.entropyBase64=eb;if(ml!==undefined)body.minLength=ml;
    setBusy(true);
    api('/api/scans',{method:'POST',body:body}).then(function(s){
      if(recent.indexOf(t)===-1){recent.unshift(t);recent=recent.slice(0,4);quick();}
      render(s);refreshHistory();poll(s.id);
    }).catch(function(e){setBusy(false);formError(e.message);});
  });
  $('err-retry').addEventListener('click',function(){show('view-empty');target.focus();});
  $('new-scan').addEventListener('click',function(){current=null;markHistory();show('view-empty');target.focus();target.select();});

  function quick(){
    var q=$('quick');q.textContent='';
    var items=[];if(session.cwd)items.push({label:'Launch folder',value:session.cwd});
    recent.forEach(function(r){if(r!==session.cwd)items.push({label:r.split(/[\\/]/).filter(Boolean).pop()||r,value:r});});
    items.forEach(function(it){var b=el('button',null,it.label);b.type='button';b.title=it.value;b.addEventListener('click',function(){target.value=it.value;updateRemote();target.focus();});q.appendChild(b);});
  }

  // ---- folder picker ----
  var dlg=$('picker'), here=null;
  function openDir(p){
    api('/api/browse?path='+encodeURIComponent(p)).then(function(d){
      here=d;$('picker-path').textContent=d.path+(d.isRepo?'  —  git repository':'');$('pk-up').disabled=!d.parent;
      var ul=$('pk-list');ul.textContent='';
      if(!d.entries.length){ul.appendChild(el('li','empty','No sub-folders here.'));}
      d.entries.forEach(function(e){
        var li=el('li'),b=el('button');b.type='button';var ico=el('span','ico');b.appendChild(ico);b.appendChild(el('span','nm',e.name));
        if(e.isRepo)b.appendChild(el('span','git','git'));
        b.addEventListener('click',function(){openDir(e.path);});
        li.appendChild(b);ul.appendChild(li);
      });
      $('pk-note').textContent=d.truncated?'Showing the first entries only.':'Folders only. git marks a repository.';
    }).catch(function(e){$('pk-note').textContent=e.message;});
  }
  $('browse').addEventListener('click',function(){
    var t=target.value.trim();var start=(t&&!isRemote(t)&&(t.charAt(0)==='/'||/^[A-Za-z]:[\\/]/.test(t)))?t:(session.cwd||session.home);
    if(typeof dlg.showModal==='function')dlg.showModal();else dlg.setAttribute('open','');
    openDir(start);
  });
  $('pk-up').addEventListener('click',function(){if(here&&here.parent)openDir(here.parent);});
  $('pk-home').addEventListener('click',function(){openDir(session.home);});
  $('pk-cwd').addEventListener('click',function(){openDir(session.cwd);});
  $('pk-use').addEventListener('click',function(){if(here){target.value=here.path;updateRemote();}dlg.close();target.focus();});

  // ---- boot ----
  api('/api/session').then(function(s){session=s;target.placeholder=s.cwd+'  or  https://…/repo.git';quick();refreshHistory();}).catch(function(){});
  show('view-empty');
})();
`;
