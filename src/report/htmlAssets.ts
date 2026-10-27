/**
 * Inline CSS and the single inline script for report.html. Everything ships inside the file
 * (strict CSP: no external fonts, images, styles or scripts), so typography uses local font stacks
 * and charts are inline SVG / CSS.
 *
 * Severity colours are an ordinal ramp validated for colour-vision deficiency on both surfaces
 * (dataviz validator: adjacent CVD ΔE ≥ 13.9 light / 14.4 dark). They are only ever used on marks
 * and fills next to a text label — never as the colour of text.
 */

export const CSS = String.raw`
:root{
  --paper:#efe9dd; --sheet:#fbf8f2; --sheet-2:#f5f0e6; --ink:#1c1a16; --ink-2:#47423a; --muted:#6f685c;
  --rule:#d8cfbf; --rule-2:#e7e0d2; --accent:#25407a; --accent-soft:#dfe5f1; --focus:#25407a;
  --redact:#1c1a16; --code:#f1ebdf; --shadow:0 1px 0 rgba(28,26,22,.04),0 8px 24px -12px rgba(28,26,22,.18);
  --sev-critical:#9b1c1c; --sev-high:#d9531e; --sev-medium:#e6a03a; --sev-low:#4f74b8;
  --on-critical:#fff; --on-high:#fff; --on-medium:#1c1a16; --on-low:#fff;
  --hatch:rgba(28,26,22,.55); --grain:.07;
  --serif:"Iowan Old Style","Palatino Linotype",Palatino,"Book Antiqua","URW Palladio L",Georgia,serif;
  --sans:"Avenir Next",Avenir,"Segoe UI Variable Text","Segoe UI","Helvetica Neue",Ubuntu,sans-serif;
  --mono:"Berkeley Mono","JetBrains Mono","SF Mono","Cascadia Code",Menlo,Consolas,"Liberation Mono",monospace;
  color-scheme:light;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --paper:#0f1012; --sheet:#17181b; --sheet-2:#1d1f23; --ink:#ece6da; --ink-2:#c3bbab; --muted:#958d7f;
  --rule:#2d2f34; --rule-2:#24262a; --accent:#9db4ff; --accent-soft:#232a3d; --focus:#9db4ff;
  --redact:#ece6da; --code:#121315; --shadow:0 1px 0 rgba(0,0,0,.3),0 12px 32px -16px rgba(0,0,0,.7);
  --sev-critical:#ff958c; --sev-high:#cc5a1e; --sev-medium:#d9a43a; --sev-low:#4f86d9;
  --on-critical:#1c0d0b; --on-high:#fff; --on-medium:#17130b; --on-low:#fff;
  --hatch:rgba(236,230,218,.5); --grain:.05; color-scheme:dark;
}}
:root[data-theme="dark"]{
  --paper:#0f1012; --sheet:#17181b; --sheet-2:#1d1f23; --ink:#ece6da; --ink-2:#c3bbab; --muted:#958d7f;
  --rule:#2d2f34; --rule-2:#24262a; --accent:#9db4ff; --accent-soft:#232a3d; --focus:#9db4ff;
  --redact:#ece6da; --code:#121315; --shadow:0 1px 0 rgba(0,0,0,.3),0 12px 32px -16px rgba(0,0,0,.7);
  --sev-critical:#ff958c; --sev-high:#cc5a1e; --sev-medium:#d9a43a; --sev-low:#4f86d9;
  --on-critical:#1c0d0b; --on-high:#fff; --on-medium:#17130b; --on-low:#fff;
  --hatch:rgba(236,230,218,.5); --grain:.05; color-scheme:dark;
}
*,*::before,*::after{box-sizing:border-box}
html{scroll-behavior:smooth;scroll-padding-top:76px}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 var(--sans);-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
.grain{position:fixed;inset:0;width:100%;height:100%;pointer-events:none;opacity:var(--grain);z-index:0;mix-blend-mode:multiply}
:root[data-theme="dark"] .grain{mix-blend-mode:screen}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]) .grain{mix-blend-mode:screen}}
.wrap{position:relative;z-index:1;max-width:1180px;margin:0 auto;padding:0 28px}
a{color:var(--accent)}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px;border-radius:4px}
.skip{position:absolute;left:-9999px;top:8px;background:var(--ink);color:var(--sheet);padding:8px 12px;border-radius:6px;z-index:20}
.skip:focus{left:12px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.mono{font-family:var(--mono);font-size:.86em;letter-spacing:-.01em}
.eyebrow{font:600 11px/1 var(--mono);letter-spacing:.18em;text-transform:uppercase;color:var(--muted)}

/* ---------- top bar ---------- */
.bar{position:sticky;top:0;z-index:10;background:color-mix(in srgb,var(--paper) 86%,transparent);backdrop-filter:saturate(1.2) blur(10px);-webkit-backdrop-filter:saturate(1.2) blur(10px);border-bottom:1px solid var(--rule)}
.bar .wrap{display:flex;align-items:center;gap:18px;height:58px}
.brand{display:flex;align-items:center;gap:10px;font:600 15px/1 var(--serif);letter-spacing:.01em;white-space:nowrap}
.brand svg{flex:none}
.nav{display:flex;gap:4px;margin-left:12px}
.nav a{font:500 13px/1 var(--sans);color:var(--ink-2);text-decoration:none;padding:8px 12px;border-radius:999px}
.nav a:hover{background:var(--sheet-2);color:var(--ink)}
.bar .spacer{flex:1}
.iconbtn{display:inline-flex;align-items:center;gap:8px;font:500 13px/1 var(--sans);color:var(--ink);background:var(--sheet);border:1px solid var(--rule);padding:8px 12px;border-radius:999px;cursor:pointer}
.iconbtn:hover{border-color:var(--ink-2)}
.iconbtn svg{width:15px;height:15px}

/* ---------- case header ---------- */
.classified{margin-top:26px;display:flex;align-items:center;gap:14px;color:var(--muted)}
.classified::before,.classified::after{content:"";flex:1;height:0;border-top:1px dashed var(--rule)}
.case{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:32px;align-items:end;padding:22px 0 30px;border-bottom:2px solid var(--ink)}
.case h1{font:500 clamp(36px,6vw,68px)/.98 var(--serif);letter-spacing:-.02em;margin:10px 0 12px;overflow-wrap:anywhere}
.case .target{font-family:var(--mono);font-size:13px;color:var(--ink-2);overflow-wrap:anywhere}
.meta{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:0;margin-top:22px;border-top:1px solid var(--rule)}
.meta div{padding:12px 16px 0 0}
.meta dt{font:600 10.5px/1 var(--mono);letter-spacing:.16em;text-transform:uppercase;color:var(--muted);margin-bottom:7px}
.meta dd{margin:0;font-size:14px;overflow-wrap:anywhere}
.stamp{--c:var(--ink);justify-self:end;transform:rotate(-7deg);border:3px double var(--c);color:var(--c);padding:14px 22px 12px;text-align:center;border-radius:6px;font-family:var(--mono);text-transform:uppercase;letter-spacing:.14em;position:relative;min-width:220px;animation:thunk .5s cubic-bezier(.2,1.6,.4,1) .35s both}
.stamp b{display:block;font:700 22px/1.05 var(--mono);letter-spacing:.08em}
.stamp small{display:block;font-size:10.5px;margin-top:6px;opacity:.85}
.stamp::after{content:"";position:absolute;inset:-3px;border-radius:6px;background:repeating-linear-gradient(115deg,transparent 0 9px,var(--paper) 9px 10px);opacity:.35;pointer-events:none;mix-blend-mode:normal}
.stamp.sev-critical{--c:var(--sev-critical)}.stamp.sev-high{--c:var(--sev-high)}.stamp.sev-medium{--c:var(--ink)}.stamp.sev-low{--c:var(--sev-low)}.stamp.clean{--c:var(--accent)}
@keyframes thunk{from{opacity:0;transform:rotate(-7deg) scale(1.6)}to{opacity:1;transform:rotate(-7deg) scale(1)}}

/* ---------- sections ---------- */
section{padding:44px 0 8px}
.sechead{display:flex;align-items:baseline;gap:16px;margin-bottom:18px}
.sechead h2{font:500 30px/1.1 var(--serif);letter-spacing:-.01em;margin:0}
.sechead .num{font:600 12px/1 var(--mono);color:var(--muted);letter-spacing:.12em}
.sechead p{margin:0 0 0 auto;color:var(--muted);font-size:13px;max-width:52ch;text-align:right}
.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:16px}
.panel{background:var(--sheet);border:1px solid var(--rule);border-radius:14px;padding:20px 22px;box-shadow:var(--shadow);min-width:0}
.panel h3{font:600 11px/1 var(--mono);letter-spacing:.16em;text-transform:uppercase;color:var(--muted);margin:0 0 16px}
.span-3{grid-column:span 3}.span-4{grid-column:span 4}.span-5{grid-column:span 5}.span-6{grid-column:span 6}.span-7{grid-column:span 7}.span-8{grid-column:span 8}.span-12{grid-column:span 12}
.reveal{animation:rise .6s cubic-bezier(.2,.7,.2,1) both;animation-delay:calc(var(--i,0)*70ms)}
@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}

/* severity tiles */
.tile{position:relative;overflow:hidden;padding:18px 20px 16px}
.tile .label{display:flex;align-items:center;gap:8px;font:600 11px/1 var(--mono);letter-spacing:.16em;color:var(--ink-2)}
.tile .count{font:500 56px/1 var(--serif);letter-spacing:-.03em;margin:14px 0 6px;font-variant-numeric:lining-nums tabular-nums}
.tile .share{font-size:12.5px;color:var(--muted)}
.tile::before{content:"";position:absolute;left:0;top:0;bottom:0;width:5px;background:var(--c)}
.tile.zero .count{color:var(--muted)}
.sw{display:inline-block;width:10px;height:10px;border-radius:3px;background:var(--c);flex:none}
.sev-critical{--c:var(--sev-critical);--on:var(--on-critical)}.sev-high{--c:var(--sev-high);--on:var(--on-high)}.sev-medium{--c:var(--sev-medium);--on:var(--on-medium)}.sev-low{--c:var(--sev-low);--on:var(--on-low)}

/* stacked severity bar */
.stack{display:flex;gap:2px;height:22px;border-radius:6px;overflow:hidden;background:var(--rule-2)}
.stack span{background:var(--c);min-width:3px}
.legend{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px 18px;margin:16px 0 0;padding:0;list-style:none}
.legend li{display:flex;align-items:center;gap:9px;font-size:13.5px}
.legend b{font-weight:600;margin-left:auto;font-variant-numeric:tabular-nums}
.legend em{font-style:normal;color:var(--muted);font-size:12px;min-width:3.5em;text-align:right;font-variant-numeric:tabular-nums}

/* exposure */
.expo{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px}
.expo .n{font:500 40px/1 var(--serif);font-variant-numeric:tabular-nums}
.expo .k{font:600 10.5px/1.3 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin-top:6px}
.split{display:flex;gap:2px;height:14px;border-radius:5px;overflow:hidden;background:var(--rule-2)}
.split .head{background:var(--ink)}
.split .hist{background:repeating-linear-gradient(45deg,var(--hatch) 0 2px,transparent 2px 6px);box-shadow:inset 0 0 0 1px var(--hatch)}
.note{font-size:12.5px;color:var(--muted);margin:12px 0 0}
.keyhatch{display:inline-block;width:12px;height:12px;vertical-align:-1px;border-radius:3px;background:repeating-linear-gradient(45deg,var(--hatch) 0 2px,transparent 2px 5px);box-shadow:inset 0 0 0 1px var(--hatch);margin-right:6px}
.keyink{display:inline-block;width:12px;height:12px;vertical-align:-1px;border-radius:3px;background:var(--ink);margin-right:6px}

/* bar lists */
.bars{list-style:none;margin:0;padding:0;display:grid;gap:11px}
.bars li{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 12px;align-items:center;font-size:13.5px}
.bars .lbl{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bars .val{font-weight:600;font-variant-numeric:tabular-nums}
.bars .track{grid-column:1/-1;height:8px;background:var(--rule-2);border-radius:4px;overflow:hidden}
.bars .fill{display:block;height:100%;background:var(--accent);border-radius:0 4px 4px 0;min-width:3px}
.bars.files .lbl{font-family:var(--mono);font-size:12.5px}
.empty-mini{color:var(--muted);font-size:13px;margin:0}

/* timeline */
.timeline svg{display:block;width:100%;height:auto;overflow:visible}
.timeline .axis{stroke:var(--rule);stroke-width:1}
.timeline .tick{fill:var(--muted);font:11px var(--mono)}
.timeline .dot{stroke:var(--sheet);stroke-width:2.5}
.timeline .dot.hist{fill-opacity:.35;stroke:var(--c);stroke-dasharray:2 2}
.timeline .dot.sev-critical{fill:var(--sev-critical);--c:var(--sev-critical)}.timeline .dot.sev-high{fill:var(--sev-high)}.timeline .dot.sev-medium{fill:var(--sev-medium)}.timeline .dot.sev-low{fill:var(--sev-low)}
.timeline .dot.hist.sev-high{stroke:var(--sev-high)}.timeline .dot.hist.sev-medium{stroke:var(--sev-medium)}.timeline .dot.hist.sev-low{stroke:var(--sev-low)}.timeline .dot.hist.sev-critical{stroke:var(--sev-critical)}
.tl-legend{display:flex;flex-wrap:wrap;gap:8px 18px;margin-top:10px;font-size:12.5px;color:var(--ink-2)}
.tl-legend span{display:inline-flex;align-items:center;gap:6px}
.ring{width:11px;height:11px;border-radius:50%;border:1.5px dashed var(--ink-2)}
.solid{width:11px;height:11px;border-radius:50%;background:var(--ink-2)}

/* verification */
.vlist{list-style:none;margin:0;padding:0;display:grid;gap:8px}
.vlist li{display:flex;justify-content:space-between;align-items:center;padding:8px 10px;border-radius:8px;background:var(--sheet-2);font-size:13.5px}
.vlist b{font-variant-numeric:tabular-nums}
.pill{display:inline-flex;align-items:center;gap:6px;font:600 10.5px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;padding:5px 8px;border-radius:999px;border:1px solid var(--rule);color:var(--ink-2);background:var(--sheet)}
.pill i{width:7px;height:7px;border-radius:50%;background:var(--muted)}
.pill.v-ACTIVE i{background:var(--sev-critical)}.pill.v-INACTIVE i{background:var(--sev-low)}.pill.v-UNVERIFIABLE i{background:var(--sev-medium)}

/* ---------- findings explorer ---------- */
.toolbar{position:sticky;top:58px;z-index:5;background:color-mix(in srgb,var(--paper) 92%,transparent);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);padding:12px 0;margin-bottom:6px;border-bottom:1px solid var(--rule);display:grid;gap:10px}
.trow{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.search{flex:1 1 280px;display:flex;align-items:center;gap:8px;background:var(--sheet);border:1px solid var(--rule);border-radius:10px;padding:0 10px}
.search:focus-within{border-color:var(--focus);box-shadow:0 0 0 3px var(--accent-soft)}
.search input{flex:1;border:0;background:transparent;color:var(--ink);font:14px var(--sans);padding:10px 2px;outline:none;min-width:0}
.search kbd{font:11px var(--mono);color:var(--muted);border:1px solid var(--rule);border-radius:5px;padding:2px 6px}
.chip{display:inline-flex;align-items:center;gap:7px;font:600 11.5px/1 var(--mono);letter-spacing:.08em;text-transform:uppercase;padding:9px 12px;border-radius:999px;border:1px solid var(--rule);background:var(--sheet);color:var(--ink-2);cursor:pointer}
.chip:hover{border-color:var(--ink-2)}
.chip[aria-pressed="true"]{background:var(--ink);color:var(--sheet);border-color:var(--ink)}
.chip .n{font-variant-numeric:tabular-nums;opacity:.75}
.seg{display:inline-flex;border:1px solid var(--rule);border-radius:999px;overflow:hidden;background:var(--sheet)}
.seg button{font:500 12.5px/1 var(--sans);border:0;background:transparent;color:var(--ink-2);padding:9px 13px;cursor:pointer}
.seg button[aria-pressed="true"]{background:var(--accent-soft);color:var(--ink);font-weight:600}
select{font:500 12.5px/1 var(--sans);color:var(--ink);background:var(--sheet);border:1px solid var(--rule);border-radius:999px;padding:9px 12px}
.tiny{font:500 12.5px/1 var(--sans);background:none;border:0;color:var(--accent);cursor:pointer;padding:8px 4px;text-decoration:underline;text-underline-offset:3px}
.count-line{font-size:13px;color:var(--muted);margin-left:auto}
.list{display:grid;gap:14px;padding-top:12px}
.card{display:grid;grid-template-columns:76px minmax(0,1fr);background:var(--sheet);border:1px solid var(--rule);border-radius:14px;box-shadow:var(--shadow);overflow:hidden;scroll-margin-top:140px}
.card[hidden]{display:none}
.card .rail{background:var(--c);color:var(--on);display:flex;flex-direction:column;align-items:center;justify-content:space-between;padding:16px 6px}
.card .idx{font:600 11px/1 var(--mono);letter-spacing:.1em;opacity:.85}
.card .sevtxt{writing-mode:vertical-rl;transform:rotate(180deg);font:700 12px/1 var(--mono);letter-spacing:.32em}
.card .body{padding:18px 22px 6px;min-width:0}
.card h4{font:500 22px/1.15 var(--serif);margin:0 0 8px;letter-spacing:-.01em}
.tags{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px}
.tag{font:600 10.5px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;padding:5px 8px;border-radius:6px;background:var(--sheet-2);color:var(--ink-2);border:1px solid var(--rule-2)}
.tag.hist{background:repeating-linear-gradient(45deg,transparent 0 5px,var(--rule-2) 5px 7px);color:var(--ink);border:1px dashed var(--ink-2)}
.tag.head{background:var(--ink);color:var(--sheet);border-color:var(--ink)}
.path{display:flex;align-items:center;gap:8px;font-family:var(--mono);font-size:13.5px;overflow-wrap:anywhere;margin-bottom:12px}
.path .ln{color:var(--muted)}
.facts{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:0 0 14px;padding:12px 0;border-top:1px dashed var(--rule);border-bottom:1px dashed var(--rule)}
.facts dt{font:600 10px/1 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
.facts dd{margin:0;font-size:13.5px;overflow-wrap:anywhere}
.evidence{display:flex;flex-wrap:wrap;align-items:center;gap:10px 14px;margin-bottom:12px}
.redact{display:inline-flex;align-items:center;font-family:var(--mono);font-size:14px;border:1px solid var(--rule);border-radius:7px;background:var(--sheet-2);padding:5px 9px;gap:2px;max-width:100%;overflow-wrap:anywhere}
.redact .blk{background:var(--redact);color:transparent;border-radius:2px;letter-spacing:-.06em;user-select:none;-webkit-user-select:none;padding:0 2px}
.copy{flex:none;white-space:nowrap;font:500 11.5px/1 var(--sans);border:1px solid var(--rule);background:var(--sheet);color:var(--ink-2);border-radius:6px;padding:5px 8px;cursor:pointer}
.copy:hover{border-color:var(--ink-2);color:var(--ink)}
.copy.done{border-color:var(--sev-low);color:var(--ink)}
details.more{border-top:1px solid var(--rule-2);margin:0 -22px;padding:0 22px}
details.more summary{cursor:pointer;list-style:none;padding:12px 0;font:600 12px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--accent);display:flex;align-items:center;gap:8px}
details.more summary::-webkit-details-marker{display:none}
details.more summary::before{content:"+";font:600 15px/1 var(--mono);width:14px}
details.more[open] summary::before{content:"\2212"}
.drawer{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(0,1fr);gap:20px;padding:4px 0 20px}
.k{font:600 10px/1 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin:14px 0 7px}
.k:first-child{margin-top:4px}
.code{display:grid;grid-template-columns:auto minmax(0,1fr);background:var(--code);border:1px solid var(--rule);border-radius:9px;font:12.5px/1.6 var(--mono);overflow:hidden}
.code .g{padding:8px 10px;color:var(--muted);border-right:1px solid var(--rule);text-align:right;user-select:none}
.code pre{margin:0;padding:8px 12px;white-space:pre-wrap;overflow-wrap:anywhere;font:inherit}
.msg{margin:0;padding:10px 12px;background:var(--sheet-2);border-left:3px solid var(--rule);border-radius:0 8px 8px 0;font-size:13.5px;white-space:pre-wrap;overflow-wrap:anywhere}
.steps{margin:0;padding-left:18px;font-size:13.5px;display:grid;gap:6px}
.kv{display:grid;grid-template-columns:auto minmax(0,1fr);gap:7px 14px;margin:0;font-size:13px}
.kv dt{color:var(--muted)}
.kv dd{margin:0;overflow-wrap:anywhere}
.meter{display:flex;align-items:center;gap:10px}
.meter .m{flex:1;height:8px;border-radius:4px;background:var(--rule-2);position:relative;overflow:hidden}
.meter .m span{display:block;position:absolute;left:0;top:0;bottom:0;background:var(--accent);border-radius:0 4px 4px 0}
.none{display:none;text-align:center;padding:46px 20px;border:1px dashed var(--rule);border-radius:14px;color:var(--muted)}
.none.on{display:block}
.clean{text-align:center;padding:60px 24px}
.clean h3{font:500 34px/1.1 var(--serif);margin:14px 0 8px;letter-spacing:-.01em;text-transform:none;color:var(--ink)}
.clean p{color:var(--muted);max-width:56ch;margin:0 auto}

/* ---------- details ---------- */
.stat .v{font:500 34px/1 var(--serif);font-variant-numeric:tabular-nums;letter-spacing:-.02em}
.stat .s{font-size:12.5px;color:var(--muted);margin-top:6px}
table.opts{width:100%;border-collapse:collapse;font-size:13.5px}
table.opts th,table.opts td{text-align:left;padding:9px 0;border-bottom:1px dashed var(--rule)}
table.opts th{font-weight:500;color:var(--muted);width:46%}
table.opts td{font-family:var(--mono);font-size:12.5px}

footer{margin:56px 0 40px;padding-top:22px;border-top:2px solid var(--ink);display:grid;grid-template-columns:minmax(0,1.4fr) minmax(0,1fr);gap:28px;font-size:13px;color:var(--ink-2)}
footer h5{font:600 11px/1 var(--mono);letter-spacing:.16em;text-transform:uppercase;color:var(--muted);margin:0 0 10px}
footer ul{margin:0;padding-left:18px;display:grid;gap:4px}
footer .sig{font-family:var(--mono);font-size:12px;color:var(--muted);text-align:right;align-self:end}

@media (max-width:980px){
  .span-3{grid-column:span 6}.span-4,.span-5,.span-7,.span-8,.span-6{grid-column:span 12}
  .meta{grid-template-columns:repeat(3,minmax(0,1fr))}
  .drawer{grid-template-columns:1fr}
  .nav{display:none}
}
@media (max-width:640px){
  .wrap{padding:0 16px}
  .case{grid-template-columns:1fr}
  .stamp{justify-self:start;min-width:0}
  .meta{grid-template-columns:repeat(2,minmax(0,1fr))}
  .span-3{grid-column:span 6}
  .tile .count{font-size:42px}
  .sechead{flex-wrap:wrap}.sechead p{margin:0;text-align:left}
  .card{grid-template-columns:44px minmax(0,1fr)}
  .card .body{padding:16px 16px 4px}
  details.more{margin:0 -16px;padding:0 16px}
  .facts{grid-template-columns:repeat(2,minmax(0,1fr))}
  .legend{grid-template-columns:1fr}
  footer{grid-template-columns:1fr}footer .sig{text-align:left}
  .brand .full{display:none}
  .bar .wrap{gap:10px}
  .iconbtn span{display:none}
  .iconbtn{padding:9px}
  .toolbar{position:static;background:none;backdrop-filter:none;-webkit-backdrop-filter:none}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important;scroll-behavior:auto!important}}
@media print{
  :root{--paper:#fff;--sheet:#fff;--sheet-2:#f6f6f6;--ink:#000;--ink-2:#222;--muted:#555;--rule:#bbb;--rule-2:#ddd;--shadow:none;--code:#f6f6f6;--redact:#000;color-scheme:light}
  .grain,.bar,.toolbar,.copy,.tiny,.skip{display:none!important}
  body{font-size:11pt}
  .card,.panel{break-inside:avoid;box-shadow:none}
  .card[hidden]{display:grid!important}
  details.more>*{display:block}
  .reveal,.stamp{animation:none}
  section{padding-top:24px}
  *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
@media (forced-colors:active){.card .rail,.tile::before,.stack span,.bars .fill{forced-color-adjust:none}}
`;

export const SCRIPT = String.raw`
(function(){
  var root=document.documentElement, KEY='glh-theme';
  function effective(){var t=root.getAttribute('data-theme');if(t)return t;return window.matchMedia&&matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';}
  function label(){var b=document.getElementById('theme');if(b){var d=effective()==='dark';b.setAttribute('aria-label',d?'Switch to light theme':'Switch to dark theme');b.querySelector('.t').textContent=d?'Light':'Dark';}}
  try{var saved=localStorage.getItem(KEY);if(saved==='light'||saved==='dark')root.setAttribute('data-theme',saved);}catch(e){}
  label();
  if(window.matchMedia){var mq=matchMedia('(prefers-color-scheme: dark)');if(mq.addEventListener)mq.addEventListener('change',label);else if(mq.addListener)mq.addListener(label);}
  var tb=document.getElementById('theme');
  if(tb)tb.addEventListener('click',function(){var next=effective()==='dark'?'light':'dark';root.setAttribute('data-theme',next);try{localStorage.setItem(KEY,next);}catch(e){}label();});
  var pb=document.getElementById('print');if(pb)pb.addEventListener('click',function(){window.print();});

  var list=document.getElementById('list');
  if(list){
    var cards=[].slice.call(list.querySelectorAll('.card'));
    var sev={}, presence='all', detector='all', q='';
    var shown=document.getElementById('shown'), none=document.getElementById('none');
    function apply(){
      var any=Object.keys(sev).some(function(k){return sev[k];}), n=0;
      cards.forEach(function(c){
        var ok=(!any||sev[c.getAttribute('data-sev')])&&(presence==='all'||c.getAttribute('data-presence')===presence)&&(detector==='all'||c.getAttribute('data-detector')===detector)&&(!q||c.getAttribute('data-search').indexOf(q)!==-1);
        c.hidden=!ok;if(ok)n++;
      });
      if(shown)shown.textContent=String(n);
      if(none)none.classList.toggle('on',n===0);
    }
    [].forEach.call(document.querySelectorAll('[data-sev-chip]'),function(b){
      b.addEventListener('click',function(){var k=b.getAttribute('data-sev-chip');sev[k]=!sev[k];b.setAttribute('aria-pressed',String(!!sev[k]));apply();});
    });
    [].forEach.call(document.querySelectorAll('[data-presence-btn]'),function(b){
      b.addEventListener('click',function(){presence=b.getAttribute('data-presence-btn');[].forEach.call(document.querySelectorAll('[data-presence-btn]'),function(x){x.setAttribute('aria-pressed',String(x===b));});apply();});
    });
    var ds=document.getElementById('detector');if(ds)ds.addEventListener('change',function(){detector=ds.value;apply();});
    var input=document.getElementById('q'),timer;
    if(input)input.addEventListener('input',function(){clearTimeout(timer);timer=setTimeout(function(){q=input.value.trim().toLowerCase();apply();},90);});
    document.addEventListener('keydown',function(e){
      var t=e.target&&e.target.tagName;
      if(e.key==='/'&&t!=='INPUT'&&t!=='SELECT'&&t!=='TEXTAREA'&&input){e.preventDefault();input.focus();}
      if(e.key==='Escape'&&document.activeElement===input){input.value='';q='';apply();input.blur();}
    });
    var so=document.getElementById('sort');
    if(so)so.addEventListener('change',function(){
      var k=so.value;
      cards.sort(function(a,b){
        if(k==='newest')return Number(b.getAttribute('data-time'))-Number(a.getAttribute('data-time'));
        if(k==='oldest')return Number(a.getAttribute('data-time'))-Number(b.getAttribute('data-time'));
        if(k==='path')return a.getAttribute('data-path')<b.getAttribute('data-path')?-1:1;
        return Number(a.getAttribute('data-order'))-Number(b.getAttribute('data-order'));
      });
      cards.forEach(function(c){list.appendChild(c);});
      if(none)list.appendChild(none);
    });
    function all(open){[].forEach.call(list.querySelectorAll('details.more'),function(d){d.open=open;});}
    var ea=document.getElementById('expand'),ca=document.getElementById('collapse');
    if(ea)ea.addEventListener('click',function(){all(true);});
    if(ca)ca.addEventListener('click',function(){all(false);});
    var wasOpen=[];
    window.addEventListener('beforeprint',function(){wasOpen=[].map.call(list.querySelectorAll('details.more'),function(d){return d.open;});all(true);});
    window.addEventListener('afterprint',function(){[].forEach.call(list.querySelectorAll('details.more'),function(d,i){d.open=!!wasOpen[i];});});
    [].forEach.call(document.querySelectorAll('[data-jump]'),function(a){
      a.addEventListener('click',function(){var k=a.getAttribute('data-jump');var b=document.querySelector('[data-sev-chip="'+k+'"]');if(b&&!sev[k]){b.click();}});
    });
  }

  [].forEach.call(document.querySelectorAll('.copy[data-copy]'),function(b){
    b.addEventListener('click',function(){
      var v=b.getAttribute('data-copy'),old=b.textContent;
      function ok(){b.textContent='Copied';b.classList.add('done');setTimeout(function(){b.textContent=old;b.classList.remove('done');},1200);}
      if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(v).then(ok,function(){});}
    });
  });
})();
`;
