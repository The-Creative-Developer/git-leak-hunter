/**
 * Shared design tokens for report.html and the local web UI: archival paper / carbon themes,
 * local font stacks, and the severity ramp (validated for colour-vision deficiency on both
 * surfaces; always paired with a text label, never used as text colour).
 * Light by default, dark via prefers-color-scheme, and `data-theme` on <html> overrides both.
 */
export const THEME_CSS = String.raw`
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
`;
