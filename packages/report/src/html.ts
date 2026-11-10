import type { ReportView, RevealedFinding } from './view';

/**
 * Self-contained HTML for the PDF export: inline CSS, no scripts, no external requests.
 * Every value is escaped, because finding titles can include text taken from the scanned
 * site (plugin names from readme files, for example).
 */
export function esc(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function safeUrl(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  try {
    const u = new URL(value);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.toString() : null;
  } catch {
    return null;
  }
}

const link = (url: unknown, label?: string) => {
  const safe = safeUrl(url);
  return safe ? `<a href="${esc(safe)}">${esc(label ?? safe)}</a>` : esc(label ?? '');
};

const SEVERITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' } as const;
const EFFORT = { minutes: 'a few minutes', hour: 'about an hour', day: 'a day or more' } as const;

function evidenceRows(evidence: Record<string, unknown>): string {
  const rows: Array<[string, string]> = [];
  if (evidence.url) rows.push(['Where', link(evidence.url)]);
  if (evidence.status) rows.push(['Response', esc(evidence.status)]);
  if (evidence.snippet) rows.push(['Seen', `<code>${esc(evidence.snippet)}</code>`]);
  const detail = (evidence.detail ?? {}) as Record<string, unknown>;
  for (const [key, value] of Object.entries(detail).slice(0, 8)) {
    if (value === null || value === undefined || key === 'vulnerabilities') continue;
    const text = typeof value === 'object' ? JSON.stringify(value) : String(value);
    rows.push([key.replace(/([A-Z])/g, ' $1').toLowerCase(), esc(text.length > 300 ? `${text.slice(0, 300)}…` : text)]);
  }
  const vulns = Array.isArray(detail.vulnerabilities) ? (detail.vulnerabilities as Array<Record<string, unknown>>) : [];
  if (vulns.length > 0) {
    rows.push(['Vulnerabilities', `<ul>${vulns.slice(0, 15).map((v) => `<li>${esc(v.id)}: ${esc(v.title)} (${esc(v.severity)})</li>`).join('')}</ul>`]);
  }
  if (rows.length === 0) return '';
  return `<table class="evidence">${rows.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${v}</td></tr>`).join('')}</table>`;
}

function findingHtml(f: RevealedFinding, index: number): string {
  const fix =
    f.fix && f.fix.length > 0
      ? `<h4>How to fix it</h4>${f.fixNote ? `<p class="note">${esc(f.fixNote)}</p>` : ''}${f.fix
          .map((g) => `<div class="guide"><p><strong>${esc(g.title)}</strong> <span class="muted">(${EFFORT[g.effort]})</span>. ${esc(g.summary)}</p><ol>${g.steps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol></div>`)
          .join('')}`
      : '';
  const refs = [
    ...f.standards.weaknesses.map((w) => link(w.url, `${w.id} ${w.name}`)),
    ...f.standards.attackPatterns.map((a) => link(a.url, `${a.id} ${a.name}`)),
    ...f.standards.owasp.map((o) => esc(`OWASP ${o.id} ${o.name}`)),
    ...f.references.filter((r) => r.type === 'cve').map((r) => link(r.url, r.id)),
  ];
  const attribution = f.attribution
    ? `<p class="attribution">Source: ${link(f.attribution.recordUrl ?? undefined, f.attribution.source === 'wordfence' ? 'Wordfence Intelligence record' : f.attribution.source.toUpperCase())}${
        f.attribution.notices.length ? `. ${f.attribution.notices.map(esc).join('. ')}` : ''
      }</p>`
    : '';
  return `<section class="finding sev-${f.severity}">
    <div class="finding-head"><span class="sev">${SEVERITY_LABEL[f.severity]}</span><span class="num">#${index + 1}</span><span class="cat">${esc(f.category)}</span><span class="conf">${esc(f.confidence)}</span></div>
    <h3>${esc(f.title)}</h3>
    ${f.indicatesCompromise ? '<p class="compromise">This may mean the site has already been broken into.</p>' : ''}
    <p>${esc(f.explanation)}</p>
    ${evidenceRows(f.evidence)}
    ${fix}
    ${refs.length ? `<p class="refs">${refs.join(' · ')}</p>` : ''}
    ${attribution}
  </section>`;
}

const CSS = `
@page { size: A4; margin: 16mm 14mm; }
* { box-sizing: border-box; }
body { font-family: -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; color: #16191d; font-size: 10.5pt; line-height: 1.45; margin: 0; }
h1 { font-size: 20pt; margin: 0 0 2mm; } h2 { font-size: 13pt; margin: 8mm 0 3mm; border-bottom: 1px solid #dde1e6; padding-bottom: 1.5mm; }
h3 { font-size: 11.5pt; margin: 1mm 0 2mm; } h4 { font-size: 10pt; margin: 3mm 0 1mm; }
.muted { color: #5b6470; } a { color: #0b5c56; word-break: break-all; }
.header { display: flex; justify-content: space-between; align-items: flex-start; gap: 10mm; }
.brand { color: #0f766e; font-weight: 700; font-size: 10pt; letter-spacing: .02em; }
.score { text-align: center; border: 2px solid #0f766e; border-radius: 4mm; padding: 3mm 6mm; min-width: 34mm; }
.score .grade { font-size: 28pt; font-weight: 800; line-height: 1; } .score .num { font-size: 10pt; }
.grade-A, .grade-B { color: #146c43; } .grade-C { color: #7a4b00; } .grade-D, .grade-F { color: #9b1c1c; }
.counts { display: flex; gap: 3mm; flex-wrap: wrap; margin: 3mm 0; } .counts span { border: 1px solid #dde1e6; border-radius: 2mm; padding: 1mm 3mm; }
.alert { background: #fdecec; color: #9b1c1c; border-radius: 2mm; padding: 3mm 4mm; margin: 4mm 0; font-weight: 600; }
.finding { border: 1px solid #dde1e6; border-left-width: 2mm; border-radius: 2mm; padding: 3mm 4mm; margin: 0 0 4mm; break-inside: avoid; }
.sev-critical { border-left-color: #8b1111; } .sev-high { border-left-color: #c2410c; } .sev-medium { border-left-color: #b45309; } .sev-low { border-left-color: #1d4f91; } .sev-info { border-left-color: #9aa4b0; }
.finding-head { display: flex; gap: 3mm; font-size: 8.5pt; color: #5b6470; text-transform: uppercase; letter-spacing: .03em; }
.finding-head .sev { font-weight: 700; color: #16191d; }
.compromise { color: #9b1c1c; font-weight: 700; }
table.evidence { border-collapse: collapse; width: 100%; font-size: 9pt; margin: 2mm 0; }
table.evidence th { text-align: left; color: #5b6470; font-weight: 600; width: 32mm; vertical-align: top; padding: .8mm 2mm .8mm 0; text-transform: capitalize; }
table.evidence td { padding: .8mm 0; vertical-align: top; } table.evidence ul { margin: 0; padding-left: 4mm; }
code { font-family: Consolas, 'SF Mono', monospace; font-size: 8.5pt; background: #f2f4f6; padding: 0 1mm; border-radius: 1mm; word-break: break-all; }
.guide ol { margin: 1mm 0 2mm; padding-left: 5mm; } .note { font-weight: 600; }
.refs, .attribution { font-size: 8.5pt; color: #5b6470; } table.software { border-collapse: collapse; width: 100%; }
table.software th, table.software td { text-align: left; border-bottom: 1px solid #dde1e6; padding: 1.2mm 2mm 1.2mm 0; font-size: 9.5pt; }
.license { font-size: 8pt; color: #5b6470; margin: 1mm 0 3mm; }
`;

export function renderReportHtml(view: ReportView, options: { generatedAt?: Date } = {}): string {
  const generatedAt = (options.generatedAt ?? new Date()).toISOString().slice(0, 16).replace('T', ' ');
  const revealed = view.findings.filter((f): f is RevealedFinding => !f.locked);
  const counts = (['critical', 'high', 'medium', 'low', 'info'] as const).map((s) => `<span><strong>${view.counts[s]}</strong> ${SEVERITY_LABEL[s]}</span>`).join('');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Security report for ${esc(view.domain)}</title><style>${CSS}</style></head>
<body>
  <div class="header">
    <div>
      <div class="brand">SECURITY HEALTH CHECK</div>
      <h1>${esc(view.domain)}</h1>
      <div class="muted">Scanned ${esc((view.finishedAt ?? view.createdAt).slice(0, 16).replace('T', ' '))} UTC · ${esc(view.requestCount)} requests to ${esc(view.baseUrl ?? view.domain)} · report generated ${esc(generatedAt)} UTC</div>
    </div>
    <div class="score"><div class="grade grade-${esc(view.grade)}">${esc(view.grade)}</div><div class="num">${esc(view.score)} / 100</div></div>
  </div>
  ${view.compromiseSuspected ? '<div class="alert">Some findings suggest this site may already be compromised. Start with those marked below.</div>' : ''}
  <div class="counts">${counts}</div>

  <h2>Findings</h2>
  ${revealed.length === 0 ? '<p>No issues were found.</p>' : revealed.map(findingHtml).join('')}
  ${view.lockedCount > 0 ? `<p class="muted">${esc(view.lockedCount)} further finding(s) are available with a Pro plan.</p>` : ''}

  <h2>Software we found</h2>
  ${
    view.components.length === 0
      ? '<p class="muted">No WordPress software was identified.</p>'
      : `<table class="software"><tr><th>Type</th><th>Name</th><th>Version</th><th>Certainty</th></tr>${view.components
          .map((c) => `<tr><td>${esc(c.type.replace('_', ' '))}</td><td>${esc(c.name ?? c.slug)}</td><td>${esc(c.version ?? 'unknown')}</td><td>${esc(c.versionConfidence ?? '')}</td></tr>`)
          .join('')}</table>`
  }

  <h2>About this report</h2>
  <p>This is an outside-in check of public pages, made only after the site owner proved control of the site. The scanner sends ordinary GET and HEAD requests (at most 2 per second), never logs in, guesses passwords or tries exploits. It cannot see everything an attacker with access to the server could, and a clean result is not a guarantee of security.</p>
  ${view.dataSources
    .map(
      (d) => `<p><strong>${esc(d.name)}</strong> · ${link(d.url)}${d.notice ? `<br><span class="license">${esc(d.notice)}</span>` : ''}</p>${d.licenses
        .map((l) => `<div class="license"><strong>${esc(l.notice)}</strong><br>${esc(l.license)}${l.licenseUrl ? ` ${link(l.licenseUrl)}` : ''}</div>`)
        .join('')}`,
    )
    .join('')}
</body></html>`;
}
