'use strict';
// Informe ejecutivo en PDF de un dominio (SPF, DKIM, DMARC, simulación y remediación).
// Uso: node scripts/generate-dossier.js <dominio> [--selector=<dkim>]...
// Salida: dossier-<dominio>.pdf en el directorio actual. No escribe nada más en disco.
const fs = require('node:fs');
const path = require('node:path');
const E = require('../src/engine.js');

const TZ = 'America/Santo_Domingo';

function usage(msg) {
  if (msg) console.error(`Error: ${msg}\n`);
  console.error('Uso: node scripts/generate-dossier.js <dominio> [--selector=<dkim>]');
  process.exit(msg ? 1 : 0);
}

function parseArgs(argv) {
  const domains = [];
  const selectors = [];
  for (const a of argv) {
    if (a === '-h' || a === '--help') usage();
    else if (a.startsWith('--selector=')) {
      const s = a.slice('--selector='.length).trim();
      if (!s) usage('--selector necesita un valor.');
      selectors.push(s);
    } else if (a.startsWith('-')) usage(`opción desconocida: ${a}`);
    else domains.push(a);
  }
  if (domains.length !== 1) usage('indica exactamente un dominio.');
  return { input: domains[0], selectors };
}

const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const TONE = { critical: '#b91c1c', high: '#c2410c', medium: '#a16207', low: '#15803d' };

function dmarcPolicyLabel(d) {
  if (!d.present) return 'Sin DMARC';
  const p = d.appliedPolicy || d.policy || 'none';
  return `p=${p}${d.testing ? ' (modo prueba)' : ''}${d.partial ? ` (pct=${d.tags.pct})` : ''}`;
}

function statusRows(r) {
  const { spf, dkim, dmarc } = r;
  const spfState = !spf.present ? 'No publicado'
    : spf.status === 'ok' ? `Válido, cierre "${spf.allQualifier ? spf.allQualifier + 'all' : 'sin all'}" (${spf.lookups} consultas DNS)`
      : `Con errores (${spf.status})`;
  const dkimState = dkim.active > 0
    ? `${dkim.active} clave(s) activa(s): ${dkim.found.filter((k) => !k.revoked && k.valid).map((k) => `${k.selector}${k.bits ? ` ~${k.bits} bits` : ''}`).join(', ')}`
    : `No encontrada en ${dkim.selectorsTested} selectores probados`;
  const dmarcState = dmarc.present
    ? `Publicado, ${dmarcPolicyLabel(dmarc)}; subdominios: ${dmarc.subdomainPolicy || 'igual'}; reportes: ${dmarc.reporting ? 'sí' : 'no'}`
    : 'No publicado';
  return [
    ['SPF', spfState, spf.record],
    ['DKIM', dkimState, null],
    ['DMARC', dmarcState, dmarc.record],
  ];
}

function remediationHtml(items) {
  return items.slice(0, 6).map((it, i) => {
    const recs = (it.records || []).map((x) => `<code>${esc(x.type)} ${esc(x.name)}  ${esc(x.value)}</code>`).join('');
    const phases = (it.phases || []).map((p) => `<code>${esc(p.label)}: ${esc(p.type)} ${esc(p.name)}  ${esc(p.value)}</code>`).join('');
    return `<li><strong>${esc(it.title)}</strong> <span class="pri">P${esc(it.priority)}</span><br>${esc(it.why)}${recs}${phases}<div class="note">${esc(it.note)}</div></li>`.replace('<li>', `<li value="${i + 1}">`);
  }).join('');
}

function buildHtml(r) {
  const when = new Date(r.analyzedAt).toLocaleString('es-DO', { timeZone: TZ, dateStyle: 'long', timeStyle: 'short' });
  const color = TONE[r.verdict.level] || '#334155';
  const sim = r.simulation;
  const rows = statusRows(r).map(([k, v, rec]) =>
    `<tr><th>${k}</th><td>${esc(v)}${rec ? `<code>${esc(rec)}</code>` : ''}</td></tr>`).join('');
  const steps = sim.steps.map((s) => `<li><strong>${esc(s.title)}</strong> (${esc(s.result)}): ${esc(s.text)}</li>`).join('');
  return `<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Informe ejecutivo ${esc(r.domain)}</title>
<style>
@page { size: A4; margin: 16mm 15mm; }
body { font: 10pt/1.4 "Segoe UI", Arial, sans-serif; color: #0f172a; margin: 0; }
header { border-bottom: 2px solid #0f172a; padding-bottom: 6px; margin-bottom: 10px; }
h1 { font-size: 17pt; margin: 0; } h2 { font-size: 11.5pt; margin: 14px 0 5px; border-bottom: 1px solid #cbd5e1; padding-bottom: 2px; }
.meta { color: #475569; font-size: 9pt; }
.verdict { display: flex; gap: 14px; align-items: center; border: 2px solid ${color}; border-radius: 6px; padding: 8px 12px; }
.verdict .lvl { font-size: 18pt; font-weight: 700; color: ${color}; }
.verdict .score { margin-left: auto; text-align: center; font-size: 20pt; font-weight: 700; color: ${color}; line-height: 1; }
.verdict .score small { display: block; font-size: 8pt; font-weight: 400; color: #475569; }
table { width: 100%; border-collapse: collapse; } th, td { text-align: left; vertical-align: top; padding: 4px 6px; border-bottom: 1px solid #e2e8f0; }
th { width: 14%; }
code { display: block; font: 8pt Consolas, monospace; background: #f1f5f9; padding: 2px 4px; margin-top: 3px; word-break: break-all; }
ol, ul { margin: 4px 0; padding-left: 20px; } li { margin-bottom: 5px; break-inside: avoid; }
.pri { font-size: 8pt; color: #475569; border: 1px solid #94a3b8; border-radius: 3px; padding: 0 3px; }
.note { color: #475569; font-size: 9pt; }
.outcome { border-left: 4px solid ${TONE[sim.outcome.tone] || '#334155'}; padding: 4px 10px; background: #f8fafc; margin-top: 6px; }
footer { margin-top: 12px; font-size: 8pt; color: #64748b; }
</style></head><body>
<header><h1>Informe de suplantación de correo: ${esc(r.domain)}</h1>
<div class="meta">Análisis: ${esc(when)} (AST) · Comprobación pasiva de DNS público · Suplanta.do</div></header>
<div class="verdict"><div><div class="lvl">Riesgo ${esc(r.verdict.label)}</div><div>${esc(r.verdict.headline)}</div></div>
<div class="score">${esc(r.score.total)}/100 · ${esc(r.score.grade)}<small>puntuación</small></div></div>
<h2>Estado de la autenticación</h2><table>${rows}</table>
<h2>Simulación del vector de suplantación</h2>
<div class="meta">Un atacante envía un correo como <code style="display:inline">${esc(sim.from)}</code> desde la IP de documentación ${esc(sim.attackerIp)}.</div>
<ol>${steps}</ol>
<div class="outcome"><strong>${esc(sim.outcome.label)}.</strong> ${esc(sim.outcome.text)}</div>
<h2>Remediación recomendada para TI</h2>
${r.remediation.length ? `<ol>${remediationHtml(r.remediation)}</ol>` : '<p>No hay acciones pendientes de prioridad.</p>'}
<footer>DMARC no detiene dominios parecidos (typosquatting) ni cuentas comprometidas. Informe generado localmente; no se almacenó ningún dato aparte de este PDF.</footer>
</body></html>`;
}

async function main() {
  const { input, selectors } = parseArgs(process.argv.slice(2));
  const report = await E.analyzeDomain(input, { customDkimSelectors: selectors, fetchMtaStsPolicy: false });
  if (!report.ok) { console.error(`Error: ${report.error}`); process.exit(1); }

  const { chromium } = require('playwright');
  const browser = await chromium.launch({ channel: 'msedge' });
  try {
    const context = await browser.newContext({ javaScriptEnabled: false });
    await context.route('**/*', (route) => (route.request().url().startsWith('about:') || route.request().url().startsWith('data:') ? route.continue() : route.abort()));
    const page = await context.newPage();
    await page.setContent(buildHtml(report), { waitUntil: 'load' });
    const buffer = await page.pdf({ format: 'A4', printBackground: true, preferCSSPageSize: true });
    const out = path.resolve(process.cwd(), `dossier-${report.domain}.pdf`);
    fs.writeFileSync(out, buffer);
    console.log(`PDF generado: ${out}`);
  } finally {
    await browser.close();
  }
}

main().catch((err) => { console.error(`Error: ${err.message}`); process.exit(1); });
