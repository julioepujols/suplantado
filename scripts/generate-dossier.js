'use strict';
// Informe en PDF de un dominio: resumen para la dirección (página 1) y detalle para TI (página 2).
// Uso: node scripts/generate-dossier.js <dominio> [--selector=<dkim>]...
// Salida: dossier-<dominio>.pdf en el directorio actual. No escribe nada más en disco.
const fs = require('node:fs');
const path = require('node:path');
const E = require('../src/engine.js');

const TZ = 'America/Santo_Domingo';
const ROOT = path.join(__dirname, '..');
const SITE = JSON.parse(fs.readFileSync(path.join(ROOT, 'site.config.json'), 'utf8'));

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

const font = (file) => fs.readFileSync(path.join(ROOT, 'assets', 'fonts', file)).toString('base64');

// ---- Textos del PDF en trato formal ("usted"). El motor (src/engine.js) usa "tú" porque la web
// habla así; aquí no se reutilizan sus textos de veredicto ni de simulación.
const VERDICT_TEXT = {
  'Cualquiera puede enviar correos como tu dominio y pasarán las verificaciones.': {
    headline: 'Cualquiera puede enviar correos como su dominio y pasarán las verificaciones.',
    detail: 'Su SPF autoriza a todo Internet. Un correo falso no solo llegaría: aparecería como legítimo.',
  },
  'Sí: cualquiera puede enviar correos haciéndose pasar por tu dominio.': {
    headline: 'Sí: cualquiera puede enviar correos haciéndose pasar por su dominio.',
    detail: 'No hay DMARC. Ningún receptor tiene la instrucción de rechazar correos falsos con su nombre; llegan o no según los filtros de cada proveedor.',
  },
  'Sí: tu dominio puede ser suplantado.': {
    headline: 'Sí: su dominio puede ser suplantado.',
    detail: 'Tiene DMARC, pero en modo de solo observación ("none" o modo prueba). Los correos falsos no se rechazan.',
  },
  'Parcialmente protegido: los correos falsos irían a spam, no a la basura.': {
    headline: 'Parcialmente protegido: los correos falsos irían a spam, no a la basura.',
    detail: 'Su DMARC está en "quarantine" o aplicado a una parte del correo. Un empleado que revise su carpeta de spam todavía podría caer.',
  },
  'Tu dominio principal está protegido, pero tus subdominios no.': {
    headline: 'Su dominio principal está protegido, pero sus subdominios no.',
    detail: 'Un atacante puede usar direcciones como facturacion.su-dominio para engañar a clientes y proveedores.',
  },
  'No: los correos falsos con tu dominio exacto serían rechazados.': {
    headline: 'No: los correos falsos con su dominio exacto serían rechazados.',
    detail: 'Su DMARC está en "reject". Aún existen ataques con dominios parecidos (typosquatting) o cuentas robadas, que DMARC no detiene.',
  },
};

const OUTCOME_TEXT = {
  'delivered-pass': { label: 'Entregado como legítimo', text: 'El correo falso llega a la bandeja de entrada y pasa todas las verificaciones.' },
  delivered: { label: 'Puede llegar a la bandeja', text: 'Nada lo bloquea por política. Llega o no según los filtros antispam del receptor.' },
  quarantine: { label: 'Enviado a spam', text: 'El correo falso termina en la carpeta de spam. Todavía puede ser abierto.' },
  rejected: { label: 'Rechazado', text: 'El servidor receptor rechaza el correo falso. Nunca llega a la víctima.' },
};

const SPF_STEP_TEXT = {
  pass: 'El SPF autoriza al servidor del atacante. El receptor lo considera legítimo.',
  fail: 'El servidor del atacante no está en el SPF: resultado "fail".',
  softfail: 'El servidor del atacante no está en el SPF: resultado "softfail" (sospechoso, pero no definitivo).',
  neutral: 'El SPF no se pronuncia: resultado "neutral".',
  none: 'No hay SPF que consultar: resultado "none".',
  permerror: 'El SPF tiene errores y el receptor lo descarta: resultado "permerror".',
  temperror: 'No se pudo consultar el SPF: resultado "temperror".',
};
const DKIM_STEP_TEXT = 'El atacante no tiene su clave privada: el correo llega sin una firma DKIM válida de su dominio.';

function stepText(step, r) {
  if (step.id === 'spf') return SPF_STEP_TEXT[step.result] || 'No se pudo determinar el resultado de SPF.';
  if (step.id === 'dkim') return DKIM_STEP_TEXT;
  const d = r.dmarc;
  const disposition = r.simulation.disposition;
  if (!d.present) return 'No existe política DMARC. El receptor decide solo con sus filtros antispam.';
  if (disposition === 'delivered-pass') return 'SPF "pass" alineado con el remitente visible: DMARC da el correo por auténtico.';
  const policy = { delivered: 'none', quarantine: 'quarantine', rejected: 'reject' }[disposition] || 'none';
  return `DMARC falla (ni SPF ni DKIM alineados). Política aplicada: "${policy}"${d.partial ? ` (peor caso: con pct=${d.tags.pct}, el resto del correo recibe una política más suave)` : ''}${d.testing ? ' (rebajada por modo prueba)' : ''}.`;
}

// Hallazgos y remediación vienen del motor en "tú". Se convierten solo con estas frases
// exactas (sin patrones amplios); el resto del texto pasa intacto.
const USTED = [
  ['SPF le dice al mundo qué servidores pueden enviar correo con tu dominio.', 'SPF le dice al mundo qué servidores pueden enviar correo con su dominio.'],
  ['Agrega todos los servicios que envían correo en tu nombre', 'Agregue todos los servicios que envían correo en su nombre'],
  ['Cuando DMARC llegue a "reject", cambia "~all" por "-all".', 'Cuando DMARC llegue a "reject", cambie "~all" por "-all".'],
  ['Elimina proveedores que ya no usas, reemplaza ', 'Elimine proveedores que ya no usa, reemplace '],
  [' o mueve envíos masivos', ' o mueva envíos masivos'],
  ['Confirma antes que ningún sistema', 'Confirme antes que ningún sistema'],
  ['Recibe reportes de 2 a 4 semanas e identifica todos los servicios legítimos que envían con tu dominio.', 'Reciba reportes de 2 a 4 semanas e identifique todos los servicios legítimos que envían con su dominio.'],
  ['Revisa los reportes cada semana.', 'Revise los reportes cada semana.'],
  ['Los correos falsos con tu dominio son rechazados.', 'Los correos falsos con su dominio son rechazados.'],
  ['rechacen correos falsos con tu dominio.', 'rechacen correos falsos con su dominio.'],
  ['Conservamos tu dirección actual de reportes DMARC. Avanza de fase solo cuando', 'Conservamos su dirección actual de reportes DMARC. Avance de fase solo cuando'],
  ['todo tu correo legítimo', 'todo su correo legítimo'],
  ['Crea el buzón ', 'Cree el buzón '],
  ['(o usa un servicio que procese', '(o use un servicio que procese'],
  ['crea los registros CNAME selector1 y selector2 que te indica el portal y activa la firma.', 'cree los registros CNAME selector1 y selector2 que le indica el portal y active la firma.'],
  ['genera una clave de 2048 bits, publica el TXT google._domainkey y pulsa ', 'genere una clave de 2048 bits, publique el TXT google._domainkey y pulse '],
  ['agrega un selector, publica el TXT y verifica.', 'agregue un selector, publique el TXT y verifique.'],
  ['Activa la firma DKIM en tu proveedor de correo (2048 bits) y publica el registro que te entregue.', 'Active la firma DKIM en su proveedor de correo (2048 bits) y publique el registro que le entregue.'],
  ['DKIM firma criptográficamente tus correos: prueba que salieron de ti y que nadie', 'DKIM firma criptográficamente sus correos: prueba que salieron de usted y que nadie'],
  ['Además publica la política en ', 'Además publique la política en '],
  ['Solo las autoridades que autorices podrán emitir certificados HTTPS para tu dominio.', 'Solo las autoridades que usted autorice podrán emitir certificados HTTPS para su dominio.'],
  ['Verifica qué autoridad usa hoy tu sitio antes de publicarlo.', 'Verifique qué autoridad usa hoy su sitio antes de publicarlo.'],
  ['<tu-proveedor-de-correo>', '<su-proveedor-de-correo>'],
  ['<tu-autoridad-certificadora>', '<su-autoridad-certificadora>'],
];
const usted = (text) => USTED.reduce((t, [from, to]) => t.split(from).join(to), String(text ?? ''));

const RISK = {
  critical: { ink: '#c4283a', bg: '#fbe9eb' },
  high: { ink: '#a8470c', bg: '#fcefe6' },
  medium: { ink: '#7d5700', bg: '#fbf3df' },
  low: { ink: '#11683a', bg: '#e6f4ec' },
};
const SEVERITY = {
  critical: { label: 'Crítico', order: 0, tone: 'critical' },
  high: { label: 'Alto', order: 1, tone: 'high' },
  warn: { label: 'Medio', order: 2, tone: 'medium' },
  info: { label: 'Info', order: 3, tone: 'low' },
};
const STEP_RESULT = { pass: 'Pasa', fail: 'Falla', none: 'Sin firma', softfail: 'Falla leve', neutral: 'Neutral', permerror: 'Error', temperror: 'Error' };

function brief(r) {
  const d = r.domain;
  const main = r.simulation.disposition;
  const subOk = r.subdomainSimulation.disposition === 'rejected';
  if (main === 'rejected') {
    return [
      ['Qué significa', `Los correos falsos que usan exactamente ${d} son rechazados antes de llegar.`],
      ['Riesgo que queda', 'Dominios parecidos (con un guion o una letra cambiada) y cuentas de correo robadas. DMARC no detiene esos casos.'],
      ['Qué hacer', subOk
        ? 'Revisar los reportes DMARC con regularidad y confirmar por teléfono todo cambio de cuenta bancaria de un proveedor.'
        : 'Proteger también los subdominios inventados (sp=reject y np=reject) y confirmar por teléfono todo cambio de cuenta bancaria.'],
    ];
  }
  if (main === 'quarantine') {
    return [
      ['Qué significa', `Los correos falsos con el nombre de ${d} terminan en spam. La protección es parcial.`],
      ['Riesgo para el negocio', 'Un empleado o un cliente todavía puede abrir el correo falso desde la carpeta de spam y seguir sus instrucciones.'],
      ['Qué hacer', 'Subir DMARC a rechazo cuando los reportes confirmen que todo el correo legítimo pasa. Suele tomar de 2 a 4 semanas.'],
    ];
  }
  return [
    ['Qué significa', main === 'delivered-pass'
      ? `Cualquiera puede enviar correos que aparentan salir de ${d}, y pasan como legítimos.`
      : `Cualquiera puede enviar correos que aparentan salir de ${d}, y ninguna regla del dominio indica rechazarlos.`],
    ['Riesgo para el negocio', 'Fraudes de pago a clientes y proveedores ("cambiamos de cuenta bancaria"), robo de contraseñas y daño a la reputación de la marca.'],
    ['Qué hacer', 'Que TI o el proveedor de correo aplique el plan de la página 2. Se hace de forma gradual en unas 4 a 8 semanas (estimado) y normalmente no requiere comprar productos.'],
  ];
}

function strengths(r) {
  const { spf, dkim, dmarc, extras } = r;
  const out = [];
  if (spf.present && spf.status === 'ok' && spf.allQualifier === '-') out.push('SPF cerrado con "-all": solo los servidores listados pueden enviar.');
  else if (spf.present && spf.status === 'ok' && spf.allQualifier === '~') out.push('SPF publicado y válido.');
  if (dkim.active > 0) out.push(`El correo se firma con DKIM (${dkim.active} ${dkim.active === 1 ? 'clave activa' : 'claves activas'}).`);
  if (dmarc.present && dmarc.appliedPolicy === 'reject' && !dmarc.partial) out.push('DMARC en rechazo: los correos falsos con el dominio exacto se descartan.');
  else if (dmarc.present) out.push('DMARC publicado: el primer paso ya está dado.');
  if (dmarc.reporting) out.push('Recibe reportes DMARC de quién envía correo con el dominio.');
  if (extras.mtaSts.present) out.push('Publica MTA-STS para exigir cifrado del correo entrante.');
  if (extras.dnssec.validated) out.push('DNS firmado con DNSSEC.');
  if (extras.caa.present) out.push('Restringe con CAA quién emite sus certificados.');
  return out;
}

function ring(score, color) {
  const c = 2 * Math.PI * 34;
  const off = c * (1 - Math.max(0, Math.min(100, score.total)) / 100);
  return `<svg class="ring" viewBox="0 0 88 88" aria-hidden="true">
<circle cx="44" cy="44" r="34" fill="none" stroke="#d3dbe8" stroke-width="8"/>
<circle cx="44" cy="44" r="34" fill="none" stroke="${color}" stroke-width="8" stroke-linecap="round" stroke-dasharray="${c.toFixed(2)}" stroke-dashoffset="${off.toFixed(2)}" transform="rotate(-90 44 44)"/>
<text x="44" y="52" text-anchor="middle" font-size="26" font-weight="700" fill="#10203a">${esc(score.grade)}</text></svg>`;
}

function flow(sim, r) {
  const steps = sim.steps.map((s) => {
    const tone = s.ok ? 'low' : s.bad ? 'critical' : 'medium';
    return `<div class="step"><div class="step-name">${esc(s.title)}</div><div class="chip ${tone}">${esc(STEP_RESULT[s.result] || s.result)}</div><p>${esc(stepText(s, r))}</p></div>`;
  }).join('<div class="arrow">→</div>');
  const tone = RISK[sim.outcome.tone] ? sim.outcome.tone : 'high';
  const out = OUTCOME_TEXT[sim.disposition] || { label: sim.outcome.label, text: usted(sim.outcome.text) };
  return `<div class="flow">${steps}</div>
<div class="outcome ${tone}"><strong>Resultado: ${esc(out.label)}.</strong> ${esc(out.text)}</div>`;
}

function findings(r) {
  const items = [...r.issues].sort((a, b) => (SEVERITY[a.severity]?.order ?? 9) - (SEVERITY[b.severity]?.order ?? 9));
  if (!items.length) return '<p class="muted">No se encontraron hallazgos.</p>';
  return `<table class="findings">${items.map((i) => {
    const s = SEVERITY[i.severity] || SEVERITY.info;
    return `<tr><td class="sev"><span class="chip ${s.tone}">${esc(s.label)}</span></td><td>${esc(usted(i.message))}</td></tr>`;
  }).join('')}</table>`;
}

function records(r) {
  const { spf, dkim, dmarc } = r;
  const keys = dkim.found.filter((k) => !k.revoked && k.valid)
    .map((k) => `${k.selector}${k.bits ? ` (~${k.bits} bits)` : ''}`).join(', ');
  const rows = [
    ['SPF', spf.record || 'No publicado'],
    ['DKIM', keys || `Ninguna clave encontrada en ${dkim.selectorsTested} selectores comunes`],
    ['DMARC', dmarc.record || 'No publicado'],
  ];
  return `<table class="records">${rows.map(([k, v]) => `<tr><th>${k}</th><td><code>${esc(v)}</code></td></tr>`).join('')}</table>`;
}

function remediation(items) {
  if (!items.length) return '<p class="muted">No hay acciones pendientes.</p>';
  return `<ol class="plan">${items.slice(0, 6).map((it) => {
    const lines = [...(it.phases || []).map((p) => [p.label, `${p.type} ${p.name}`, usted(p.value)]), ...(it.records || []).map((x) => ['', `${x.type} ${x.name}`, usted(x.value)])];
    const recs = lines.map(([label, where, value]) => `<div class="rec">${label ? `<span class="rec-label">${esc(label)}</span>` : ''}<span class="rec-where">${esc(where)}</span><code>${esc(value)}</code></div>`).join('');
    return `<li><div class="plan-head"><strong>${esc(usted(it.title))}</strong><span class="pri">P${esc(it.priority)}</span></div><p>${esc(usted(it.why))}</p>${recs}${it.note ? `<p class="muted">${esc(usted(it.note))}</p>` : ''}</li>`;
  }).join('')}</ol>`;
}

function buildHtml(r) {
  const when = new Date(r.analyzedAt).toLocaleString('es-DO', { timeZone: TZ, dateStyle: 'long', timeStyle: 'short' });
  const risk = RISK[r.verdict.level] || RISK.high;
  const vt = VERDICT_TEXT[r.verdict.headline] || { headline: usted(r.verdict.headline), detail: usted(r.verdict.detail) };
  const good = strengths(r);
  const author = SITE.author || {};
  const contact = SITE.contact || {};
  const site = (SITE.siteUrl || '').replace(/^https?:\/\//, '').replace(/\/$/, '');
  return `<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; font-src data:; img-src data:">
<title>Informe de suplantación de correo: ${esc(r.domain)}</title>
<style>
@font-face { font-family: Archivo; src: url(data:font/woff2;base64,${font('archivo.woff2')}) format('woff2'); font-weight: 100 900; }
@font-face { font-family: Plex; src: url(data:font/woff2;base64,${font('plex400.woff2')}) format('woff2'); font-weight: 400; }
@page { size: A4; margin: 14mm 15mm 16mm; }
* { box-sizing: border-box; }
body { margin: 0; font: 9.6pt/1.45 Archivo, Arial, sans-serif; color: #10203a; }
h2 { font-size: 11.5pt; margin: 0 0 6px; letter-spacing: .01em; }
p { margin: 0; }
.muted { color: #5d6982; font-size: 8.6pt; }
code { font: 7.8pt/1.45 Plex, Consolas, monospace; overflow-wrap: anywhere; }
section { margin-top: 14px; }
.brand { display: flex; justify-content: space-between; align-items: center; color: #44526d; font-size: 8.4pt; border-bottom: 1px solid #d3dbe8; padding-bottom: 6px; }
.brand b { color: #10203a; font-size: 10pt; letter-spacing: .02em; }
.brand b span { color: #c01f35; }
.title { margin-top: 14px; }
.title .kicker { font-size: 9pt; color: #1c4e9e; font-weight: 600; text-transform: uppercase; letter-spacing: .08em; }
.title h1 { font-size: 24pt; line-height: 1.1; margin: 2px 0 2px; overflow-wrap: anywhere; }
.verdict { display: flex; align-items: center; gap: 16px; margin-top: 12px; padding: 12px 16px; border-radius: 10px; background: ${risk.bg}; border-left: 5px solid ${risk.ink}; }
.verdict .lvl { color: ${risk.ink}; font-weight: 700; font-size: 9pt; text-transform: uppercase; letter-spacing: .08em; }
.verdict .head { font-size: 13.5pt; font-weight: 700; line-height: 1.25; margin: 2px 0 4px; }
.verdict .body { flex: 1; }
.score { text-align: center; }
.ring { width: 78px; height: 78px; display: block; }
.score small { display: block; color: #44526d; font-size: 8pt; margin-top: 2px; }
dl.brief { display: grid; grid-template-columns: 30% 70%; margin: 0; border-top: 1px solid #d3dbe8; }
dl.brief dt, dl.brief dd { margin: 0; padding: 7px 0; border-bottom: 1px solid #d3dbe8; }
dl.brief dt { font-weight: 700; padding-right: 12px; }
.flow { display: flex; align-items: stretch; gap: 6px; }
.step { flex: 1; border: 1px solid #d3dbe8; border-radius: 8px; padding: 8px 10px; }
.step-name { font-weight: 700; font-size: 9pt; }
.step p { font-size: 8.2pt; color: #44526d; margin-top: 4px; }
.arrow { align-self: center; color: #7d889d; font-size: 14pt; }
.chip { display: inline-block; font-size: 7.6pt; font-weight: 700; padding: 1px 7px; border-radius: 999px; margin-top: 3px; }
.chip.critical { color: #c4283a; background: #fbe9eb; } .chip.high { color: #a8470c; background: #fcefe6; }
.chip.medium { color: #7d5700; background: #fbf3df; } .chip.low { color: #11683a; background: #e6f4ec; }
.outcome { margin-top: 8px; padding: 8px 12px; border-radius: 8px; }
.outcome.critical { background: #fbe9eb; } .outcome.high { background: #fcefe6; } .outcome.medium { background: #fbf3df; } .outcome.low { background: #e6f4ec; }
.note-sim { margin-top: 5px; }
ul.good { margin: 0; padding-left: 0; list-style: none; columns: 2; column-gap: 18px; }
ul.good li { padding-left: 16px; position: relative; margin-bottom: 4px; break-inside: avoid; }
ul.good li::before { content: "✓"; position: absolute; left: 0; color: #11683a; font-weight: 700; }
.tech { break-before: page; }
table { width: 100%; border-collapse: collapse; }
table th, table td { text-align: left; vertical-align: top; padding: 5px 6px; border-bottom: 1px solid #e3e8f1; }
table.records th { width: 13%; font-size: 9pt; }
td.sev { width: 13%; }
ol.plan { margin: 0; padding-left: 18px; }
ol.plan li { margin-bottom: 9px; break-inside: avoid; }
.plan-head { display: flex; gap: 8px; align-items: baseline; }
.pri { font-size: 7.4pt; color: #44526d; border: 1px solid #b6c1d3; border-radius: 4px; padding: 0 4px; }
.rec { margin-top: 4px; padding: 5px 8px; background: #f5f7fb; border-radius: 6px; }
.rec-label { font-weight: 700; font-size: 8pt; margin-right: 6px; }
.rec-where { font: 7.8pt Plex, Consolas, monospace; color: #1c4e9e; display: block; }
.about { margin-top: 14px; padding: 10px 12px; border: 1px solid #d3dbe8; border-radius: 8px; font-size: 8.4pt; color: #44526d; break-inside: avoid; }
.about strong { color: #10203a; }
</style></head><body>
<div class="brand"><b>Suplanta<span>.do</span></b><span>Informe confidencial para ${esc(r.domain)}</span></div>
<div class="title"><div class="kicker">Informe de suplantación de correo</div><h1>${esc(r.domain)}</h1>
<div class="muted">Análisis del ${esc(when)} (hora de República Dominicana) · Lectura pasiva de registros DNS públicos</div></div>
<div class="verdict"><div class="body"><div class="lvl">Riesgo ${esc(r.verdict.label)}</div><div class="head">${esc(vt.headline)}</div><p>${esc(vt.detail)}</p></div>
<div class="score">${ring(r.score, risk.ink)}<small>${esc(r.score.total)} de 100 puntos</small></div></div>
<section><h2>Resumen para la dirección</h2><dl class="brief">${brief(r).map(([t, v]) => `<dt>${esc(t)}</dt><dd>${esc(v)}</dd>`).join('')}</dl></section>
<section><h2>Qué pasaría con un correo falso a su nombre</h2>
<p class="muted" style="margin-bottom:6px">Un estafador envía un correo como <b>${esc(r.simulation.from)}</b> desde un servidor que no es suyo.</p>
${flow(r.simulation, r)}
<p class="muted note-sim">Simulación calculada a partir de los registros públicos del dominio. No se envió ningún correo.</p></section>
<section><h2>Lo que ya está bien</h2>${good.length ? `<ul class="good">${good.map((g) => `<li>${esc(g)}</li>`).join('')}</ul>` : '<p class="muted">Ninguno de los controles principales de autenticación de correo está publicado todavía.</p>'}</section>
<div class="tech">
<section style="margin-top:0"><h2>Detalle técnico para TI</h2>${records(r)}</section>
<section><h2>Hallazgos</h2>${findings(r)}</section>
<section><h2>Plan de corrección</h2>${remediation(r.remediation)}</section>
<div class="about"><strong>Sobre este informe.</strong> Elaborado por ${esc(author.name)}, ${esc(author.title)}, con la herramienta Suplanta.do. Solo se leyeron registros que el dominio publica en el DNS para que cualquier servidor de correo los consulte: no se accedió a ningún sistema, no se enviaron correos y no se probaron contraseñas. Puede comprobar el resultado usted mismo en <strong>${esc(site)}</strong>. Suplanta.do no está afiliado a ninguna entidad pública ni privada. DMARC no detiene dominios parecidos (typosquatting) ni cuentas comprometidas.${contact.email ? ` Contacto: ${esc(contact.email)}.` : ''}</div>
</div>
</body></html>`;
}

function footer(domain) {
  return `<div style="font: 7pt Arial, sans-serif; color: #7d889d; width: 100%; padding: 0 15mm; display: flex; justify-content: space-between;">
<span>Suplanta.do · ${esc(domain)}</span><span>Página <span class="pageNumber"></span> de <span class="totalPages"></span></span></div>`;
}

async function main() {
  const { input, selectors } = parseArgs(process.argv.slice(2));
  const report = await E.analyzeDomain(input, { customDkimSelectors: selectors, fetchMtaStsPolicy: false });
  if (!report.ok) { console.error(`Error: ${report.error}`); process.exit(1); }

  const { chromium } = require('playwright');
  const channel = process.env.DOSSIER_BROWSER_CHANNEL || (process.platform === 'win32' ? 'msedge' : undefined);
  const browser = await chromium.launch(channel ? { channel } : {});
  try {
    const context = await browser.newContext({ javaScriptEnabled: false });
    await context.route('**/*', (route) => (/^(about|data):/.test(route.request().url()) ? route.continue() : route.abort()));
    const page = await context.newPage();
    await page.setContent(buildHtml(report), { waitUntil: 'load' });
    const buffer = await page.pdf({
      format: 'A4', printBackground: true, preferCSSPageSize: true,
      displayHeaderFooter: true, headerTemplate: '<span></span>', footerTemplate: footer(report.domain),
    });
    const out = path.resolve(process.cwd(), `dossier-${report.domain}.pdf`);
    fs.writeFileSync(out, buffer);
    console.log(`PDF generado: ${out}`);
  } finally {
    await browser.close();
  }
}

main().catch((err) => { console.error(`Error: ${err.message}`); process.exit(1); });
