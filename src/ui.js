(function () {
  'use strict';
  const E = window.SuplantaEngine;
  const $ = (id) => document.getElementById(id);
  const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const fmt = (n) => Number(n).toLocaleString('es-DO', { maximumFractionDigits: 1 });

  // Construye nodos sin innerHTML: todo texto llega por textContent.
  function h(tag, props, ...children) {
    const el = document.createElement(tag);
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (v === null || v === undefined || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k === 'dataset') Object.assign(el.dataset, v);
        else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? '' : String(v));
      }
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  const SEVERITY = {
    critical: { label: 'Crítico', tone: 'critical', order: 0 },
    high: { label: 'Alto', tone: 'high', order: 1 },
    warn: { label: 'Advertencia', tone: 'warn', order: 2 },
    info: { label: 'Informativo', tone: 'info', order: 3 },
  };
  const RISK_LABEL = { critical: 'Riesgo crítico', high: 'Riesgo alto', medium: 'Riesgo medio', low: 'Riesgo bajo' };
  const STAMP = {
    'delivered-pass': { text: 'Entregado', sub: 'pasa como legítimo', tone: 'critical' },
    delivered: { text: 'Puede llegar', sub: 'nada lo bloquea', tone: 'high' },
    quarantine: { text: 'A spam', sub: 'cuarentena DMARC', tone: 'medium' },
    rejected: { text: 'Rechazado', sub: 'bloqueado por DMARC', tone: 'low' },
  };

  const samples = new Map(DATA.samples.map((s) => [s.report.domain, s]));
  let current = null;
  let simMode = 'main';

  // ------------------------------------------------------------ sobre
  const envFrom = $('env-from');
  const mark = $('mark');
  function setFrom(domain) {
    envFrom.textContent = `gerencia@${domain || 'tuempresa.com.do'}`;
  }
  function setStamp(state) {
    mark.dataset.tone = state ? state.tone : 'ghost';
    $('mark-text').textContent = state ? state.text : 'Sin verificar';
    $('mark-sub').textContent = state ? state.sub : 'escribe tu dominio';
    mark.classList.remove('thunk');
    if (state && !reduceMotion) { void mark.offsetWidth; mark.classList.add('thunk'); }
  }
  $('domain-input').addEventListener('input', (ev) => {
    const n = E.normalizeDomain(ev.target.value);
    setFrom(n.ok ? n.domain : '');
    if (current) { current = null; setStamp(null); $('env-caption').textContent = 'Pulsa Comprobar para ver si este mensaje llegaría.'; }
  });

  // ------------------------------------------------------------ ejemplos
  const examples = $('examples');
  for (const s of DATA.samples) {
    examples.append(h('button', { type: 'button', class: 'chip', onclick: () => { $('domain-input').value = s.report.domain; run(s.report.domain); } },
      s.report.domain, s.kind === 'ficticio' ? h('small', { text: ' (ficticio)' }) : null));
  }

  // ------------------------------------------------------------ análisis
  const statusEl = $('status');
  function status(msg, isError) {
    statusEl.textContent = msg || '';
    statusEl.classList.toggle('error', Boolean(isError));
  }

  async function run(input) {
    const norm = E.normalizeDomain(input);
    if (!norm.ok) { status(norm.error, true); $('domain-input').focus(); return; }
    setFrom(norm.domain);
    const sample = samples.get(norm.domain);
    if (sample && sample.kind === 'ficticio') { show(sample.report, 'ficticio'); return; }

    const btn = $('check-btn');
    btn.disabled = true;
    status(`Consultando los registros DNS públicos de ${norm.domain}…`);
    let report;
    try {
      report = await E.analyzeDomain(norm.domain, { concurrency: 8, timeoutMs: 6000 });
    } catch (_) {
      report = { ok: false, error: 'network' };
    } finally {
      btn.disabled = false;
    }
    if (report.ok) { status(''); show(report, 'live'); return; }

    const offline = report.error === 'network' || /No pudimos contactar/.test(report.error);
    if (offline && sample) { status(''); show(sample.report, 'saved'); return; }
    if (offline) {
      status('Esta página no puede consultar DNS en este momento. Si la estás viendo dentro de Claude, el análisis en vivo está bloqueado por seguridad: ábrela en su sitio publicado. Mientras tanto, prueba uno de los ejemplos.', true);
      return;
    }
    status(report.error, true);
  }

  $('check-form').addEventListener('submit', (ev) => { ev.preventDefault(); run($('domain-input').value); });
  $('check-another').addEventListener('click', () => {
    const input = $('domain-input');
    input.value = '';
    setFrom('');
    current = null;
    setStamp(null);
    $('resultado').hidden = true;
    $('comprobar').scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth' });
    input.focus({ preventScroll: true });
  });

  // ------------------------------------------------------------ informe
  function show(report, source) {
    current = report;
    simMode = 'main';
    const stamp = STAMP[report.simulation.disposition];
    setStamp(stamp);
    $('env-caption').textContent = `${report.simulation.outcome.text} Resultado para ${report.domain}.`;

    $('r-domain').textContent = report.domain;
    const risk = $('r-risk');
    risk.dataset.tone = report.verdict.level;
    risk.textContent = RISK_LABEL[report.verdict.level];
    const when = new Date(report.analyzedAt);
    const dateText = when.toLocaleDateString('es-DO', { day: 'numeric', month: 'long', year: 'numeric' });
    $('r-source').textContent = source === 'live' ? 'Análisis en vivo' : source === 'ficticio' ? 'Ejemplo ficticio' : `Análisis guardado del ${dateText}`;
    $('r-headline').textContent = report.verdict.headline;
    $('r-detail').textContent = report.verdict.detail;
    $('r-grade').textContent = report.score.grade;
    $('r-score').textContent = `${report.score.total} de 100`;
    $('r-parts').replaceChildren(...report.score.parts.map((p) => h('li', null,
      h('span', { text: p.label }), h('span', { class: 'pts', text: `${p.points}/${p.max}` }),
      h('span', { class: 'meter', 'aria-hidden': 'true' }, h('span', { style: `width:${Math.round((p.points / p.max) * 100)}%` })))));

    renderRoute();
    renderFindings(report);
    renderPlan(report);
    renderTech(report);

    const section = $('resultado');
    section.hidden = false;
    section.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
    $('r-headline').focus({ preventScroll: true });
  }

  function renderRoute() {
    const sim = simMode === 'main' ? current.simulation : current.subdomainSimulation;
    $('tab-main').setAttribute('aria-selected', String(simMode === 'main'));
    $('tab-sub').setAttribute('aria-selected', String(simMode === 'sub'));
    $('route-panel').setAttribute('aria-labelledby', simMode === 'main' ? 'tab-main' : 'tab-sub');
    const origin = sim.spfAuthorizesAttacker
      ? [' enviado desde cualquier servidor que el atacante elija: tu SPF lo autoriza.']
      : [' enviado desde un servidor del atacante (', h('code', { text: sim.attackerIp }), ', dirección reservada para documentación).'];
    $('route-from').replaceChildren('Correo falso de ', h('code', { text: sim.from }), ...origin);
    const items = sim.steps.map((s) => h('li', { 'data-state': s.bad ? 'bad' : s.ok ? 'ok' : 'warn' },
      h('h4', { text: s.title }), h('span', { class: 'code', text: `resultado: ${s.result}` }), h('p', { text: s.text })));
    const tone = sim.outcome.tone;
    items.push(h('li', { class: 'final', 'data-tone': tone, 'data-state': tone === 'low' ? 'ok' : tone === 'medium' ? 'warn' : 'bad' },
      h('h4', { text: sim.outcome.label }), h('span', { class: 'code', text: 'destino' }), h('p', { text: sim.outcome.text })));
    $('route').replaceChildren(...items);
  }
  $('tab-main').addEventListener('click', () => { simMode = 'main'; renderRoute(); });
  $('tab-sub').addEventListener('click', () => { simMode = 'sub'; renderRoute(); });
  $('tab-main').addEventListener('keydown', (e) => { if (e.key === 'ArrowRight') { $('tab-sub').focus(); $('tab-sub').click(); } });
  $('tab-sub').addEventListener('keydown', (e) => { if (e.key === 'ArrowLeft') { $('tab-main').focus(); $('tab-main').click(); } });

  function sortedIssues(report) {
    return report.issues.slice().sort((a, b) => SEVERITY[a.severity].order - SEVERITY[b.severity].order);
  }

  function renderFindings(report) {
    const list = sortedIssues(report);
    if (!list.length) {
      $('r-findings').replaceChildren(h('li', null, h('span', { class: 'pill', 'data-tone': 'low', text: 'Sin hallazgos' }), h('p', { text: 'No encontramos problemas en los registros analizados.' })));
      return;
    }
    $('r-findings').replaceChildren(...list.map((i) => h('li', null,
      h('span', null, h('span', { class: 'pill', 'data-tone': SEVERITY[i.severity].tone, text: SEVERITY[i.severity].label })),
      h('p', { text: i.message }))));
  }

  async function copyText(text, button) {
    const original = button.textContent;
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = 'Copiado';
    } catch (_) {
      const area = h('textarea', { class: 'sr-only', 'aria-hidden': 'true' });
      area.value = text;
      document.body.append(area);
      area.select();
      let ok = false;
      try { ok = document.execCommand('copy'); } catch (__) { ok = false; }
      area.remove();
      button.textContent = ok ? 'Copiado' : 'Selecciona y copia';
    }
    setTimeout(() => { button.textContent = original; }, 1800);
  }

  function recordRow(r) {
    const btn = h('button', { type: 'button', class: 'copy', text: 'Copiar' });
    btn.addEventListener('click', () => copyText(r.value, btn));
    return h('div', { class: 'record' },
      h('span', { class: 'rtype', text: r.type }),
      h('div', null, h('span', { class: 'rname', text: r.name }), h('code', { class: 'rvalue', text: r.value })),
      btn);
  }

  function renderPlan(report) {
    if (!report.remediation.length) {
      $('r-plan').replaceChildren(h('p', { class: 'empty-note', text: 'Tu configuración de autenticación de correo ya cumple lo esencial. Mantén los reportes DMARC bajo revisión.' }));
      return;
    }
    $('r-plan').replaceChildren(...report.remediation.map((item) => {
      const box = h('div', { class: 'plan-item' }, h('h4', { text: item.title }), h('p', { class: 'why', text: item.why }));
      for (const r of item.records) box.append(recordRow(r));
      if (item.phases && item.phases.length) {
        box.append(h('ol', { class: 'phases' }, item.phases.map((ph) => h('li', null, h('div', null,
          h('h5', { text: ph.label }), recordRow(ph), h('p', { text: ph.note }))))));
      }
      if (item.note) box.append(h('p', { class: 'note', text: item.note }));
      return box;
    }));
  }

  function statusPill(ok, okText, badText, tone) {
    return h('span', { class: 'pill', 'data-tone': ok ? 'low' : (tone || 'warn'), text: ok ? okText : badText });
  }

  function spfTree(node) {
    const li = h('li', null, h('span', { class: 'tdom', text: node.domain }),
      h('span', { class: 'trec', text: node.record || ({ none: 'sin SPF', nxdomain: 'no existe', loop: 'inclusión circular', multiple: 'varios registros', temperror: 'error de consulta' }[node.error] || '') }));
    if (node.children && node.children.length) li.append(h('ul', null, node.children.map(spfTree)));
    return li;
  }

  function renderTech(r) {
    const blocks = [];
    const spf = r.spf;
    const spfBody = h('div', { class: 'body' });
    if (spf.record) spfBody.append(h('pre', { class: 'raw', text: spf.record }));
    spfBody.append(h('p', { class: 'small', text: `Consultas DNS que exige: ${spf.lookups} de 10 permitidas. Consultas vacías: ${spf.voidLookups} de 2.` }));
    const over = spf.lookups > 10;
    spfBody.append(h('div', { class: `lookups${over ? ' over' : ''}`, 'aria-hidden': 'true' },
      Array.from({ length: 10 }, (_, i) => h('span', { class: i < spf.lookups ? 'on' : '' }))));
    if (spf.tree && spf.tree.children && spf.tree.children.length) spfBody.append(h('ul', { class: 'tree' }, spfTree(spf.tree)));
    blocks.push(h('details', { open: true }, h('summary', null, 'SPF', statusPill(spf.status === 'ok' && spf.allQualifier !== '+', 'Válido', spf.status === 'none' ? 'Ausente' : spf.status === 'ok' ? 'Inseguro' : 'Con errores', 'critical')), spfBody));

    const d = r.dmarc;
    const dBody = h('div', { class: 'body' });
    if (d.record) {
      dBody.append(h('pre', { class: 'raw', text: d.record }));
      if (d.inherited) dBody.append(h('p', { class: 'small', text: `Heredado del dominio ${d.foundAt}.` }));
      const tagNames = { p: 'política', sp: 'política subdominios', np: 'subdominios inexistentes', rua: 'reportes agregados', ruf: 'reportes forenses', adkim: 'alineación DKIM', aspf: 'alineación SPF', pct: 'porcentaje (obsoleto)', t: 'modo prueba', psd: 'dominio de sufijo público', fo: 'opciones de fallo' };
      dBody.append(h('dl', { class: 'kv' }, Object.entries(d.tags || {}).filter(([k]) => k !== 'v').flatMap(([k, v]) => [h('dt', { text: k }), h('dd', { text: `${v}${tagNames[k] ? `  (${tagNames[k]})` : ''}` })])));
    } else {
      dBody.append(h('p', { class: 'small', text: `No existe registro en _dmarc.${r.domain}.` }));
    }
    const effective = d.present ? E.effectivePolicy(d.appliedPolicy, d.testing) : null;
    blocks.push(h('details', { open: true }, h('summary', null, 'DMARC', d.present
      ? h('span', { class: 'pill', 'data-tone': effective === 'reject' ? 'low' : effective === 'quarantine' ? 'medium' : 'high', text: `p=${effective}` })
      : h('span', { class: 'pill', 'data-tone': 'critical', text: 'Ausente' })), dBody));

    const k = r.dkim;
    const kBody = h('div', { class: 'body' });
    if (k.found.length) {
      kBody.append(h('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Claves DKIM encontradas' }, h('table', null,
        h('thead', null, h('tr', null, h('th', { text: 'Selector' }), h('th', { text: 'Tipo' }), h('th', { class: 'num', text: 'Bits aprox.' }), h('th', { text: 'Estado' }))),
        h('tbody', null, k.found.map((x) => h('tr', null, h('td', { class: 'mono', text: x.selector }), h('td', { text: x.keyType }),
          h('td', { class: 'num', text: x.bits ? String(x.bits) : '—' }), h('td', { text: x.revoked ? 'Revocada' : !x.valid ? 'Inválida' : x.bits && x.bits < 2048 && x.keyType === 'rsa' ? 'Débil' : 'Correcta' })))))));
    }
    kBody.append(h('p', { class: 'small', text: `Probamos ${k.selectorsTested} selectores comunes. DKIM no se puede listar desde fuera: si tu proveedor usa un selector propio, puede existir aunque no aparezca aquí.` }));
    blocks.push(h('details', null, h('summary', null, 'DKIM', statusPill(k.active > 0, `${k.active} clave${k.active === 1 ? '' : 's'} activa${k.active === 1 ? '' : 's'}`, 'No encontrada')), kBody));

    const mx = r.mx;
    const mBody = h('div', { class: 'body' });
    mBody.append(h('p', { class: 'small', text: mx.provider ? `Proveedor detectado: ${mx.provider.name}.` : mx.nullMx ? 'El dominio declara que no recibe correo (MX nulo).' : 'El dominio no tiene servidores de correo (MX).' }));
    if (mx.records.length && !mx.nullMx) mBody.append(h('pre', { class: 'raw', text: mx.records.map((m) => `${m.preference}  ${m.host}`).join('\n') }));
    blocks.push(h('details', null, h('summary', null, 'Correo entrante (MX)', h('span', { class: 'pill', 'data-tone': 'info', text: mx.provider ? mx.provider.name : 'Sin correo' })), mBody));

    const x = r.extras;
    const rows = [
      ['MTA-STS', x.mtaSts.present, x.mtaSts.present ? (x.mtaSts.mode ? `Publicado, modo ${x.mtaSts.mode}` : 'Registro publicado') : 'No publicado', 'Obliga a cifrar el correo que recibes.'],
      ['TLS-RPT', x.tlsRpt.present, x.tlsRpt.present ? 'Publicado' : 'No publicado', 'Te avisa si falla el cifrado del correo entrante.'],
      ['DNSSEC', x.dnssec.validated, x.dnssec.validated ? 'Firmado y validado' : x.dnssec.signed ? 'Firmado, sin validar' : 'No firmado', 'Impide falsificar las respuestas DNS de tu dominio.'],
      ['CAA', x.caa.present, x.caa.present ? x.caa.records.map((c) => `${c.tag} ${c.value}`).join(', ') : 'No publicado', 'Limita quién puede emitir certificados HTTPS.'],
      ['BIMI', x.bimi.present, x.bimi.present ? 'Publicado' : 'No publicado', 'Muestra tu logo en la bandeja (requiere DMARC estricto).'],
    ];
    const oBody = h('div', { class: 'body' }, h('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Otros controles de seguridad' }, h('table', null,
      h('thead', null, h('tr', null, h('th', { text: 'Control' }), h('th', { text: 'Estado' }), h('th', { text: 'Para qué sirve' }))),
      h('tbody', null, rows.map(([name, ok, state, what]) => h('tr', null, h('td', { text: name }), h('td', null, statusPill(ok, state, state, 'info')), h('td', { text: what })))))));
    blocks.push(h('details', null, h('summary', null, 'Otros controles', h('span', { class: 'pill', 'data-tone': 'info', text: `${rows.filter((rw) => rw[1]).length} de ${rows.length}` })), oBody));

    blocks.push(h('p', { class: 'small', text: `${r.dnsQueries} consultas DNS en ${(r.durationMs / 1000).toLocaleString('es-DO', { maximumFractionDigits: 1 })} s, vía DNS sobre HTTPS (Cloudflare y Google). Fecha: ${new Date(r.analyzedAt).toLocaleString('es-DO')}.` }));
    $('r-tech').replaceChildren(...blocks);
  }

  $('copy-summary').addEventListener('click', (ev) => {
    if (!current) return;
    const r = current;
    const lines = [
      `Informe Suplanta.do: ${r.domain}`,
      `Fecha: ${new Date(r.analyzedAt).toLocaleString('es-DO')}`,
      `${RISK_LABEL[r.verdict.level]}. Calificación ${r.score.grade} (${r.score.total}/100).`,
      r.verdict.headline,
      `Correo falso simulado: ${r.simulation.outcome.label.toLowerCase()}.`,
      '',
      'Hallazgos:',
      ...sortedIssues(r).map((i) => `- [${SEVERITY[i.severity].label}] ${i.message}`),
      '',
      'Acciones recomendadas:',
      ...r.remediation.map((m) => `- ${m.title}`),
      '',
      'Análisis pasivo de registros DNS públicos. No garantiza ausencia de riesgo.',
    ];
    copyText(lines.join('\n'), ev.currentTarget);
  });

  // ------------------------------------------------------------ observatorio
  function renderObservatory() {
    const o = DATA.observatory;
    const all = o.overall;
    const scanDate = new Date(`${o.scanDate}T12:00:00`).toLocaleDateString('es-DO', { day: 'numeric', month: 'long', year: 'numeric' });
    $('obs-sub').textContent = `${o.sample.analyzed} organizaciones dominicanas analizadas el ${scanDate}.`;
    $('obs-fig').textContent = `${fmt(all.spoofable)}%`;
    $('obs-fig-label').textContent = `pueden ser suplantadas por correo: ${all.spoofableCount} de ${all.n} no tienen DMARC o lo tienen en modo de solo observación.`;
    const bank = o.sectors.find((s) => s.sector === 'Banca y finanzas');
    const worst = o.sectors[0];
    $('obs-lead').textContent = `Solo el ${fmt(all.dmarc.reject)}% les pide a los receptores rechazar los correos falsos. La banca lidera (${fmt(bank.dmarc.reject)}% en rechazo); ${worst.sector.toLowerCase()} es el sector más expuesto, con ${fmt(worst.spoofable)}% suplantable. Como referencia, PowerDMARC midió entre 16% y 25% de dominios en rechazo en México, Perú, Argentina, Brasil y Ecuador en 2026, con una muestra y un método distintos.`;

    const m365 = o.providers.find((p) => p.id === 'm365');
    const facts = [
      [`${fmt(all.subdomainSpoofable)}%`, 'permite suplantar subdominios inventados, como pagos.su-dominio.'],
      [`${fmt(all.dkimWeak)}%`, 'publica al menos una clave DKIM de 1024 bits o menos.'],
      [`${fmt(all.spf.broken)}%`, 'tiene un SPF con errores que lo invalidan.'],
      [`${fmt(all.mtaSts)}%`, `publica MTA-STS para cifrar el correo entrante (${all.mtaStsEnforce} en modo obligatorio).`],
      [`${fmt(all.dnssec)}%`, 'firma su zona con DNSSEC validable.'],
      [m365 ? `${fmt(m365.share)}%` : '', 'usa Microsoft 365: corregirlo es cuestión de horas, no de comprar productos.'],
    ].filter((f) => f[0]);
    $('obs-facts').replaceChildren(...facts.map(([n, t]) => h('li', null, h('strong', { text: n }), h('span', { text: t }))));

    $('obs-method').replaceChildren(
      h('p', { text: `${o.method} Analizamos el dominio web principal de cada organización (${o.sample.scanned} candidatos de Wikidata y directorios públicos; ${o.sample.notResolving} no existían en DNS y ${o.sample.excluded} se excluyeron por duplicados o titularidad dudosa).` }),
      h('p', { text: '"Suplantable" significa que un correo falso con ese dominio exacto no sería rechazado ni enviado a spam por política DMARC: llega o no según los filtros de cada proveedor. Es una muestra de conveniencia, no un censo, y refleja el estado de un día.' }),
      h('p', { text: 'Publicamos solo cifras agregadas. Los resultados por organización se comparten de forma privada con cada entidad que lo solicite.' }),
      h('p', null, 'El motor y la metodología son abiertos para revisión. Si representas a una organización de la muestra y quieres tu informe, usa el contacto al pie de la página.'));

    const segs = [
      ['missing', 'Sin DMARC', all.dmarc.counts.missing],
      ['none', 'Solo observa (none)', all.dmarc.counts.none],
      ['quarantine', 'A spam (quarantine)', all.dmarc.counts.quarantine],
      ['reject', 'Rechaza (reject)', all.dmarc.counts.reject],
    ];
    $('policy-sub').textContent = `${all.n} organizaciones, según su política DMARC efectiva.`;
    const stack = $('policy-stack');
    stack.setAttribute('aria-label', segs.map(([, l, c]) => `${l}: ${c}`).join('; '));
    stack.replaceChildren(...segs.filter(([, , c]) => c > 0).map(([k, l, c]) => h('span', { class: `c-${k}`, style: `flex:${c} 1 0`, title: `${l}: ${c} (${fmt((c / all.n) * 100)}%)` })));
    $('policy-legend').replaceChildren(...segs.map(([k, l, c]) => h('li', null, h('i', { class: `c-${k}`, 'aria-hidden': 'true' }), `${l} ${fmt((c / all.n) * 100)}%`)));

    const tip = $('tip');
    const container = $('chart-sectors');
    const max = 100;
    $('sector-bars').replaceChildren(...o.sectors.map((s) => {
      const track = h('div', { class: 'bar-track', tabindex: '0', 'aria-label': `${s.sector}: ${fmt(s.spoofable)}% suplantable, ${s.n} organizaciones` },
        h('span', { class: 'bar-fill', style: `width:calc((100% - 56px) * ${s.spoofable / max})` }), h('span', { class: 'bar-val', text: `${fmt(s.spoofable)}%` }));
      const showTip = () => {
        tip.textContent = `${s.sector}: ${s.spoofableCount} de ${s.n} suplantables. Rechazo ${fmt(s.dmarc.reject)}%, sin DMARC ${fmt(s.dmarc.missing)}%.`;
        tip.hidden = false;
        const cr = container.getBoundingClientRect();
        const fill = track.firstChild.getBoundingClientRect();
        const left = Math.min(Math.max(fill.right - cr.left, 140), cr.width - 140);
        tip.style.left = `${left}px`;
        tip.style.top = `${fill.top - cr.top}px`;
      };
      const hideTip = () => { tip.hidden = true; };
      track.addEventListener('mouseenter', showTip);
      track.addEventListener('mouseleave', hideTip);
      track.addEventListener('focus', showTip);
      track.addEventListener('blur', hideTip);
      return h('div', { class: 'bar-row' }, h('span', { class: 'lbl' }, s.sector, h('small', { text: `${s.n} organizaciones` })), track);
    }));

    $('sector-table').replaceChildren(
      h('thead', null, h('tr', null, ['Sector', 'n', 'Suplantable', 'Sin DMARC', 'none', 'quarantine', 'reject', 'Promedio'].map((t, i) => h('th', { class: i ? 'num' : null, text: t })))),
      h('tbody', null, o.sectors.concat([{ sector: 'Total', ...all }]).map((s) => h('tr', null,
        h('td', { text: s.sector }), h('td', { class: 'num', text: String(s.n) }), h('td', { class: 'num', text: `${fmt(s.spoofable)}%` }),
        h('td', { class: 'num', text: `${fmt(s.dmarc.missing)}%` }), h('td', { class: 'num', text: `${fmt(s.dmarc.none)}%` }),
        h('td', { class: 'num', text: `${fmt(s.dmarc.quarantine)}%` }), h('td', { class: 'num', text: `${fmt(s.dmarc.reject)}%` }),
        h('td', { class: 'num', text: String(s.avgScore) }))))
    );
  }

  function renderContact() {
    const box = $('contact');
    const parts = [h('p', null, h('strong', { text: '¿Tu dominio salió mal?' })),
      h('p', { text: 'Corregirlo suele tomar días, no meses, y no requiere comprar productos. Julio Pujols ofrece una revisión inicial sin costo para organizaciones dominicanas.' })];
    if (CONTACT.email) parts.push(h('p', null, 'Correo: ', h('span', { class: 'mono', text: CONTACT.email })));
    if (CONTACT.linkedin) parts.push(h('p', null, h('a', { href: CONTACT.linkedin, target: '_blank', rel: 'noopener noreferrer', text: 'Escríbele por LinkedIn' })));
    if (CONTACT.github) parts.push(h('p', null, h('a', { href: CONTACT.github, target: '_blank', rel: 'noopener noreferrer', text: 'Otros proyectos en GitHub' })));
    box.replaceChildren(...parts);
  }

  renderObservatory();
  renderContact();
})();
