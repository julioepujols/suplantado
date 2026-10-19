(function () {
  'use strict';
  const E = window.SuplantaEngine;
  const $ = (id) => document.getElementById(id);
  const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const fmt = (n) => Number(n).toLocaleString('es-DO', { maximumFractionDigits: 1 });
  const SVG_NS = 'http://www.w3.org/2000/svg';

  // Construye nodos sin innerHTML: todo texto llega por textContent.
  function h(tag, props, ...children) {
    const el = document.createElement(tag);
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (v === null || v === undefined || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
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
  function svg(tag, attrs) {
    const el = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, String(v));
    return el;
  }
  function icon(name) {
    const el = svg('svg', { class: 'icon', 'aria-hidden': 'true' });
    el.append(svg('use', { href: `#i-${name}` }));
    return el;
  }
  const chev = () => h('span', { class: 'chev', 'aria-hidden': 'true' }, icon('chev'));
  function fold(summaryParts, bodyParts, open) {
    return h('details', { class: 'fold', open: Boolean(open) },
      h('summary', null, summaryParts, chev()),
      h('div', { class: 'body' }, bodyParts));
  }
  const both = (simple, tech) => [h('span', { class: 'only-simple', text: simple }), h('span', { class: 'only-tech', text: tech })];

  // ------------------------------------------------------------ textos
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

  const SPF_PLAIN = {
    pass: 'Tu lista de servidores autorizados deja pasar al impostor. Para Gmail u Outlook, el correo viene de ti.',
    fail: 'El servidor del impostor no está en tu lista de autorizados. Primera alarma encendida.',
    softfail: 'El impostor no está en tu lista, pero la lista dice "sospechoso", no "prohibido". Es una alarma a medias.',
    neutral: 'Tu lista no dice ni sí ni no, así que el receptor no recibe ninguna señal.',
    none: 'No hay lista de servidores autorizados que consultar, así que el receptor no puede comparar.',
    permerror: 'Tu lista tiene un error y el receptor la ignora. Es como no tenerla.',
    temperror: 'No se pudo leer tu lista en este momento, así que el receptor no puede usarla.',
  };
  const DKIM_PLAIN = 'El impostor no puede copiar tu sello digital, así que el correo llega sin sello. Eso solo sirve si DMARC exige el sello.';
  function dmarcPlain(sim, report, usingSub) {
    if (sim.disposition === 'rejected') return 'Tu instrucción al portero es "rechazar": devuelve el correo falso y tu cliente nunca lo ve.';
    if (sim.disposition === 'quarantine') return 'Tu instrucción es "a spam": el correo falso no llega a la bandeja principal, aunque alguien podría abrirlo desde spam.';
    if (sim.disposition === 'delivered-pass') return 'Como tu lista autorizó al impostor, el portero lo trata como un correo tuyo legítimo.';
    if (!report.dmarc.present) return 'No le has dado ninguna instrucción al portero. Cada proveedor decide por su cuenta y muchos correos falsos pasan.';
    return usingSub
      ? 'Tu instrucción no cubre los subdominios inventados: el portero ve que falla y aun así lo deja pasar.'
      : 'Tu instrucción es "solo observa": el portero ve que el correo falla y aun así lo deja pasar.';
  }

  const PLAIN = {
    'dmarc-missing': ['Nadie le dice a Gmail u Outlook qué hacer con correos falsos a tu nombre', 'Publica un registro DMARC en modo observación y llévalo a rechazo en 6 a 8 semanas, como indica el plan.'],
    'dmarc-none': ['Tu DMARC solo observa: los correos falsos se entregan igual', 'Pasa a cuarentena y luego a rechazo cuando los reportes confirmen que tu correo legítimo pasa.'],
    'dmarc-invalid-policy': ['Tu registro DMARC tiene un error y los receptores lo ignoran', 'Corrígelo con el valor exacto del plan.'],
    'dmarc-syntax': ['Tu registro DMARC tiene un error de escritura', 'Corrígelo con el valor exacto del plan.'],
    'dmarc-multiple': ['Tienes más de un registro DMARC y eso los anula', 'Deja uno solo.'],
    'dmarc-quarantine': ['Los correos falsos van a spam, pero todavía pueden abrirse', 'Cuando los reportes estén limpios, sube a rechazo (p=reject).'],
    'dmarc-partial': ['Tu DMARC protege solo una parte del correo', 'Quita la etiqueta pct, que ya es obsoleta, para aplicar la política a todo.'],
    'dmarc-testing': ['Tu DMARC está en modo prueba y no se aplica del todo', 'Quita t=y cuando termines las pruebas.'],
    'dmarc-sp-none': ['Tus subdominios no están protegidos', 'Agrega sp=reject (o quarantine) a tu DMARC.'],
    'dmarc-no-rua': ['No recibes reportes de quién envía correo con tu nombre', 'Agrega una dirección rua para ver quién usa tu dominio.'],
    'dmarc-rua-unauthorized': ['Tus reportes DMARC no llegarán a su destino', 'El dominio externo que recibe los reportes debe autorizarlo con un registro DNS.'],
    'dmarc-rua-too-many': ['Tienes demasiadas direcciones de reportes', 'Deja una o dos.'],
    'dmarc-obsolete': ['Tu DMARC usa etiquetas obsoletas', 'Retíralas en el próximo cambio. No es urgente.'],
    'dmarc-temperror': ['No pudimos leer tu DMARC en este momento', 'Vuelve a intentarlo en unos minutos.'],
    'dmarc-warning': ['Tu DMARC tiene un detalle por revisar', 'Revisa el detalle técnico con tu equipo de TI.'],
    'spf-missing': ['No tienes lista de servidores autorizados (SPF)', 'Publica un SPF con todos los servicios que envían correo por ti.'],
    'spf-pass-all': ['Tu SPF autoriza a cualquier servidor del mundo', 'Reemplaza "+all" por la lista exacta de tus proveedores y termina en ~all.'],
    'spf-pass-all-indirect': ['Tu SPF autoriza a cualquier servidor del mundo por una vía indirecta', 'Revisa los include: uno de ellos abre el SPF a todos.'],
    'spf-wide-range': ['Tu SPF autoriza rangos de direcciones enormes', 'Limítalo a los rangos reales de tus proveedores.'],
    'spf-too-many-lookups': ['Tu SPF es demasiado largo y los receptores lo invalidan', 'Quita proveedores que ya no usas o simplifica el registro.'],
    'spf-void-lookups': ['Tu SPF apunta a dominios que no existen', 'Quita esas referencias.'],
    'spf-multiple': ['Tienes más de un SPF y eso invalida ambos', 'Únelos en un solo registro.'],
    'spf-syntax': ['Tu SPF tiene un error de escritura que lo invalida', 'Corrígelo con quien administra tu DNS.'],
    'spf-loop': ['Tu SPF se incluye a sí mismo en círculo', 'Corrige la referencia circular.'],
    'spf-include-missing': ['Tu SPF apunta a un proveedor que no tiene SPF', 'Quita o corrige esa referencia.'],
    'spf-include-multiple': ['Un proveedor de tu SPF tiene registros duplicados', 'Avísale al proveedor o quita la referencia.'],
    'spf-neutral-all': ['Tu SPF no le dice al receptor qué hacer con los extraños', 'Termina el SPF en ~all, o en -all cuando DMARC esté en rechazo.'],
    'spf-no-all': ['Tu SPF no le dice al receptor qué hacer con los extraños', 'Termina el SPF en ~all, o en -all cuando DMARC esté en rechazo.'],
    'spf-softfail': ['Tu SPF marca a los extraños como sospechosos (normal si usas DMARC)', 'Nada urgente. Cámbialo a -all cuando DMARC esté en rechazo.'],
    'spf-near-limit': ['Tu SPF funciona, pero está cerca de su límite', 'Revísalo antes de agregar otro proveedor.'],
    'spf-long': ['Tu SPF es muy largo', 'Simplifícalo para evitar errores en algunos receptores.'],
    'spf-ptr': ['Tu SPF usa un mecanismo desaconsejado (ptr)', 'Reemplázalo por rangos ip4/ip6 o include.'],
    'spf-temperror': ['No pudimos leer tu SPF completo en este momento', 'Vuelve a intentarlo en unos minutos.'],
    'dkim-not-found': ['No encontramos tu sello digital (DKIM)', 'Actívalo en tu proveedor de correo. Si usa un selector propio, puede existir aunque no aparezca aquí.'],
    'dkim-weak': ['Tu sello digital usa una clave corta', 'Cámbiala por una de 2048 bits.'],
    'dkim-cname-pending': ['Tu DKIM está a medio configurar', 'Termina la activación en el portal de tu proveedor.'],
    'dnssec-bogus': ['Tu DNSSEC está roto y algunos usuarios no pueden encontrar tu dominio', 'Corrige o retira la firma DNSSEC con tu registrador cuanto antes.'],
  };

  // ------------------------------------------------------------ aviso flotante
  const toastEl = $('toast');
  let toastTimer = null;
  function toast(msg, name) {
    toastEl.replaceChildren(icon(name || 'check'), h('span', { text: msg }));
    toastEl.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toastEl.classList.remove('show'), 2200);
  }

  // ------------------------------------------------------------ modo de lectura
  const MODE_KEY = 'suplanta-mode';
  function setMode(mode) {
    document.body.dataset.mode = mode;
    $('mode-simple').setAttribute('aria-pressed', String(mode === 'simple'));
    $('mode-tech').setAttribute('aria-pressed', String(mode === 'tech'));
    try { localStorage.setItem(MODE_KEY, mode); } catch (_) { /* almacenamiento no disponible */ }
  }
  let savedMode = null;
  try { savedMode = localStorage.getItem(MODE_KEY); } catch (_) { savedMode = null; }
  setMode(savedMode === 'tech' ? 'tech' : 'simple');
  $('mode-simple').addEventListener('click', () => setMode('simple'));
  $('mode-tech').addEventListener('click', () => setMode('tech'));

  // ------------------------------------------------------------ menú móvil
  const nav = $('nav');
  const menuBtn = $('menu-btn');
  function closeMenu() { nav.classList.remove('open'); menuBtn.setAttribute('aria-expanded', 'false'); }
  menuBtn.addEventListener('click', () => {
    const open = !nav.classList.contains('open');
    nav.classList.toggle('open', open);
    menuBtn.setAttribute('aria-expanded', String(open));
  });
  nav.addEventListener('click', (ev) => { if (ev.target.closest('a')) closeMenu(); });
  document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape' && nav.classList.contains('open')) { closeMenu(); menuBtn.focus(); } });

  // ------------------------------------------------------------ sobre y recorrido postal
  const samples = new Map(DATA.samples.map((s) => [s.report.domain, s]));
  let current = null;
  let simMode = 'main';
  const envFrom = $('env-from');
  const mark = $('mark');
  const trail = $('trail');
  const stops = { spf: $('stop-spf'), dkim: $('stop-dkim'), dmarc: $('stop-dmarc'), dest: $('stop-dest') };

  function setFrom(domain) {
    envFrom.textContent = `gerencia@${domain || 'tuempresa.com.do'}`;
  }
  function stepState(s) { return s.bad ? 'bad' : s.ok ? 'ok' : 'warn'; }
  function setTrail(sim) {
    delete trail.dataset.busy;
    if (!sim) {
      trail.dataset.at = '0';
      for (const el of Object.values(stops)) delete el.dataset.state;
      $('dest-label').textContent = 'Destino';
      $('dest-sub').textContent = '¿bandeja o rechazo?';
      return;
    }
    const delays = reduceMotion ? ['0ms', '0ms', '0ms'] : ['500ms', '1000ms', '1500ms'];
    trail.style.setProperty('--d2', delays[0]);
    trail.style.setProperty('--d3', delays[1]);
    trail.style.setProperty('--d4', delays[2]);
    trail.dataset.at = '0';
    const byId = Object.fromEntries(sim.steps.map((s) => [s.id, s]));
    for (const key of ['spf', 'dkim', 'dmarc']) delete stops[key].dataset.state;
    delete stops.dest.dataset.state;
    void trail.offsetWidth;
    for (const key of ['spf', 'dkim', 'dmarc']) stops[key].dataset.state = stepState(byId[key]);
    const tone = sim.outcome.tone;
    stops.dest.dataset.state = tone === 'low' ? 'ok' : tone === 'medium' ? 'warn' : 'bad';
    $('dest-label').textContent = STAMP[sim.disposition].text;
    $('dest-sub').textContent = STAMP[sim.disposition].sub;
    trail.dataset.at = sim.disposition === 'rejected' ? '2' : '3';
  }
  function setStamp(state) {
    mark.dataset.tone = state ? state.tone : 'ghost';
    $('mark-text').textContent = state ? state.text : 'Sin verificar';
    $('mark-sub').textContent = state ? state.sub : 'escribe tu dominio';
    mark.classList.remove('thunk');
    if (state && !reduceMotion) {
      mark.style.setProperty('--thunk-delay', '1500ms');
      void mark.offsetWidth;
      mark.classList.add('thunk');
    }
  }
  function resetEnvelope(caption) {
    current = null;
    setStamp(null);
    setTrail(null);
    $('env-caption').textContent = caption;
  }
  $('domain-input').addEventListener('input', (ev) => {
    const n = E.normalizeDomain(ev.target.value);
    setFrom(n.ok ? n.domain : '');
    if (current) resetEnvelope('Pulsa Comprobar para ver si este mensaje llegaría.');
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
    setStamp(null);
    setTrail(null);
    trail.dataset.busy = '';
    status(`Consultando los registros DNS públicos de ${norm.domain}…`);
    let report;
    try {
      report = await E.analyzeDomain(norm.domain, { concurrency: 8, timeoutMs: 6000 });
    } catch (_) {
      report = { ok: false, error: 'network' };
    } finally {
      btn.disabled = false;
      delete trail.dataset.busy;
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
    resetEnvelope('Así empieza un fraude por suplantación de correo empresarial. La pregunta es si este mensaje llegaría a tu cliente.');
    $('resultado').hidden = true;
    $('comprobar').scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth' });
    input.focus({ preventScroll: true });
  });

  // ------------------------------------------------------------ informe
  function brief(report) {
    const main = report.simulation;
    const sub = report.subdomainSimulation;
    const d = report.domain;
    let rows;
    if (main.disposition === 'rejected') {
      rows = [
        ['Qué significa', `Los correos falsos que usan exactamente ${d} son rechazados antes de llegar.`],
        ['Riesgo que queda', 'Dominios parecidos (por ejemplo, con un guion o una letra cambiada) y cuentas de correo robadas. DMARC no detiene esos casos.'],
        ['Qué hacer', sub.disposition === 'rejected'
          ? 'Mantener los reportes DMARC bajo revisión y acordar con finanzas que todo cambio de cuenta bancaria se confirme por teléfono.'
          : 'Proteger también los subdominios inventados (sp=reject y np=reject) y confirmar por teléfono todo cambio de cuenta bancaria.'],
      ];
    } else if (main.disposition === 'quarantine') {
      rows = [
        ['Qué significa', `Los correos falsos con el nombre de ${d} terminan en spam. La protección es parcial.`],
        ['Riesgo para el negocio', 'Un empleado o cliente todavía puede abrir el correo falso desde la carpeta de spam y seguir sus instrucciones.'],
        ['Qué hacer', 'Subir DMARC a rechazo cuando los reportes confirmen que todo el correo legítimo pasa. Suele tomar de 2 a 4 semanas.'],
      ];
    } else {
      rows = [
        ['Qué significa', main.disposition === 'delivered-pass'
          ? `Cualquiera puede enviar correos que aparentan salir de ${d}, y pasan como legítimos.`
          : `Cualquiera puede enviar correos que aparentan salir de ${d}, y ninguna regla tuya los bloquea.`],
        ['Riesgo para el negocio', 'Fraudes de pago a clientes y proveedores ("cambiamos de cuenta bancaria"), robo de contraseñas y daño a la reputación de la marca.'],
        ['Qué hacer', 'Pedir a TI o al proveedor de correo que aplique el plan de abajo. Toma de 4 a 8 semanas de forma gradual y casi nunca requiere comprar productos.'],
      ];
    }
    return rows.flatMap(([t, v]) => [h('dt', { text: t }), h('dd', { text: v })]);
  }

  function animateRing(report) {
    const ring = $('r-ring');
    const fg = $('r-ring-fg');
    ring.dataset.tone = report.verdict.level;
    const target = 263.9 * (1 - report.score.total / 100);
    fg.style.transition = 'none';
    fg.style.strokeDashoffset = '263.9';
    void fg.getBoundingClientRect();
    fg.style.transition = '';
    requestAnimationFrame(() => { fg.style.strokeDashoffset = String(target); });
  }

  function show(report, source) {
    current = report;
    simMode = 'main';
    setStamp(STAMP[report.simulation.disposition]);
    setTrail(report.simulation);
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
    $('r-brief').replaceChildren(...brief(report));
    $('r-grade').textContent = report.score.grade;
    $('r-score').textContent = String(report.score.total);
    $('r-parts').replaceChildren(...report.score.parts.map((p) => h('li', null,
      h('span', { text: p.label }), h('span', { class: 'pts', text: `${p.points}/${p.max}` }),
      h('span', { class: 'meter', 'aria-hidden': 'true' }, h('span', { style: `width:${Math.round((p.points / p.max) * 100)}%` })))));

    renderRoute();
    renderFindings(report);
    renderPlan(report);
    renderTech(report);

    const section = $('resultado');
    section.hidden = false;
    animateRing(report);
    section.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
    $('r-headline').focus({ preventScroll: true });
  }

  function renderRoute() {
    const usingSub = simMode === 'sub';
    const sim = usingSub ? current.subdomainSimulation : current.simulation;
    $('tab-main').setAttribute('aria-selected', String(!usingSub));
    $('tab-sub').setAttribute('aria-selected', String(usingSub));
    $('tab-main').tabIndex = usingSub ? -1 : 0;
    $('tab-sub').tabIndex = usingSub ? 0 : -1;
    $('route-panel').setAttribute('aria-labelledby', usingSub ? 'tab-sub' : 'tab-main');
    const origin = sim.spfAuthorizesAttacker
      ? [' enviado desde cualquier servidor que el atacante elija: tu SPF lo autoriza.']
      : [' enviado desde un servidor del atacante (', h('code', { text: sim.attackerIp }), ', dirección reservada para documentación).'];
    $('route-from').replaceChildren('Correo falso de ', h('code', { text: sim.from }), ...origin);
    const plainFor = (s) => (s.id === 'spf' ? SPF_PLAIN[s.result] : s.id === 'dkim' ? DKIM_PLAIN : dmarcPlain(sim, current, usingSub));
    const items = sim.steps.map((s) => h('li', { 'data-state': stepState(s) },
      h('h4', { text: s.title }),
      h('span', { class: 'code only-tech', text: `resultado: ${s.result}` }),
      h('p', { class: 'only-tech', text: s.text }),
      h('p', { class: 'plain' }, h('b', { text: 'En palabras simples' }), plainFor(s))));
    const tone = sim.outcome.tone;
    items.push(h('li', { class: 'final', 'data-tone': tone, 'data-state': tone === 'low' ? 'ok' : tone === 'medium' ? 'warn' : 'bad' },
      h('h4', { text: sim.outcome.label }), h('span', { class: 'code only-tech', text: 'destino' }), h('p', { text: sim.outcome.text })));
    $('route').replaceChildren(...items);
  }
  function selectTab(mode) { simMode = mode; renderRoute(); $(mode === 'main' ? 'tab-main' : 'tab-sub').focus(); }
  $('tab-main').addEventListener('click', () => { simMode = 'main'; renderRoute(); });
  $('tab-sub').addEventListener('click', () => { simMode = 'sub'; renderRoute(); });
  for (const id of ['tab-main', 'tab-sub']) {
    $(id).addEventListener('keydown', (e) => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') { e.preventDefault(); selectTab(simMode === 'main' ? 'sub' : 'main'); }
    });
  }

  function sortedIssues(report) {
    return report.issues.slice().sort((a, b) => SEVERITY[a.severity].order - SEVERITY[b.severity].order);
  }

  function renderFindings(report) {
    const list = sortedIssues(report);
    if (!list.length) {
      $('r-findings').replaceChildren(h('p', { class: 'note' }, h('span', { class: 'pill', 'data-tone': 'low', text: 'Sin hallazgos' }), ' No encontramos problemas en los registros analizados.'));
      return;
    }
    $('r-findings').replaceChildren(...list.map((i, idx) => {
      const sev = SEVERITY[i.severity];
      const plain = PLAIN[i.code];
      return fold(
        [h('span', { class: 'pill', 'data-tone': sev.tone, text: sev.label }), h('span', { class: 'sum-text' }, plain ? both(plain[0], i.message) : i.message)],
        [plain ? h('p', null, h('strong', { text: 'Qué hacer: ' }), plain[1]) : null,
          plain ? h('p', { class: 'small only-simple', text: `Detalle técnico: ${i.message}` }) : null,
          h('p', { class: 'small only-tech', text: `Código: ${i.code}` })],
        idx === 0 && i.severity === 'critical');
    }));
  }

  async function copyText(text, okMsg) {
    try {
      await navigator.clipboard.writeText(text);
      toast(okMsg || 'Copiado al portapapeles');
    } catch (_) {
      const area = h('textarea', { class: 'sr-only', 'aria-hidden': 'true' });
      area.value = text;
      document.body.append(area);
      area.select();
      let ok = false;
      try { ok = document.execCommand('copy'); } catch (__) { ok = false; }
      area.remove();
      toast(ok ? (okMsg || 'Copiado al portapapeles') : 'No se pudo copiar: selecciona el texto y cópialo', ok ? 'check' : 'alert');
    }
  }

  function recordRow(r) {
    return h('div', { class: 'record' },
      h('span', { class: 'rtype', text: r.type }),
      h('div', null, h('span', { class: 'rname', text: r.name }), h('code', { class: 'rvalue', text: r.value })),
      h('button', { type: 'button', class: 'btn ghost small', 'aria-label': `Copiar registro ${r.type} de ${r.name}`, onclick: () => copyText(r.value, 'Registro copiado') }, icon('copy'), 'Copiar'));
  }

  function renderPlan(report) {
    if (!report.remediation.length) {
      $('r-plan').replaceChildren(h('p', { class: 'note', text: 'Tu configuración de autenticación de correo ya cumple lo esencial. Mantén los reportes DMARC bajo revisión.' }));
      return;
    }
    $('r-plan').replaceChildren(...report.remediation.map((item, idx) => {
      const body = [h('p', { text: item.why }), ...item.records.map(recordRow)];
      if (item.phases && item.phases.length) {
        body.push(h('ol', { class: 'phases' }, item.phases.map((ph) => h('li', null, h('div', null,
          h('p', { class: 'ph-label', text: ph.label }), recordRow(ph), h('p', { text: ph.note }))))));
      }
      if (item.note) body.push(h('p', { class: 'note', text: item.note }));
      const tag = item.priority === 1 ? ['high', 'Prioridad alta'] : item.priority === 2 ? ['warn', 'Prioridad media'] : ['info', 'Recomendado'];
      return fold([h('span', { class: 'pill', 'data-tone': tag[0], text: tag[1] }), h('span', { class: 'sum-text', text: item.title })], body, idx === 0);
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
    const spfBody = [];
    if (spf.record) spfBody.push(h('pre', { class: 'raw', text: spf.record }));
    spfBody.push(h('p', { class: 'small', text: `Consultas DNS que exige: ${spf.lookups} de 10 permitidas. Consultas vacías: ${spf.voidLookups} de 2.` }));
    spfBody.push(h('div', { class: `lookups${spf.lookups > 10 ? ' over' : ''}`, 'aria-hidden': 'true' },
      Array.from({ length: 10 }, (_, i) => h('span', { class: i < spf.lookups ? 'on' : '' }))));
    if (spf.tree && spf.tree.children && spf.tree.children.length) spfBody.push(h('ul', { class: 'tree' }, spfTree(spf.tree)));
    blocks.push(fold([h('span', { class: 'sum-text', text: 'SPF' }), statusPill(spf.status === 'ok' && spf.allQualifier !== '+' && !spf.openToAll, 'Válido', spf.status === 'none' ? 'Ausente' : spf.status === 'ok' ? 'Inseguro' : 'Con errores', 'critical')], spfBody));

    const d = r.dmarc;
    const dBody = [];
    if (d.record) {
      dBody.push(h('pre', { class: 'raw', text: d.record }));
      if (d.inherited) dBody.push(h('p', { class: 'small', text: `Heredado del dominio ${d.foundAt}.` }));
      const tagNames = { p: 'política', sp: 'política subdominios', np: 'subdominios inexistentes', rua: 'reportes agregados', ruf: 'reportes forenses', adkim: 'alineación DKIM', aspf: 'alineación SPF', pct: 'porcentaje (obsoleto)', t: 'modo prueba', psd: 'dominio de sufijo público', fo: 'opciones de fallo' };
      dBody.push(h('dl', { class: 'kv' }, Object.entries(d.tags || {}).filter(([k]) => k !== 'v').flatMap(([k, v]) => [h('dt', { text: k }), h('dd', { text: `${v}${tagNames[k] ? `  (${tagNames[k]})` : ''}` })])));
    } else {
      dBody.push(h('p', { class: 'small', text: `No existe registro en _dmarc.${r.domain}.` }));
    }
    const effective = d.present ? E.effectivePolicy(d.appliedPolicy, d.testing) : null;
    blocks.push(fold([h('span', { class: 'sum-text', text: 'DMARC' }), d.present
      ? h('span', { class: 'pill', 'data-tone': effective === 'reject' ? 'low' : effective === 'quarantine' ? 'medium' : 'high', text: `p=${effective}` })
      : h('span', { class: 'pill', 'data-tone': 'critical', text: 'Ausente' })], dBody));

    const k = r.dkim;
    const kBody = [];
    if (k.found.length) {
      kBody.push(h('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Claves DKIM encontradas' }, h('table', null,
        h('thead', null, h('tr', null, h('th', { text: 'Selector' }), h('th', { text: 'Tipo' }), h('th', { class: 'num', text: 'Bits aprox.' }), h('th', { text: 'Estado' }))),
        h('tbody', null, k.found.map((x) => h('tr', null, h('td', { class: 'mono', text: x.selector }), h('td', { text: x.keyType }),
          h('td', { class: 'num', text: x.bits ? String(x.bits) : '—' }), h('td', { text: x.revoked ? 'Revocada' : !x.valid ? 'Inválida' : x.bits && x.bits < 2048 && x.keyType === 'rsa' ? 'Débil' : 'Correcta' })))))));
    }
    kBody.push(h('p', { class: 'small', text: `Probamos ${k.selectorsTested} selectores comunes. DKIM no se puede listar desde fuera: si tu proveedor usa un selector propio, puede existir aunque no aparezca aquí.` }));
    blocks.push(fold([h('span', { class: 'sum-text', text: 'DKIM' }), statusPill(k.active > 0, `${k.active} clave${k.active === 1 ? '' : 's'} activa${k.active === 1 ? '' : 's'}`, 'No encontrada')], kBody));

    const mx = r.mx;
    const mBody = [h('p', { class: 'small', text: mx.provider ? `Proveedor detectado: ${mx.provider.name}.` : mx.nullMx ? 'El dominio declara que no recibe correo (MX nulo).' : 'El dominio no tiene servidores de correo (MX).' })];
    if (mx.records.length && !mx.nullMx) mBody.push(h('pre', { class: 'raw', text: mx.records.map((m) => `${m.preference}  ${m.host}`).join('\n') }));
    blocks.push(fold([h('span', { class: 'sum-text', text: 'Correo entrante (MX)' }), h('span', { class: 'pill', 'data-tone': 'info', text: mx.provider ? mx.provider.name : 'Sin correo' })], mBody));

    const x = r.extras;
    const rows = [
      ['MTA-STS', x.mtaSts.present, x.mtaSts.present ? (x.mtaSts.mode ? `Publicado, modo ${x.mtaSts.mode}` : 'Registro publicado') : 'No publicado', 'Obliga a cifrar el correo que recibes.'],
      ['TLS-RPT', x.tlsRpt.present, x.tlsRpt.present ? 'Publicado' : 'No publicado', 'Te avisa si falla el cifrado del correo entrante.'],
      ['DNSSEC', x.dnssec.validated, x.dnssec.validated ? 'Firmado y validado' : x.dnssec.signed ? 'Firmado, sin validar' : 'No firmado', 'Impide falsificar las respuestas DNS de tu dominio.'],
      ['CAA', x.caa.present, x.caa.present ? x.caa.records.map((c) => `${c.tag} ${c.value}`).join(', ') : 'No publicado', 'Limita quién puede emitir certificados HTTPS.'],
      ['BIMI', x.bimi.present, x.bimi.present ? 'Publicado' : 'No publicado', 'Muestra tu logo en la bandeja (requiere DMARC estricto).'],
    ];
    const oBody = [h('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Otros controles de seguridad' }, h('table', null,
      h('thead', null, h('tr', null, h('th', { text: 'Control' }), h('th', { text: 'Estado' }), h('th', { text: 'Para qué sirve' }))),
      h('tbody', null, rows.map(([name, ok, state, what]) => h('tr', null, h('td', { text: name }), h('td', null, statusPill(ok, state, state, 'info')), h('td', { text: what }))))))];
    blocks.push(fold([h('span', { class: 'sum-text', text: 'Otros controles' }), h('span', { class: 'pill', 'data-tone': 'info', text: `${rows.filter((rw) => rw[1]).length} de ${rows.length}` })], oBody));

    blocks.push(h('p', { class: 'small', style: 'margin-top:12px', text: `${r.dnsQueries} consultas DNS en ${(r.durationMs / 1000).toLocaleString('es-DO', { maximumFractionDigits: 1 })} s, vía DNS sobre HTTPS (Cloudflare y Google). Fecha: ${new Date(r.analyzedAt).toLocaleString('es-DO')}.` }));
    $('r-tech').replaceChildren(...blocks);
  }

  $('copy-summary').addEventListener('click', () => {
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
      ...sortedIssues(r).map((i) => `- [${SEVERITY[i.severity].label}] ${PLAIN[i.code] ? PLAIN[i.code][0] : i.message}`),
      '',
      'Acciones recomendadas:',
      ...r.remediation.map((m) => `- ${m.title}`),
      '',
      'Análisis pasivo de registros DNS públicos. No garantiza ausencia de riesgo.',
    ];
    copyText(lines.join('\n'), 'Resumen copiado: pégalo en un correo o chat');
  });

  // ------------------------------------------------------------ observatorio
  function onVisible(el, fn) {
    if (reduceMotion || !('IntersectionObserver' in window)) { fn(); return; }
    const io = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting)) { io.disconnect(); fn(); }
    }, { threshold: 0.3 });
    io.observe(el);
  }
  function countUp(el, value, suffix) {
    const final = `${fmt(value)}${suffix}`;
    if (reduceMotion) { el.textContent = final; return; }
    const start = performance.now();
    const dur = 1100;
    const tick = (now) => {
      const t = Math.min(1, (now - start) / dur);
      const eased = 1 - Math.pow(1 - t, 3);
      el.textContent = t < 1 ? `${Math.round(value * eased)}${suffix}` : final;
      if (t < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }
  const longDate = (iso) => new Date(`${iso}T12:00:00`).toLocaleDateString('es-DO', { day: 'numeric', month: 'long', year: 'numeric' });

  function renderObservatory() {
    const o = DATA.observatory;
    const all = o.overall;
    $('obs-updated').textContent = `Datos al cierre del ${longDate(o.scanDate)}. Se actualiza cada día a medianoche (hora de RD).`;
    $('obs-sub').textContent = `${o.sample.analyzed} organizaciones dominicanas analizadas.`;
    const fig = $('obs-fig');
    fig.textContent = `${fmt(all.spoofable)}%`;
    onVisible(fig, () => countUp(fig, all.spoofable, '%'));
    $('obs-fig-label').textContent = `pueden ser suplantadas por correo: ${all.spoofableCount} de ${all.n} no tienen DMARC o lo tienen en modo de solo observación.`;
    const bank = o.sectors.find((s) => s.sector === 'Banca y finanzas');
    const worst = o.sectors[0];
    $('obs-lead').textContent = `Solo el ${fmt(all.dmarc.reject)}% les pide a los receptores rechazar los correos falsos.${bank ? ` La banca lidera (${fmt(bank.dmarc.reject)}% en rechazo);` : ''} ${worst.sector.toLowerCase()} es el sector más expuesto, con ${fmt(worst.spoofable)}% suplantable. Como referencia, PowerDMARC midió entre 16% y 25% de dominios en rechazo en México, Perú, Argentina, Brasil y Ecuador en 2026, con una muestra y un método distintos.`;

    const m365 = o.providers.find((p) => p.id === 'm365');
    const facts = [
      [`${fmt(all.subdomainSpoofable)}%`, 'permite suplantar subdominios inventados, como pagos.su-dominio.'],
      [`${fmt(all.dkimWeak)}%`, 'publica al menos una clave DKIM de 1024 bits o menos.'],
      [`${fmt(all.spf.broken)}%`, 'tiene un SPF con errores que lo invalidan.'],
      [`${fmt(all.mtaSts)}%`, `publica MTA-STS para cifrar el correo entrante (${all.mtaStsEnforce} en modo obligatorio).`],
      [`${fmt(all.dnssec)}%`, 'firma su zona con DNSSEC validable.'],
      [m365 ? `${fmt(m365.share)}%` : '', 'usa Microsoft 365: corregirlo es cuestión de configuración, no de comprar productos.'],
    ].filter((f) => f[0]);
    $('obs-facts').replaceChildren(...facts.map(([n, t]) => h('li', null, h('strong', { text: n }), h('span', { text: t }))));

    $('obs-method').replaceChildren(
      h('p', { text: `${o.method} Analizamos el dominio web principal de cada organización (${o.sample.scanned} candidatos de Wikidata y directorios públicos; ${o.sample.notResolving} no existían en DNS, ${o.sample.excluded} se excluyeron por duplicados o titularidad dudosa${o.sample.inconclusive ? ` y ${o.sample.inconclusive} dieron errores DNS persistentes, por lo que no se cuentan` : ''}).` }),
      h('p', { text: '"Suplantable" significa que un correo falso con ese dominio exacto no sería rechazado ni enviado a spam por política DMARC: llega o no según los filtros de cada proveedor. Es una muestra de conveniencia, no un censo.' }),
      h('p', { text: 'Publicamos solo cifras agregadas. Los resultados por organización se comparten de forma privada con cada entidad que lo solicite.' }),
      h('p', { text: 'El motor y la metodología están publicados para revisión. Si representas a una organización de la muestra y quieres tu informe, usa el contacto al pie de la página.' }));

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
    const bars = $('sector-bars');
    bars.replaceChildren(...o.sectors.map((s) => {
      const track = h('div', { class: 'bar-track', tabindex: '0', 'aria-label': `${s.sector}: ${fmt(s.spoofable)}% suplantable, ${s.n} organizaciones` },
        h('span', { class: 'bar-fill', style: `--w:calc((100% - 56px) * ${s.spoofable / 100})` }), h('span', { class: 'bar-val', text: `${fmt(s.spoofable)}%` }));
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
    onVisible(bars, () => bars.classList.add('grown'));

    $('sector-table').replaceChildren(
      h('thead', null, h('tr', null, ['Sector', 'n', 'Suplantable', 'Sin DMARC', 'none', 'quarantine', 'reject', 'Promedio'].map((t, i) => h('th', { class: i ? 'num' : null, text: t })))),
      h('tbody', null, o.sectors.concat([{ sector: 'Total', ...all }]).map((s) => h('tr', null,
        h('td', { text: s.sector }), h('td', { class: 'num', text: String(s.n) }), h('td', { class: 'num', text: `${fmt(s.spoofable)}%` }),
        h('td', { class: 'num', text: `${fmt(s.dmarc.missing)}%` }), h('td', { class: 'num', text: `${fmt(s.dmarc.none)}%` }),
        h('td', { class: 'num', text: `${fmt(s.dmarc.quarantine)}%` }), h('td', { class: 'num', text: `${fmt(s.dmarc.reject)}%` }),
        h('td', { class: 'num', text: String(s.avgScore) }))))
    );
    renderTrend(DATA.history || []);
  }

  function renderTrend(history) {
    const points = history.filter((p) => p && /^\d{4}-\d{2}-\d{2}$/.test(p.date) && Number.isFinite(p.spoofable) && Number.isFinite(p.reject)).slice(-90);
    if (points.length < 2) return;
    const W = 560; const H = 200; const L = 34; const R = 10; const T = 10; const B = 26;
    const x = (i) => L + (i * (W - L - R)) / (points.length - 1);
    const y = (v) => T + (1 - v / 100) * (H - T - B);
    const plot = svg('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': `Evolución diaria: suplantables de ${fmt(points[0].spoofable)}% a ${fmt(points[points.length - 1].spoofable)}%; en rechazo de ${fmt(points[0].reject)}% a ${fmt(points[points.length - 1].reject)}%.` });
    for (const v of [0, 50, 100]) {
      plot.append(svg('line', { class: 'axis', x1: L, x2: W - R, y1: y(v), y2: y(v) }));
      const label = svg('text', { x: L - 6, y: y(v) + 4, 'text-anchor': 'end' });
      label.textContent = `${v}%`;
      plot.append(label);
    }
    for (const [key, cls, color] of [['spoofable', 'line', 'var(--risk-critical)'], ['reject', 'line alt', 'var(--risk-low)']]) {
      plot.append(svg('polyline', { class: cls, points: points.map((p, i) => `${x(i).toFixed(1)},${y(p[key]).toFixed(1)}`).join(' ') }));
      const last = points.length - 1;
      plot.append(svg('circle', { class: 'pt', cx: x(last), cy: y(points[last][key]), r: 4, style: `stroke:${color}` }));
    }
    for (const i of [0, points.length - 1]) {
      const t = svg('text', { x: x(i), y: H - 6, 'text-anchor': i === 0 ? 'start' : 'end' });
      t.textContent = new Date(`${points[i].date}T12:00:00`).toLocaleDateString('es-DO', { day: 'numeric', month: 'short' });
      plot.append(t);
    }
    $('trend-sub').textContent = `${points.length} días de datos. Cada punto es el cierre de un día.`;
    $('trend-plot').replaceChildren(plot);
    $('chart-trend').hidden = false;
  }

  // ------------------------------------------------------------ glosario, legal y preguntas
  const GLOSSARY = [
    ['list', 'SPF', 'La lista de carteros autorizados', 'Un registro público donde tu empresa dice qué servidores pueden enviar correo en su nombre. Si un correo llega desde un servidor fuera de la lista, el receptor lo nota. Por sí solo no bloquea nada: necesita DMARC.'],
    ['seal', 'DKIM', 'El sello de lacre', 'Tu servidor firma cada correo con una clave secreta, y la parte pública de esa clave está en tu DNS. Si alguien modifica el mensaje o lo envía sin tu clave, el sello no coincide.'],
    ['door', 'DMARC', 'La instrucción al portero', 'Le dice al correo del destinatario qué hacer si un mensaje con tu nombre no trae lista ni sello válidos: dejarlo pasar (none), mandarlo a spam (quarantine) o rechazarlo (reject). También te envía reportes de quién usa tu dominio.'],
    ['inbox', 'MX', 'Tu buzón de recepción', 'Indica qué servidores reciben el correo de tu dominio. Por eso sabemos si usas Microsoft 365, Google Workspace u otro proveedor.'],
    ['lock', 'MTA-STS', 'El sobre cerrado en el camino', 'Obliga a que el correo que te envían viaje cifrado, para que nadie en el camino pueda leerlo o desviarlo.'],
    ['shield', 'DNSSEC', 'El directorio con firma notarial', 'Firma las respuestas del DNS de tu dominio para que nadie pueda falsificarlas y desviar a tus visitantes o tu correo.'],
    ['badge', 'CAA', 'La lista de cerrajeros autorizados', 'Dice qué autoridades pueden emitir certificados HTTPS (el candado del navegador) para tu dominio.'],
    ['globe', 'BIMI', 'Tu logo en la bandeja', 'Permite mostrar tu logo junto a tus correos en algunos proveedores. Solo funciona si DMARC ya está en cuarentena o rechazo.'],
    ['alert', 'BEC', 'El fraude del falso jefe o proveedor', 'Business Email Compromise: un correo que se hace pasar por alguien de confianza para pedir una transferencia, un cambio de cuenta o datos. No necesita virus, solo credibilidad.'],
    ['hook', 'Suplantación', 'Usar tu nombre sin permiso', 'Enviar correos que aparentan venir de tu dominio exacto. SPF, DKIM y DMARC juntos la impiden, pero no protegen contra dominios parecidos.'],
  ];
  function renderGlossary() {
    $('glossary').replaceChildren(...GLOSSARY.map(([ic, term, short, body]) => fold(
      [h('span', { class: 'term-icon', 'aria-hidden': 'true' }, icon(ic)), h('span', { class: 'sum-text' }, h('span', { class: 'term-name', text: term }), h('span', { class: 'term-short', text: short }))],
      [h('p', { text: body })])));
  }

  function renderLegal() {
    const privacy = SITE.analytics
      ? 'Medimos visitas con Cloudflare Web Analytics, que según Cloudflare no usa cookies ni almacenamiento en tu navegador y no guarda tu dirección IP. Solo vemos totales: visitas, países y desde qué sitio llegaste. Nunca vemos qué dominio analizaste, porque el análisis no sale de tu navegador.'
      : 'Este sitio no usa cookies ni herramientas de seguimiento. El análisis no sale de tu navegador.';
    const folds = [
      ['scale', 'Ley 53-07 sobre Crímenes y Delitos de Alta Tecnología', 'Esta ley sanciona, entre otras conductas, el acceso no autorizado a sistemas y datos. Esta herramienta no accede a ningún sistema: consulta información que cada dominio publica en el DNS precisamente para que cualquier servidor de correo la lea. No enviamos correos, no probamos contraseñas y no escaneamos equipos.'],
      ['lock', 'Ley 172-13 de Protección de Datos Personales', 'No guardamos los dominios ni las direcciones que escribes: el análisis ocurre en tu navegador. Si escribes una dirección de correo, solo usamos la parte del dominio. Los registros DNS de una organización son información técnica pública, no datos de personas.'],
      ['shield', 'Divulgación responsable', 'El observatorio nunca publica qué organizaciones son suplantables. Cada organización puede pedir su informe privado por el contacto del pie. Si encuentras un fallo en esta herramienta, repórtalo de forma privada: el sitio publica un security.txt con el canal de contacto.'],
      ['chart', 'Privacidad y métricas de uso', privacy],
      ['info', 'Uso aceptable', 'Usa la herramienta para revisar tus propios dominios o los de organizaciones para las que trabajas. Si ves un problema en una organización ajena, avísale por sus canales oficiales en lugar de difundirlo. El resultado describe una configuración pública en un momento dado: no es una auditoría completa ni certifica la seguridad de nadie.'],
    ];
    $('legal-folds').replaceChildren(...folds.map(([ic, t, body]) => fold([icon(ic), h('span', { class: 'sum-text', text: t })], [h('p', { text: body })])));
  }

  function renderFaq() {
    const name = SITE.author && SITE.author.name ? SITE.author.name : 'el autor';
    const faq = [
      ['¿Guardan el dominio que escribo?', 'No. El análisis se hace en tu navegador, que consulta directamente los servidores DNS públicos de Cloudflare y Google. Este sitio no tiene una base de datos de consultas.'],
      ['¿Por qué dice que no encontró DKIM si lo tengo activo?', `DKIM no se puede listar desde fuera: hay que adivinar el nombre del selector. Probamos ${E.DKIM_SELECTORS.length} selectores comunes. Si tu proveedor usa uno propio, tu DKIM puede existir aunque no aparezca aquí.`],
      ['Si sale "Rechazado", ¿estoy protegido?', 'Contra la suplantación de tu dominio exacto, sí. No contra dominios parecidos, cuentas de correo robadas ni proveedores comprometidos. Por eso conviene confirmar por teléfono cualquier cambio de cuenta bancaria.'],
      ['¿Cuánto cuesta corregirlo?', 'Casi siempre no hace falta comprar nada: son registros DNS y ajustes en tu proveedor de correo. Lo que toma tiempo es hacerlo sin bloquear tu propio correo legítimo: de 4 a 8 semanas de forma gradual.'],
      ['¿Cada cuánto se actualiza el observatorio?', 'Cada día a medianoche (hora de República Dominicana), con los datos al cierre del día anterior. Solo se publican cifras agregadas.'],
      ['¿Quién está detrás de Suplanta.do?', `${name}, de forma independiente. No está afiliado a ningún proveedor de correo ni a ninguna entidad del Estado.`],
    ];
    $('faq').replaceChildren(...faq.map(([q, a]) => fold([h('span', { class: 'sum-text', text: q })], [h('p', { text: a })])));
  }

  function renderFooter() {
    const a = SITE.author || {};
    $('foot-author').replaceChildren(h('strong', { text: 'Suplanta.do' }), ` es un proyecto independiente de ${a.name}${a.title ? `, ${a.title}` : ''}${a.city ? `, ${a.city}` : ''}.`);
    const c = SITE.contact || {};
    const buttons = [];
    if (c.email) buttons.push(h('a', { class: 'btn', href: `mailto:${c.email}?subject=${encodeURIComponent('Informe de Suplanta.do')}` }, icon('mail'), 'Escribir un correo'));
    if (c.linkedin) buttons.push(h('a', { class: 'btn secondary', href: c.linkedin, target: '_blank', rel: 'noopener noreferrer' }, icon('badge'), 'LinkedIn'));
    if (c.github) buttons.push(h('a', { class: 'btn secondary', href: c.github, target: '_blank', rel: 'noopener noreferrer' }, icon('code'), 'GitHub'));
    $('contact').replaceChildren(
      h('p', null, h('strong', { text: '¿Tu dominio salió mal?' })),
      h('p', { text: `Corregirlo suele tomar días o semanas, no meses, y no requiere comprar productos. ${a.name} ofrece una revisión inicial sin costo para organizaciones dominicanas.` }),
      c.email ? h('p', null, 'Correo: ', h('span', { class: 'mono', text: c.email })) : null,
      buttons.length ? h('div', { class: 'actions' }, buttons) : null);
    $('foot-legal').textContent = `© ${new Date().getFullYear()} ${a.name}. Todos los derechos reservados. El código se publica para revisión, no para reutilización. Esto no es asesoría legal.`;
  }

  renderObservatory();
  renderGlossary();
  renderLegal();
  renderFaq();
  renderFooter();
})();
