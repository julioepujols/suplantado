'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const E = require('../src/engine.js');

function mockResolver(zone) {
  // zone: { 'name|TYPE': { status?, ad?, answers: [data...], cname?: [] } }
  let queries = 0;
  async function resolve(name, type) {
    queries++;
    const entry = zone[`${name.toLowerCase()}|${type}`];
    if (!entry) return { status: 'NXDOMAIN', ad: false, answers: [], cname: [] };
    return {
      status: entry.status || 'NOERROR',
      ad: Boolean(entry.ad),
      answers: (entry.answers || []).map((d) => ({ data: d, ttl: 300 })),
      cname: entry.cname || [],
    };
  }
  async function txt(name) {
    const r = await resolve(name, 'TXT');
    return { ...r, records: r.answers.map((a) => E.parseTxtData(a.data)) };
  }
  return { resolve, txt, stats: () => ({ queries }) };
}

const q = (s) => `"${s}"`;

function baseZone(domain, extra = {}) {
  return {
    [`${domain}|NS`]: { answers: ['ns1.example.net.'] },
    [`${domain}|SOA`]: { answers: ['ns1.example.net. host. 1 2 3 4 5'] },
    [`${domain}|MX`]: { answers: [`0 ${domain.replace(/\./g, '-')}.mail.protection.outlook.com.`] },
    ...extra,
  };
}

test('normalizeDomain acepta formas comunes y rechaza basura', () => {
  assert.equal(E.normalizeDomain('https://www.Empresa.com.do/contacto?x=1').domain, 'empresa.com.do');
  assert.equal(E.normalizeDomain('  juan.perez@Empresa.DO ').domain, 'empresa.do');
  assert.equal(E.normalizeDomain('empresa.do.').domain, 'empresa.do');
  assert.equal(E.normalizeDomain('ñandú.com').domain, 'xn--and-6ma2c.com');
  assert.equal(E.normalizeDomain('empresa.do:8443').domain, 'empresa.do');
  for (const bad of ['', '   ', 'localhost', '8.8.8.8', '<script>alert(1)</script>.com', 'a'.repeat(400), 'empresa.123', '-malo.com', 'a..b.com', null, 42]) {
    assert.equal(E.normalizeDomain(bad).ok, false, `debería rechazar ${String(bad).slice(0, 40)}`);
  }
});

test('organizationalDomain respeta sufijos de dos niveles', () => {
  assert.equal(E.organizationalDomain('correo.banco.com.do'), 'banco.com.do');
  assert.equal(E.organizationalDomain('mail.ministerio.gob.do'), 'ministerio.gob.do');
  assert.equal(E.organizationalDomain('a.b.empresa.com'), 'empresa.com');
  assert.equal(E.organizationalDomain('empresa.do'), 'empresa.do');
});

test('parseTxtData une cadenas partidas y decodifica escapes', () => {
  assert.equal(E.parseTxtData('"v=spf1 include:a.com" " -all"'), 'v=spf1 include:a.com -all');
  assert.equal(E.parseTxtData('"a\\"b" "c\\059d"'), 'a"bc;d');
  assert.equal(E.parseTxtData('v=DMARC1; p=none'), 'v=DMARC1; p=none');
  assert.equal(E.parseTxtData('"' + 'x'.repeat(10000) + '"').length, 4096);
});

test('parseSpf detecta errores de sintaxis', () => {
  const ok = E.parseSpf('v=spf1 ip4:192.0.2.0/24 include:_spf.google.com a/24 mx -all');
  assert.deepEqual(ok.errors, []);
  assert.equal(ok.terms.length, 5);
  assert.equal(ok.terms[2].value, '/24');
  assert.match(E.parseSpf('v=spf1 incluide:x.com -all').errors[0], /no reconocido/);
  assert.match(E.parseSpf('v=spf1 ip4:300.1.1.1 -all').errors[0], /ip4 inválida/);
  assert.match(E.parseSpf('spf1 -all').errors[0], /v=spf1/);
});

test('evaluateSpf: registro correcto y conteo de consultas', async () => {
  const dns = mockResolver({
    'empresa.do|TXT': { answers: [q('v=spf1 include:spf.protection.outlook.com -all')] },
    'spf.protection.outlook.com|TXT': { answers: [q('v=spf1 ip4:40.92.0.0/15 -all')] },
  });
  const r = await E.evaluateSpf('empresa.do', dns);
  assert.equal(r.status, 'ok');
  assert.equal(r.allQualifier, '-');
  assert.equal(r.lookups, 1);
});

test('evaluateSpf: más de 10 consultas es permerror', async () => {
  const zone = { 'empresa.do|TXT': { answers: [q('v=spf1 ' + Array.from({ length: 11 }, (_, i) => `include:p${i}.com`).join(' ') + ' -all')] } };
  for (let i = 0; i < 11; i++) zone[`p${i}.com|TXT`] = { answers: [q('v=spf1 ip4:192.0.2.1 -all')] };
  const r = await E.evaluateSpf('empresa.do', mockResolver(zone));
  assert.equal(r.status, 'permerror');
  assert.ok(r.issues.some((i) => i.code === 'spf-too-many-lookups'));
});

test('evaluateSpf: bucle de inclusiones no cuelga el motor', async () => {
  const dns = mockResolver({
    'a.com|TXT': { answers: [q('v=spf1 include:b.com -all')] },
    'b.com|TXT': { answers: [q('v=spf1 include:a.com -all')] },
  });
  const r = await E.evaluateSpf('a.com', dns);
  assert.equal(r.status, 'permerror');
  assert.ok(r.issues.some((i) => i.code === 'spf-loop'));
});

test('evaluateSpf: múltiples registros, +all, include inexistente y rango enorme', async () => {
  const multiple = await E.evaluateSpf('m.com', mockResolver({ 'm.com|TXT': { answers: [q('v=spf1 -all'), q('v=spf1 mx -all')] } }));
  assert.ok(multiple.issues.some((i) => i.code === 'spf-multiple'));

  const passAll = await E.evaluateSpf('p.com', mockResolver({ 'p.com|TXT': { answers: [q('v=spf1 +all')] } }));
  assert.ok(passAll.issues.some((i) => i.code === 'spf-pass-all' && i.severity === 'critical'));

  const missingInclude = await E.evaluateSpf('i.com', mockResolver({ 'i.com|TXT': { answers: [q('v=spf1 include:noexiste.com -all')] } }));
  assert.equal(missingInclude.status, 'permerror');

  const wide = await E.evaluateSpf('w.com', mockResolver({ 'w.com|TXT': { answers: [q('v=spf1 ip4:0.0.0.0/1 -all')] } }));
  assert.ok(wide.issues.some((i) => i.code === 'spf-wide-range'));
});

test('cidrContains', () => {
  assert.equal(E.cidrContains('203.0.113.0/24', '203.0.113.66'), true);
  assert.equal(E.cidrContains('198.51.100.0/24', '203.0.113.66'), false);
  assert.equal(E.cidrContains('0.0.0.0/0', '203.0.113.66'), true);
  assert.equal(E.cidrContains('203.0.113.66', '203.0.113.66'), true);
  assert.equal(E.cidrContains('bad/99', '203.0.113.66'), false);
});

test('parseDmarc valida etiquetas y marca obsoletas (RFC 9989)', () => {
  const ok = E.parseDmarc('v=DMARC1; p=reject; sp=reject; np=reject; rua=mailto:d@empresa.do');
  assert.deepEqual(ok.errors, []);
  const old = E.parseDmarc('v=DMARC1; p=quarantine; pct=50; rf=afrf');
  assert.deepEqual(old.obsolete, ['pct', 'rf']);
  assert.ok(E.parseDmarc('v=DMARC1; p=bloquear').errors.length);
  assert.ok(E.parseDmarc('p=reject; v=DMARC1').errors.length);
  assert.ok(E.parseDmarc('v=DMARC1; p=none; rua=empresa@x.com').warnings.length);
});

test('evaluateDmarc: ausente, none, reject y heredado', async () => {
  const none = await E.evaluateDmarc('a.do', mockResolver({}));
  assert.equal(none.present, false);
  assert.ok(none.issues.some((i) => i.code === 'dmarc-missing'));

  const monitor = await E.evaluateDmarc('b.do', mockResolver({ '_dmarc.b.do|TXT': { answers: [q('v=DMARC1; p=none; rua=mailto:x@b.do')] } }));
  assert.equal(monitor.appliedPolicy, 'none');

  const inherited = await E.evaluateDmarc('correo.c.com.do', mockResolver({ '_dmarc.c.com.do|TXT': { answers: [q('v=DMARC1; p=reject; sp=quarantine')] } }));
  assert.equal(inherited.inherited, true);
  assert.equal(inherited.foundAt, 'c.com.do');
  assert.equal(inherited.appliedPolicy, 'quarantine');

  const multiple = await E.evaluateDmarc('d.do', mockResolver({ '_dmarc.d.do|TXT': { answers: [q('v=DMARC1; p=reject'), q('v=DMARC1; p=none')] } }));
  assert.equal(multiple.present, false);
});

test('evaluateDmarc: reportes externos sin autorización', async () => {
  const dns = mockResolver({
    '_dmarc.e.do|TXT': { answers: [q('v=DMARC1; p=reject; rua=mailto:r@proveedor.com,mailto:yo@e.do')] },
  });
  const r = await E.evaluateDmarc('e.do', dns);
  assert.deepEqual(r.externalReports, [{ domain: 'proveedor.com', authorized: false }]);
  assert.ok(r.issues.some((i) => i.code === 'dmarc-rua-unauthorized'));
});

test('estimateDkimKey', () => {
  assert.equal(E.estimateDkimKey('v=DKIM1; k=rsa; p=' + 'A'.repeat(216)).bits, 1024);
  assert.equal(E.estimateDkimKey('v=DKIM1; k=rsa; p=' + 'A'.repeat(392)).bits, 2048);
  assert.equal(E.estimateDkimKey('v=DKIM1; p=').revoked, true);
  assert.equal(E.estimateDkimKey('v=DKIM1; k=ed25519; p=abc').keyType, 'ed25519');
});

test('parseCaa en formato genérico RFC 3597 y presentación', () => {
  // flags 0, tag "issue", value "letsencrypt.org"
  const hex = '00 05 69 73 73 75 65 6c 65 74 73 65 6e 63 72 79 70 74 2e 6f 72 67';
  assert.deepEqual(E.parseCaa(`\\# 22 ${hex}`), { flags: 0, tag: 'issue', value: 'letsencrypt.org' });
  assert.deepEqual(E.parseCaa('0 issue "digicert.com"'), { flags: 0, tag: 'issue', value: 'digicert.com' });
});

test('analyzeDomain: dominio sin DMARC es crítico y el simulador entrega el correo falso', async () => {
  const dns = mockResolver(baseZone('sinproteccion.do', {
    'sinproteccion.do|TXT': { answers: [q('v=spf1 include:spf.protection.outlook.com ~all')] },
    'spf.protection.outlook.com|TXT': { answers: [q('v=spf1 ip4:40.92.0.0/15 -all')] },
  }));
  const r = await E.analyzeDomain('sinproteccion.do', { resolver: dns });
  assert.equal(r.ok, true);
  assert.equal(r.mx.provider.id, 'm365');
  assert.equal(r.verdict.level, 'critical');
  assert.equal(r.simulation.disposition, 'delivered');
  assert.ok(r.score.total <= 35);
  assert.ok(r.remediation.some((x) => /DMARC/.test(x.title)));
});

test('analyzeDomain: reject con sp=reject es riesgo bajo y el correo falso se rechaza', async () => {
  const dns = mockResolver(baseZone('protegido.do', {
    'protegido.do|TXT': { answers: [q('v=spf1 include:spf.protection.outlook.com -all')] },
    'spf.protection.outlook.com|TXT': { answers: [q('v=spf1 ip4:40.92.0.0/15 -all')] },
    '_dmarc.protegido.do|TXT': { answers: [q('v=DMARC1; p=reject; sp=reject; rua=mailto:d@protegido.do')] },
    'selector1._domainkey.protegido.do|TXT': { answers: [q('v=DKIM1; k=rsa; p=' + 'A'.repeat(392))], cname: ['selector1-protegido-do._domainkey.x.onmicrosoft.com'] },
  }));
  const r = await E.analyzeDomain('protegido.do', { resolver: dns });
  assert.equal(r.verdict.level, 'low');
  assert.equal(r.simulation.disposition, 'rejected');
  assert.equal(r.subdomainSimulation.disposition, 'rejected');
  assert.equal(r.dkim.active, 1);
  assert.ok(r.score.total >= 80, `puntuación ${r.score.total}`);
});

test('analyzeDomain: +all hace que el correo falso pase DMARC', async () => {
  const dns = mockResolver(baseZone('abierto.do', {
    'abierto.do|TXT': { answers: [q('v=spf1 +all')] },
    '_dmarc.abierto.do|TXT': { answers: [q('v=DMARC1; p=reject')] },
  }));
  const r = await E.analyzeDomain('abierto.do', { resolver: dns });
  assert.equal(r.verdict.level, 'critical');
  assert.equal(r.simulation.disposition, 'delivered-pass');
});

test('analyzeDomain: sp=none deja subdominios suplantables', async () => {
  const dns = mockResolver(baseZone('mitad.do', {
    'mitad.do|TXT': { answers: [q('v=spf1 -all')] },
    '_dmarc.mitad.do|TXT': { answers: [q('v=DMARC1; p=reject; sp=none; rua=mailto:d@mitad.do')] },
  }));
  const r = await E.analyzeDomain('mitad.do', { resolver: dns });
  assert.equal(r.verdict.level, 'medium');
  assert.equal(r.simulation.disposition, 'rejected');
  assert.equal(r.subdomainSimulation.disposition, 'delivered');
});

test('analyzeDomain: modo prueba t=y rebaja reject a cuarentena', async () => {
  const dns = mockResolver(baseZone('prueba.do', {
    'prueba.do|TXT': { answers: [q('v=spf1 -all')] },
    '_dmarc.prueba.do|TXT': { answers: [q('v=DMARC1; p=reject; t=y')] },
  }));
  const r = await E.analyzeDomain('prueba.do', { resolver: dns });
  assert.equal(r.simulation.disposition, 'quarantine');
  assert.equal(r.verdict.level, 'medium');
});

test('analyzeDomain: dominio sin correo recibe receta de blindaje', async () => {
  const zone = baseZone('parqueado.do');
  delete zone['parqueado.do|MX'];
  const r = await E.analyzeDomain('parqueado.do', { resolver: mockResolver(zone) });
  assert.equal(r.mx.acceptsMail, false);
  assert.equal(r.remediation[0].title, 'Blindar un dominio que no envía correo');
  assert.ok(r.remediation[0].records.some((x) => x.value === 'v=spf1 -all'));
});

test('analyzeDomain: dominio inexistente y entrada inválida', async () => {
  const r = await E.analyzeDomain('noexiste-xyz.do', { resolver: mockResolver({}) });
  assert.equal(r.ok, false);
  assert.match(r.error, /no existe/);
  const bad = await E.analyzeDomain('javascript:alert(1)', { resolver: mockResolver({}) });
  assert.equal(bad.ok, false);
});

test('abuso: contenido hostil en registros se conserva como texto y no rompe el análisis', async () => {
  const hostile = '<img src=x onerror=alert(1)>';
  const dns = mockResolver(baseZone('hostil.do', {
    'hostil.do|TXT': { answers: [q(`v=spf1 include:${hostile} -all`)] },
    '_dmarc.hostil.do|TXT': { answers: [q(`v=DMARC1; p=${hostile}; rua=mailto:${hostile}`)] },
  }));
  const r = await E.analyzeDomain('hostil.do', { resolver: dns });
  assert.equal(r.ok, true);
  assert.equal(r.verdict.level, 'high');
  assert.ok(r.dmarc.record.includes(hostile));
});

test('resolver real: cae al segundo endpoint si el primero falla y cachea', async () => {
  const calls = [];
  const fakeFetch = async (url) => {
    calls.push(url);
    if (url.startsWith('https://primero')) throw new Error('caído');
    return { ok: true, json: async () => ({ Status: 0, AD: true, Answer: [{ type: 16, TTL: 60, data: '"v=spf1 -all"' }] }) };
  };
  const dns = E.createResolver({ endpoints: ['https://primero/q', 'https://segundo/q'], fetch: fakeFetch });
  const a = await dns.txt('x.do');
  const b = await dns.txt('x.do');
  assert.deepEqual(a.records, ['v=spf1 -all']);
  assert.equal(a.ad, true);
  assert.equal(b.records[0], 'v=spf1 -all');
  assert.equal(calls.length, 2);
});

test('remediación: conserva el rua existente y omite la fase de observación', async () => {
  const dns = mockResolver(baseZone('observa.do', {
    'observa.do|TXT': { answers: [q('v=spf1 include:spf.protection.outlook.com -all')] },
    'spf.protection.outlook.com|TXT': { answers: [q('v=spf1 ip4:40.92.0.0/15 -all')] },
    '_dmarc.observa.do|TXT': { answers: [q('v=DMARC1; p=none; rua=mailto:reportes@proveedor.example')] },
  }));
  const r = await E.analyzeDomain('observa.do', { resolver: dns });
  const plan = r.remediation.find((x) => x.phases);
  assert.ok(plan.phases.every((ph) => ph.value.includes('rua=mailto:reportes@proveedor.example')));
  assert.ok(!plan.phases.some((ph) => /p=none/.test(ph.value)));
  assert.match(plan.phases[plan.phases.length - 1].value, /p=reject; sp=reject; np=reject/);
});
