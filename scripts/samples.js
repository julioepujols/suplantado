'use strict';
// Regenera data/samples.json: informes de ejemplo embebidos en la página.
// Dominios globales reales (datos públicos) y dos casos ficticios bajo el TLD
// reservado .example (RFC 2606). Requiere red. Uso: npm run samples
const fs = require('node:fs');
const path = require('node:path');
const E = require('../src/engine.js');

function mockResolver(zone) {
  let queries = 0;
  async function resolve(name, type) {
    queries++;
    const e = zone[`${name}|${type}`];
    if (!e) return { status: 'NXDOMAIN', ad: false, answers: [], cname: [] };
    return { status: 'NOERROR', ad: false, answers: e.map((d) => ({ data: d, ttl: 300 })), cname: [] };
  }
  async function txt(name) {
    const r = await resolve(name, 'TXT');
    return { ...r, records: r.answers.map((a) => E.parseTxtData(a.data)) };
  }
  return { resolve, txt, stats: () => ({ queries }) };
}

const fictional = {
  'colmado.example': {
    'colmado.example|NS': ['ns1.hosting.example.'],
    'colmado.example|SOA': ['ns1.hosting.example. admin. 1 2 3 4 5'],
    'colmado.example|MX': ['0 colmado-example.mail.protection.outlook.com.'],
    'colmado.example|TXT': ['"v=spf1 include:spf.protection.outlook.com include:servers.mcsv.net ?all"', '"MS=ms12345678"'],
    'spf.protection.outlook.com|TXT': ['"v=spf1 ip4:40.92.0.0/15 ip4:52.100.0.0/15 -all"'],
    'servers.mcsv.net|TXT': ['"v=spf1 ip4:205.201.128.0/20 -all"'],
  },
  'clinica.example': {
    'clinica.example|NS': ['ns1.hosting.example.'],
    'clinica.example|SOA': ['ns1.hosting.example. admin. 1 2 3 4 5'],
    'clinica.example|MX': ['1 aspmx.l.google.com.', '5 alt1.aspmx.l.google.com.'],
    'clinica.example|TXT': ['"v=spf1 include:_spf.google.com ~all"'],
    '_spf.google.com|TXT': ['"v=spf1 ip4:74.125.0.0/16 ip4:209.85.128.0/17 -all"'],
    '_dmarc.clinica.example|TXT': ['"v=DMARC1; p=quarantine; pct=50; rua=mailto:reportes@proveedor-dmarc.example"'],
    'google._domainkey.clinica.example|TXT': ['"v=DKIM1; k=rsa; p=' + 'M'.repeat(216) + '"'],
  },
};

(async () => {
  const samples = [];
  for (const domain of ['gmail.com', 'microsoft.com', 'paypal.com']) {
    const r = await E.analyzeDomain(domain, { fetchMtaStsPolicy: true });
    if (!r.ok) throw new Error(`${domain}: ${r.error}`);
    samples.push({ kind: 'real', report: r });
  }
  for (const [domain, zone] of Object.entries(fictional)) {
    const r = await E.analyzeDomain(domain, { resolver: mockResolver(zone) });
    if (!r.ok) throw new Error(`${domain}: ${r.error}`);
    samples.push({ kind: 'ficticio', report: r });
  }
  fs.writeFileSync(path.join(__dirname, '..', 'data', 'samples.json'), JSON.stringify(samples));
  for (const s of samples) console.log(s.report.domain, s.kind, s.report.verdict.level, s.report.score.grade, s.report.simulation.disposition);
})();
