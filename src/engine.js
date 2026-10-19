/*
 * Suplanta.do — motor de análisis pasivo de autenticación de correo.
 * Solo consulta registros DNS públicos vía DNS-over-HTTPS. No envía correos,
 * no escanea puertos y no toca la infraestructura del dominio analizado.
 * Funciona igual en navegador y en Node >= 18 (fetch nativo).
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.SuplantaEngine = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const TYPE = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, DS: 43, CAA: 257 };

  const DOH_ENDPOINTS = [
    'https://cloudflare-dns.com/dns-query',
    'https://dns.google/resolve',
  ];

  const SPF_LOOKUP_LIMIT = 10;
  const SPF_VOID_LIMIT = 2;
  const MAX_TXT_LENGTH = 4096;
  const DMARC_WALK_LIMIT = 8;
  const RUA_CHECK_LIMIT = 4;

  // Sufijos públicos de dos niveles relevantes para la región. Se usa solo para
  // estimar el dominio organizacional cuando se analiza un subdominio.
  const MULTI_LABEL_SUFFIXES = new Set([
    'com.do', 'gob.do', 'gov.do', 'edu.do', 'org.do', 'net.do', 'mil.do', 'web.do', 'art.do', 'sld.do',
    'com.mx', 'gob.mx', 'edu.mx', 'org.mx', 'com.co', 'gov.co', 'edu.co', 'org.co', 'com.ar', 'gob.ar',
    'com.br', 'gov.br', 'com.pe', 'gob.pe', 'com.ve', 'gob.ve', 'com.ec', 'gob.ec', 'com.pa', 'gob.pa',
    'com.gt', 'gob.gt', 'com.hn', 'gob.hn', 'com.sv', 'gob.sv', 'co.cr', 'go.cr', 'com.pr', 'gov.pr',
    'com.uy', 'gub.uy', 'com.py', 'gov.py', 'com.bo', 'gob.bo', 'co.uk', 'org.uk', 'gov.uk', 'ac.uk',
    'com.es', 'com.au', 'co.jp', 'co.nz', 'com.cu', 'com.ni', 'gob.ni', 'com.ht', 'gouv.ht',
  ]);

  const DKIM_SELECTORS = [
    'selector1', 'selector2', 'google', 'default', 'dkim', 'mail', 'k1', 'k2', 'k3', 's1', 's2',
    'smtp', 'mx', 'zoho', 'zmail', 'mandrill', 'mxvault', 'everlytickey1', 'everlytickey2',
    'pm', 'sendgrid', 'smtpapi', 'amazonses', 'cm', 'sig1', 'protonmail', 'fm1', 'hs1', 'hs2', 'key1',
    'dkim1', 'mail1', 'ctct1', 'ctct2', 'mailjet', 'sm', 'brevo1', '20230601', '20221208', '20210112', '20161025',
  ];

  const MAIL_PROVIDERS = [
    { id: 'm365', name: 'Microsoft 365', mx: /\.mail\.protection\.outlook\.com$|\.mx\.microsoft$/ },
    { id: 'google', name: 'Google Workspace', mx: /(^|\.)(aspmx\.l\.google\.com|googlemail\.com|google\.com|smtp\.google\.com)$/ },
    { id: 'zoho', name: 'Zoho Mail', mx: /(^|\.)zoho(mail)?\.(com|eu|in)$/ },
    { id: 'proofpoint', name: 'Proofpoint', mx: /\.pphosted\.com$|\.ppe-hosted\.com$/ },
    { id: 'mimecast', name: 'Mimecast', mx: /\.mimecast\.(com|co\.za)$/ },
    { id: 'barracuda', name: 'Barracuda', mx: /\.barracudanetworks\.com$/ },
    { id: 'cisco', name: 'Cisco Secure Email', mx: /\.iphmx\.com$/ },
    { id: 'fortimail', name: 'FortiMail Cloud', mx: /\.fortimailcloud\.com$/ },
    { id: 'godaddy', name: 'GoDaddy', mx: /\.secureserver\.net$/ },
    { id: 'titan', name: 'Titan Email', mx: /\.titan\.email$/ },
    { id: 'hostinger', name: 'Hostinger', mx: /\.hostinger\.com$/ },
    { id: 'icloud', name: 'iCloud Mail', mx: /\.mail\.icloud\.com$/ },
    { id: 'outlookcom', name: 'Outlook.com (Microsoft, cuenta personal)', mx: /(^|\.)(pamx\d+\.)?hotmail\.com$|\.olc\.protection\.outlook\.com$/ },
    { id: 'yandex', name: 'Yandex', mx: /\.yandex\.(net|ru)$/ },
    { id: 'ovh', name: 'OVHcloud', mx: /\.ovh\.net$/ },
    { id: 'ionos', name: 'IONOS', mx: /\.(ionos|1and1)\.[a-z.]+$/ },
    { id: 'cpanel', name: 'Hosting compartido (cPanel)', mx: /^mail\./ },
  ];

  const SPF_PROVIDER_INCLUDE = {
    m365: 'include:spf.protection.outlook.com',
    google: 'include:_spf.google.com',
    zoho: 'include:zohomail.com',
    godaddy: 'include:secureserver.net',
    titan: 'include:spf.titan.email',
    hostinger: 'include:_spf.mail.hostinger.com',
    outlookcom: 'include:outlook.com',
  };

  // ---------------------------------------------------------------- utilidades

  function issue(severity, code, message) {
    return { severity, code, message };
  }

  function normalizeDomain(input) {
    if (typeof input !== 'string') return { ok: false, error: 'Escribe un dominio.' };
    let s = input.trim().toLowerCase();
    if (!s) return { ok: false, error: 'Escribe un dominio.' };
    if (s.length > 320) return { ok: false, error: 'El texto es demasiado largo para ser un dominio.' };
    if (s.includes('@')) s = s.slice(s.lastIndexOf('@') + 1);
    s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
    s = s.split(/[/?#\s]/)[0];
    s = s.replace(/:\d+$/, '').replace(/\.+$/, '');
    if (s.startsWith('www.')) s = s.slice(4);
    let host;
    try {
      host = new URL('http://' + s).hostname;
    } catch (_) {
      return { ok: false, error: 'Eso no parece un dominio válido.' };
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[')) {
      return { ok: false, error: 'Escribe un dominio, no una dirección IP.' };
    }
    const labels = host.split('.');
    const validLabel = (l) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l);
    if (host.length > 253 || labels.length < 2 || !labels.every(validLabel)) {
      return { ok: false, error: 'Eso no parece un dominio válido.' };
    }
    const tld = labels[labels.length - 1];
    if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.test(tld)) {
      return { ok: false, error: 'La extensión del dominio no es válida.' };
    }
    return { ok: true, domain: host };
  }

  // Segundos niveles genéricos bajo un ccTLD (com.sg, co.za, gov.in...). Aproximación
  // mientras no se incluya una copia de la Public Suffix List.
  const CCTLD_GENERIC_SLD = new Set(['com', 'co', 'net', 'org', 'gov', 'gob', 'edu', 'ac', 'or', 'ne', 'go', 'mil', 'gouv', 'gub', 'nic']);

  function isMultiLabelSuffix(lastTwo) {
    if (MULTI_LABEL_SUFFIXES.has(lastTwo)) return true;
    const [sld, tld] = lastTwo.split('.');
    return tld.length === 2 && CCTLD_GENERIC_SLD.has(sld);
  }

  function organizationalDomain(domain) {
    const labels = domain.split('.');
    if (labels.length <= 2) return domain;
    const lastTwo = labels.slice(-2).join('.');
    const take = isMultiLabelSuffix(lastTwo) ? 3 : 2;
    return labels.slice(-take).join('.');
  }

  function parseTxtData(data) {
    if (typeof data !== 'string') return '';
    const s = data.trim();
    if (!s.startsWith('"')) return s.slice(0, MAX_TXT_LENGTH);
    let out = '';
    let i = 0;
    while (i < s.length && out.length < MAX_TXT_LENGTH) {
      if (s[i] !== '"') { i++; continue; }
      i++;
      while (i < s.length && s[i] !== '"' && out.length < MAX_TXT_LENGTH) {
        if (s[i] === '\\' && i + 1 < s.length) {
          const dec = /^\d{3}/.exec(s.slice(i + 1, i + 4));
          if (dec) { out += String.fromCharCode(Number(dec[0])); i += 4; continue; }
          out += s[i + 1]; i += 2; continue;
        }
        out += s[i++];
      }
      i++;
    }
    return out.slice(0, MAX_TXT_LENGTH);
  }

  function decodeGenericRdata(data) {
    // RFC 3597: "\# <len> <hex...>"
    const m = /^\\#\s+(\d+)((?:\s+[0-9a-fA-F]{2})*)\s*$/.exec(data.trim());
    if (!m) return null;
    const hex = m[2].replace(/\s+/g, '');
    const bytes = [];
    for (let i = 0; i + 1 < hex.length; i += 2) bytes.push(parseInt(hex.slice(i, i + 2), 16));
    return bytes;
  }

  function parseCaa(data) {
    const bytes = decodeGenericRdata(data);
    if (bytes) {
      if (bytes.length < 2) return null;
      const flags = bytes[0];
      const tagLen = bytes[1];
      const tag = String.fromCharCode(...bytes.slice(2, 2 + tagLen));
      const value = String.fromCharCode(...bytes.slice(2 + tagLen));
      return { flags, tag: tag.toLowerCase(), value };
    }
    const m = /^(\d+)\s+(\S+)\s+"?(.*?)"?$/.exec(data.trim());
    return m ? { flags: Number(m[1]), tag: m[2].toLowerCase(), value: m[3] } : null;
  }

  function parseMx(data) {
    const m = /^(\d+)\s+(\S+)$/.exec(String(data).trim());
    if (!m) return null;
    return { preference: Number(m[1]), host: m[2].replace(/\.$/, '').toLowerCase() };
  }

  function ipv4ToInt(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return null;
    let n = 0;
    for (const p of parts) {
      if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return null;
      n = n * 256 + Number(p);
    }
    return n;
  }

  function cidrContains(cidr, ip) {
    const [base, bitsStr] = cidr.split('/');
    const bits = bitsStr === undefined ? 32 : Number(bitsStr);
    const b = ipv4ToInt(base);
    const t = ipv4ToInt(ip);
    if (b === null || t === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
    if (bits === 0) return true;
    const size = 2 ** (32 - bits);
    return Math.floor(b / size) === Math.floor(t / size);
  }

  // ------------------------------------------------------------------ resolver

  function createResolver(options = {}) {
    const endpoints = options.endpoints || DOH_ENDPOINTS;
    const fetchImpl = options.fetch || (typeof fetch !== 'undefined' ? fetch.bind(globalThis) : null);
    const timeoutMs = options.timeoutMs || 6000;
    const maxConcurrent = options.concurrency || 6;
    const maxQueries = options.maxQueries || 150;
    if (!fetchImpl) throw new Error('fetch no disponible');

    const cache = new Map();
    let active = 0;
    const waiting = [];
    let queries = 0;

    async function withSlot(fn) {
      if (active >= maxConcurrent) await new Promise((r) => waiting.push(r));
      active++;
      try { return await fn(); } finally {
        active--;
        const next = waiting.shift();
        if (next) next();
      }
    }

    async function queryEndpoint(endpoint, name, type) {
      const url = `${endpoint}?name=${encodeURIComponent(name)}&type=${type}`;
      const ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
      const timer = ctrl ? setTimeout(() => ctrl.abort(), timeoutMs) : null;
      try {
        const res = await fetchImpl(url, {
          headers: { accept: 'application/dns-json' },
          signal: ctrl ? ctrl.signal : undefined,
          credentials: 'omit',
          referrerPolicy: 'no-referrer',
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
      } finally {
        if (timer) clearTimeout(timer);
      }
    }

    async function resolve(name, typeName) {
      const type = TYPE[typeName];
      if (!type) throw new Error(`Tipo DNS no soportado: ${typeName}`);
      const key = `${name.toLowerCase()}|${type}`;
      if (cache.has(key)) return cache.get(key);
      if (cache.size >= maxQueries) {
        return { status: 'ERROR', ad: false, answers: [], cname: [], error: 'límite de consultas alcanzado' };
      }
      const p = withSlot(async () => {
        let lastError = null;
        for (const endpoint of endpoints) {
          try {
            queries++;
            const json = await queryEndpoint(endpoint, name, type);
            if (json.Status === 2 && endpoint !== endpoints[endpoints.length - 1]) {
              lastError = new Error('SERVFAIL');
              continue;
            }
            const answers = Array.isArray(json.Answer) ? json.Answer : [];
            return {
              status: json.Status === 0 ? 'NOERROR' : json.Status === 3 ? 'NXDOMAIN' : json.Status === 2 ? 'SERVFAIL' : `RCODE${json.Status}`,
              ad: json.AD === true,
              answers: answers.filter((a) => a.type === type).map((a) => ({ data: String(a.data), ttl: a.TTL })),
              cname: answers.filter((a) => a.type === TYPE.CNAME).map((a) => String(a.data).replace(/\.$/, '')),
            };
          } catch (err) {
            lastError = err;
          }
        }
        return { status: 'ERROR', ad: false, answers: [], cname: [], error: lastError ? String(lastError.message || lastError) : 'error' };
      });
      cache.set(key, p);
      return p;
    }

    async function txt(name) {
      const r = await resolve(name, 'TXT');
      return { ...r, records: r.answers.map((a) => parseTxtData(a.data)) };
    }

    return { resolve, txt, stats: () => ({ queries, cached: cache.size }) };
  }

  // ----------------------------------------------------------------------- SPF

  const SPF_MECH_RE = /^([+\-~?]?)(all|include|a|mx|ptr|ip4|ip6|exists)(?:([:/])(.*))?$/i;
  const SPF_MOD_RE = /^([a-z][a-z0-9_.-]*)=(.*)$/i;

  function parseSpf(record) {
    const result = { terms: [], modifiers: {}, errors: [] };
    const tokens = record.trim().split(/\s+/);
    if (!/^v=spf1$/i.test(tokens[0] || '')) {
      result.errors.push('El registro no empieza con "v=spf1".');
      return result;
    }
    for (const token of tokens.slice(1)) {
      const mod = SPF_MOD_RE.exec(token);
      if (mod && !SPF_MECH_RE.test(token)) {
        const name = mod[1].toLowerCase();
        if (name in result.modifiers) result.errors.push(`El modificador "${name}" aparece más de una vez.`);
        result.modifiers[name] = mod[2];
        continue;
      }
      const m = SPF_MECH_RE.exec(token);
      if (!m) {
        result.errors.push(`Término no reconocido: "${token}".`);
        continue;
      }
      const mechanism = m[2].toLowerCase();
      let value = m[4] === undefined ? '' : m[4];
      if (m[3] === '/') value = '/' + value;
      if (mechanism === 'all' && m[3]) result.errors.push('"all" no admite argumentos.');
      if ((mechanism === 'include' || mechanism === 'exists') && !value) {
        result.errors.push(`"${mechanism}" requiere un dominio.`);
      }
      if ((mechanism === 'ip4' || mechanism === 'ip6') && !value) {
        result.errors.push(`"${mechanism}" requiere una dirección.`);
      }
      if (mechanism === 'ip4' && value) {
        const [ip, bits] = value.split('/');
        if (ipv4ToInt(ip) === null || (bits !== undefined && !(Number(bits) >= 0 && Number(bits) <= 32 && /^\d+$/.test(bits)))) {
          result.errors.push(`Dirección ip4 inválida: "${value}".`);
        }
      }
      result.terms.push({ qualifier: m[1] || '+', mechanism, value });
    }
    return result;
  }

  function effectiveAll(node) {
    let n = node;
    while (n && !(n.terms || []).some((t) => t.mechanism === 'all')) n = (n.children || []).find((c) => c.viaRedirect);
    const all = n && n.terms.find((t) => t.mechanism === 'all');
    return all ? all.qualifier : null;
  }

  async function evaluateSpf(domain, dns) {
    const state = { lookups: 0, voids: 0, issues: [], ip4: [], ip6: [], openVia: [], exceeded: false };

    async function expand(name, depth, chain) {
      const node = { domain: name, record: null, terms: [], children: [], error: null };
      const res = await dns.txt(name);
      if (res.status === 'ERROR' || res.status === 'SERVFAIL') {
        node.error = 'temperror';
        return node;
      }
      const spfRecords = res.records.filter((r) => /^v=spf1(\s|$)/i.test(r));
      if (spfRecords.length === 0) {
        node.error = res.status === 'NXDOMAIN' ? 'nxdomain' : 'none';
        return node;
      }
      if (spfRecords.length > 1) {
        node.error = 'multiple';
        node.record = spfRecords.join(' | ');
        return node;
      }
      node.record = spfRecords[0];
      const parsed = parseSpf(node.record);
      node.terms = parsed.terms;
      node.modifiers = parsed.modifiers;
      if (parsed.errors.length) node.syntaxErrors = parsed.errors;

      for (const term of parsed.terms) {
        if (term.mechanism === 'ip4') state.ip4.push({ cidr: term.value, qualifier: term.qualifier, via: name });
        if (term.mechanism === 'ip6') state.ip6.push({ cidr: term.value, qualifier: term.qualifier, via: name });
        if (!['include', 'a', 'mx', 'ptr', 'exists'].includes(term.mechanism)) continue;
        state.lookups++;
        if (state.lookups > SPF_LOOKUP_LIMIT) { state.exceeded = true; continue; }
        const target = term.value && !term.value.startsWith('/') ? term.value.split('/')[0] : name;
        if (target.includes('%')) continue;
        if (term.mechanism === 'include') {
          if (chain.includes(target.toLowerCase())) {
            node.children.push({ domain: target, error: 'loop', terms: [], children: [] });
            continue;
          }
          const child = await expand(target, depth + 1, chain.concat(target.toLowerCase()));
          if (child.error === 'none' || child.error === 'nxdomain') state.voids++;
          if (term.qualifier === '+' && effectiveAll(child) === '+') state.openVia.push(`include:${target}`);
          node.children.push(child);
        } else if (term.mechanism === 'a' || term.mechanism === 'mx') {
          const r = await dns.resolve(target, term.mechanism === 'a' ? 'A' : 'MX');
          if (r.status === 'NXDOMAIN' || (r.status === 'NOERROR' && r.answers.length === 0)) state.voids++;
        } else if (term.mechanism === 'exists' && term.qualifier === '+') {
          const r = await dns.resolve(target, 'A');
          if (r.answers.length) state.openVia.push(`exists:${target}`);
        }
      }

      const redirect = parsed.modifiers.redirect;
      const hasAll = parsed.terms.some((t) => t.mechanism === 'all');
      if (redirect && !hasAll) {
        state.lookups++;
        if (state.lookups > SPF_LOOKUP_LIMIT) state.exceeded = true;
        else if (!chain.includes(redirect.toLowerCase())) {
          const child = await expand(redirect, depth + 1, chain.concat(redirect.toLowerCase()));
          child.viaRedirect = true;
          if (child.error === 'none' || child.error === 'nxdomain') state.voids++;
          node.children.push(child);
        }
      }
      return node;
    }

    const tree = await expand(domain, 0, [domain.toLowerCase()]);
    const out = {
      present: Boolean(tree.record) && tree.error !== 'multiple',
      record: tree.record,
      tree,
      lookups: state.lookups,
      voidLookups: state.voids,
      allQualifier: null,
      ip4: state.ip4,
      issues: state.issues,
      status: 'ok',
    };

    if (tree.error === 'temperror') {
      out.status = 'temperror';
      out.issues.push(issue('warn', 'spf-temperror', 'No se pudo consultar el SPF (error temporal de DNS).'));
      return out;
    }
    if (tree.error === 'none' || tree.error === 'nxdomain') {
      out.status = 'none';
      out.issues.push(issue('high', 'spf-missing', 'No hay registro SPF: ningún receptor sabe qué servidores pueden enviar correo de este dominio.'));
      return out;
    }
    if (tree.error === 'multiple') {
      out.status = 'permerror';
      out.issues.push(issue('high', 'spf-multiple', 'Hay más de un registro SPF. El estándar exige uno solo; los receptores tratan esto como error y el SPF deja de funcionar.'));
      return out;
    }

    (function collectSyntax(node) {
      if (node.syntaxErrors) {
        for (const e of node.syntaxErrors) out.issues.push(issue('high', 'spf-syntax', `Error de sintaxis en el SPF de ${node.domain}: ${e}`));
      }
      if (node.error === 'loop') out.issues.push(issue('high', 'spf-loop', `Inclusión circular detectada en ${node.domain}.`));
      if (node.error === 'multiple') out.issues.push(issue('high', 'spf-include-multiple', `El dominio incluido ${node.domain} tiene más de un SPF.`));
      if ((node.error === 'none' || node.error === 'nxdomain') && node !== tree) {
        out.issues.push(issue('high', 'spf-include-missing', `El SPF incluye ${node.domain}, pero ese dominio no publica SPF. Esto provoca un error permanente.`));
      }
      (node.children || []).forEach(collectSyntax);
    })(tree);

    out.allQualifier = effectiveAll(tree);

    if (state.exceeded || state.lookups > SPF_LOOKUP_LIMIT) {
      out.status = 'permerror';
      out.issues.push(issue('high', 'spf-too-many-lookups', `El SPF requiere ${state.lookups} consultas DNS; el límite es ${SPF_LOOKUP_LIMIT}. Los receptores lo marcan como error permanente y el SPF deja de proteger.`));
    } else if (state.lookups >= 8) {
      out.issues.push(issue('warn', 'spf-near-limit', `El SPF usa ${state.lookups} de ${SPF_LOOKUP_LIMIT} consultas DNS permitidas. Agregar otro proveedor podría romperlo.`));
    }
    if (state.voids > SPF_VOID_LIMIT) {
      out.status = 'permerror';
      out.issues.push(issue('high', 'spf-void-lookups', `El SPF tiene ${state.voids} consultas vacías; más de ${SPF_VOID_LIMIT} provoca error permanente.`));
    }
    if (out.issues.some((i) => i.code === 'spf-syntax' || i.code === 'spf-loop' || i.code === 'spf-include-missing')) {
      out.status = 'permerror';
    }

    if (out.allQualifier === '+') {
      out.issues.push(issue('critical', 'spf-pass-all', 'El SPF termina en "+all": autoriza a CUALQUIER servidor del mundo a enviar correo como este dominio.'));
    } else if (out.allQualifier === '?') {
      out.issues.push(issue('high', 'spf-neutral-all', 'El SPF termina en "?all" (neutral): no le dice al receptor que rechace a remitentes no autorizados.'));
    } else if (out.allQualifier === null) {
      out.issues.push(issue('high', 'spf-no-all', 'El SPF no termina en "all": los servidores no listados quedan en estado neutral.'));
    } else if (out.allQualifier === '~') {
      out.issues.push(issue('info', 'spf-softfail', 'El SPF termina en "~all" (softfail). Es correcto mientras DMARC haga cumplir la política.'));
    }
    if (tree.terms.some((t) => t.mechanism === 'ptr')) {
      out.issues.push(issue('warn', 'spf-ptr', 'El SPF usa "ptr", mecanismo desaconsejado por el estándar (lento y poco fiable).'));
    }
    const wideOpen = state.ip4.find((e) => {
      const bits = Number((e.cidr.split('/')[1]) ?? 32);
      return e.qualifier === '+' && bits <= 8;
    });
    if (wideOpen) {
      out.issues.push(issue('critical', 'spf-wide-range', `El SPF autoriza el rango ${wideOpen.cidr} (vía ${wideOpen.via}): millones de direcciones pueden enviar como este dominio.`));
    }
    const wideOpen6 = state.ip6.find((e) => e.qualifier === '+' && Number(e.cidr.split('/')[1] ?? 128) <= 32);
    if (wideOpen6) {
      out.issues.push(issue('critical', 'spf-wide-range', `El SPF autoriza el rango IPv6 ${wideOpen6.cidr} (vía ${wideOpen6.via}): cualquier servidor de ese bloque puede enviar como este dominio.`));
    }
    if (state.openVia.length) {
      out.issues.push(issue('critical', 'spf-pass-all-indirect', `El SPF autoriza a cualquier servidor a través de ${state.openVia.join(', ')}.`));
    }
    const syntaxBroken = out.issues.some((i) => i.code === 'spf-syntax');
    out.openToAll = !syntaxBroken && (out.allQualifier === '+' || out.issues.some((i) => i.code === 'spf-wide-range' || i.code === 'spf-pass-all-indirect'));
    if (tree.record && tree.record.length > 450) {
      out.issues.push(issue('warn', 'spf-long', 'El SPF es muy largo (más de 450 caracteres); algunos resolvers podrían truncarlo.'));
    }
    return out;
  }

  function spfMatchesIp(spf, ip) {
    return spf.ip4.some((e) => e.qualifier === '+' && cidrContains(e.cidr, ip));
  }

  // --------------------------------------------------------------------- DMARC

  const DMARC_POLICIES = ['none', 'quarantine', 'reject'];
  const DMARC_VERSION_RE = /^v[ \t]*=[ \t]*DMARC1[ \t]*(;|$)/;

  function parseDmarc(record) {
    const out = { tags: {}, errors: [], warnings: [], obsolete: [] };
    const parts = record.split(';').map((p) => p.trim()).filter(Boolean);
    if (!parts.length || !DMARC_VERSION_RE.test(record)) {
      out.errors.push('El registro debe empezar exactamente con "v=DMARC1".');
      return out;
    }
    for (const part of parts) {
      const eq = part.indexOf('=');
      if (eq < 1) { out.errors.push(`Etiqueta mal formada: "${part}".`); continue; }
      const tag = part.slice(0, eq).trim().toLowerCase();
      const value = part.slice(eq + 1).trim();
      if (tag in out.tags) out.warnings.push(`La etiqueta "${tag}" está repetida; se usa la primera.`);
      else out.tags[tag] = value;
    }
    const t = out.tags;
    const checkPolicy = (tag) => {
      if (t[tag] !== undefined && !DMARC_POLICIES.includes(t[tag].toLowerCase())) {
        out.errors.push(`Valor inválido para "${tag}": "${t[tag]}".`);
      }
    };
    checkPolicy('p'); checkPolicy('sp'); checkPolicy('np');
    if (t.p === undefined) out.errors.push('Falta la etiqueta obligatoria "p" (política).');
    for (const tag of ['adkim', 'aspf']) {
      if (t[tag] !== undefined && !/^[rs]$/i.test(t[tag])) out.errors.push(`Valor inválido para "${tag}": "${t[tag]}".`);
    }
    if (t.t !== undefined && !/^[yn]$/i.test(t.t)) out.errors.push(`Valor inválido para "t": "${t.t}".`);
    if (t.psd !== undefined && !/^[ynu]$/i.test(t.psd)) out.errors.push(`Valor inválido para "psd": "${t.psd}".`);
    if (t.pct !== undefined) {
      out.obsolete.push('pct');
      if (!/^\d{1,3}$/.test(t.pct) || Number(t.pct) > 100) out.errors.push(`Valor inválido para "pct": "${t.pct}".`);
    }
    for (const tag of ['rf', 'ri']) if (t[tag] !== undefined) out.obsolete.push(tag);
    for (const tag of ['rua', 'ruf']) {
      if (t[tag] === undefined) continue;
      for (const uri of t[tag].split(',').map((u) => u.trim()).filter(Boolean)) {
        if (!/^mailto:[^@\s]+@[a-z0-9.-]+\.[a-z]{2,}(!\d+[kmgt]?)?$/i.test(uri)) {
          out.warnings.push(`Dirección de reporte "${tag}" no válida: "${uri}".`);
        }
      }
    }
    const known = new Set(['v', 'p', 'sp', 'np', 'psd', 't', 'adkim', 'aspf', 'rua', 'ruf', 'fo', 'pct', 'rf', 'ri']);
    for (const tag of Object.keys(t)) if (!known.has(tag)) out.warnings.push(`Etiqueta desconocida: "${tag}".`);
    return out;
  }

  function reportDomains(tags) {
    if (!tags.rua) return [];
    return tags.rua.split(',').map((u) => u.trim())
      .map((u) => /^mailto:[^@]+@([a-z0-9.-]+)/i.exec(u))
      .filter(Boolean).map((m) => m[1].toLowerCase());
  }

  async function evaluateDmarc(domain, dns) {
    const out = { present: false, record: null, foundAt: null, inherited: false, tags: {}, policy: null, appliedPolicy: null, subdomainPolicy: null, nonexistentPolicy: null, testing: false, partial: false, reporting: false, issues: [], externalReports: [] };
    const orgDomain = organizationalDomain(domain);
    const candidates = [domain];
    let cursor = domain;
    while (cursor !== orgDomain && cursor.includes('.') && candidates.length < DMARC_WALK_LIMIT) {
      cursor = cursor.slice(cursor.indexOf('.') + 1);
      candidates.push(cursor);
    }

    let records = [];
    let foundAt = null;
    for (const candidate of candidates) {
      const res = await dns.txt(`_dmarc.${candidate}`);
      if (res.status === 'ERROR' || res.status === 'SERVFAIL') {
        out.issues.push(issue('warn', 'dmarc-temperror', 'No se pudo consultar DMARC (error temporal de DNS).'));
        out.status = 'temperror';
        return out;
      }
      records = res.records.filter((r) => DMARC_VERSION_RE.test(r));
      if (records.length) { foundAt = candidate; break; }
    }

    if (!records.length) {
      out.status = 'none';
      out.issues.push(issue('critical', 'dmarc-missing', 'No hay DMARC: los receptores no tienen instrucciones para rechazar correos falsos que usen este dominio.'));
      return out;
    }
    if (records.length > 1) {
      out.status = 'permerror';
      out.record = records.join(' | ');
      out.foundAt = foundAt;
      out.issues.push(issue('critical', 'dmarc-multiple', 'Hay más de un registro DMARC. El estándar indica ignorarlos todos: en la práctica, no hay DMARC.'));
      return out;
    }

    out.present = true;
    out.record = records[0];
    out.foundAt = foundAt;
    out.inherited = foundAt !== domain;
    const parsed = parseDmarc(out.record);
    out.tags = parsed.tags;
    out.parseErrors = parsed.errors;

    const t = parsed.tags;
    const validPolicy = (v) => (v && DMARC_POLICIES.includes(v.toLowerCase()) ? v.toLowerCase() : null);
    let p = validPolicy(t.p);
    if (!p) {
      p = 'none';
      out.issues.push(issue('critical', 'dmarc-invalid-policy', 'La política DMARC falta o es inválida; los receptores la tratan como "none" (no hacer nada).'));
    }
    out.policy = p;
    out.subdomainPolicy = validPolicy(t.sp) || p;
    out.nonexistentPolicy = validPolicy(t.np) || out.subdomainPolicy;
    out.testing = (t.t || '').toLowerCase() === 'y';
    out.partial = t.pct !== undefined && Number(t.pct) < 100;
    out.reporting = Boolean(t.rua);
    out.appliedPolicy = out.inherited ? out.subdomainPolicy : p;

    for (const e of parsed.errors) if (!/"p"/.test(e)) out.issues.push(issue('high', 'dmarc-syntax', `Error en DMARC: ${e}`));
    for (const w of parsed.warnings) out.issues.push(issue('warn', 'dmarc-warning', `DMARC: ${w}`));
    if (parsed.obsolete.length) {
      out.issues.push(issue('info', 'dmarc-obsolete', `DMARC usa etiquetas eliminadas en el estándar actual (RFC 9989): ${parsed.obsolete.join(', ')}. Siguen siendo toleradas, pero conviene migrar.`));
    }

    const applied = out.appliedPolicy;
    if (applied === 'none') {
      out.issues.push(issue('critical', 'dmarc-none', 'La política DMARC es "none": solo monitorea. Un correo falso con este dominio NO es rechazado ni enviado a spam por DMARC.'));
    } else if (applied === 'quarantine') {
      out.issues.push(issue('warn', 'dmarc-quarantine', 'La política DMARC es "quarantine": los correos falsos van a spam, pero aún pueden ser abiertos por la víctima.'));
    }
    if (out.testing) {
      out.issues.push(issue('high', 'dmarc-testing', 'DMARC está en modo de prueba (t=y): los receptores aplican una política un nivel más suave.'));
    }
    if (out.partial) {
      out.issues.push(issue('high', 'dmarc-partial', `DMARC solo se aplica al ${t.pct}% de los correos (pct=${t.pct}); el resto recibe una política más suave.`));
    }
    if (applied !== 'none' && out.subdomainPolicy === 'none') {
      out.issues.push(issue('high', 'dmarc-sp-none', 'La política para subdominios es "none" (sp=none): un atacante puede suplantar cualquier subdominio, por ejemplo pagos.' + organizationalDomain(domain) + '.'));
    }
    if (!out.reporting) {
      out.issues.push(issue('warn', 'dmarc-no-rua', 'DMARC no pide reportes (falta "rua"): nadie se entera de quién envía correo usando este dominio.'));
    }

    const org = organizationalDomain(foundAt);
    const external = [...new Set(reportDomains(t))].filter((rd) => organizationalDomain(rd) !== org);
    if (external.length > RUA_CHECK_LIMIT) {
      out.issues.push(issue('warn', 'dmarc-rua-too-many', `DMARC declara ${external.length} destinos externos de reportes; solo verificamos los primeros ${RUA_CHECK_LIMIT}.`));
    }
    const checks = await Promise.all(external.slice(0, RUA_CHECK_LIMIT).map(async (rd) => {
      const check = await dns.txt(`${foundAt}._report._dmarc.${rd}`);
      return { rd, check, authorized: check.records.some((r) => DMARC_VERSION_RE.test(r)) };
    }));
    for (const { rd, check, authorized } of checks) {
      out.externalReports.push({ domain: rd, authorized });
      if (!authorized && check.status !== 'ERROR') {
        out.issues.push(issue('warn', 'dmarc-rua-unauthorized', `Los reportes DMARC van a ${rd}, pero ese dominio no publica la autorización requerida; muchos receptores no enviarán los reportes.`));
      }
    }
    out.status = 'ok';
    return out;
  }

  // ---------------------------------------------------------------------- DKIM

  function estimateDkimKey(record) {
    const tags = {};
    for (const part of record.split(';')) {
      const eq = part.indexOf('=');
      if (eq > 0) tags[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1).replace(/\s+/g, '');
    }
    const keyType = (tags.k || 'rsa').toLowerCase();
    const p = tags.p;
    if (p === undefined) return { keyType, bits: null, revoked: false, valid: false };
    if (p === '') return { keyType, bits: null, revoked: true, valid: true };
    if (keyType === 'ed25519') return { keyType, bits: 256, revoked: false, valid: true };
    const bytes = Math.floor((p.replace(/=+$/, '').length * 3) / 4);
    let bits;
    if (bytes < 120) bits = 512;
    else if (bytes < 200) bits = 1024;
    else if (bytes < 330) bits = 2048;
    else if (bytes < 600) bits = 4096;
    else bits = 8192;
    return { keyType, bits, revoked: false, valid: true };
  }

  async function evaluateDkim(domain, dns, selectors = DKIM_SELECTORS) {
    const found = [];
    const pendingCname = [];
    await Promise.all(selectors.map(async (sel) => {
      const res = await dns.txt(`${sel}._domainkey.${domain}`);
      const rec = res.records.find((r) => /(^|;)\s*(v=DKIM1|k=|p=)/i.test(r));
      if (rec) found.push({ selector: sel, ...estimateDkimKey(rec), via: res.cname[0] || null });
      else if (res.cname.length) pendingCname.push({ selector: sel, target: res.cname[res.cname.length - 1] });
    }));
    found.sort((a, b) => a.selector.localeCompare(b.selector));
    const wildcard = pendingCname.length > 4 && new Set(pendingCname.map((c) => c.target)).size === 1;
    if (wildcard) pendingCname.length = 0;
    const issues = [];
    const active = found.filter((k) => !k.revoked && k.valid);
    if (!active.length) {
      issues.push(issue('warn', 'dkim-not-found', 'No encontramos claves DKIM en los selectores más comunes. Puede usar un selector personalizado, pero si no firma, los correos legítimos son más fáciles de falsificar y de marcar como spam.'));
    }
    const weak = active.filter((k) => k.bits !== null && k.bits < 2048 && k.keyType === 'rsa');
    if (weak.length) {
      const list = weak.map((k) => `"${k.selector}" (~${k.bits} bits)`).join(', ');
      issues.push(issue('warn', 'dkim-weak', `Claves DKIM débiles: ${list}. Se recomienda 2048 bits como mínimo.`));
    }
    for (const c of pendingCname) {
      issues.push(issue('info', 'dkim-cname-pending', `El selector "${c.selector}" apunta a ${c.target}, pero no devuelve clave: DKIM podría no estar activado en el proveedor.`));
    }
    return { found, active: active.length, pendingCname, issues, selectorsTested: selectors.length };
  }

  // ------------------------------------------------------- MX y extras de DNS

  function detectProvider(mxHosts) {
    for (const host of mxHosts) {
      for (const p of MAIL_PROVIDERS) if (p.mx.test(host)) return { id: p.id, name: p.name };
    }
    return mxHosts.length ? { id: 'other', name: 'Servidor propio u otro proveedor' } : null;
  }

  async function evaluateMx(domain, dns) {
    const res = await dns.resolve(domain, 'MX');
    const records = res.answers.map((a) => parseMx(a.data)).filter(Boolean).sort((a, b) => a.preference - b.preference);
    const nullMx = records.length === 1 && (records[0].host === '' || records[0].host === '.');
    const hosts = nullMx ? [] : records.map((r) => r.host);
    return { status: res.status, records, nullMx, acceptsMail: hosts.length > 0, provider: detectProvider(hosts) };
  }

  async function evaluateExtras(domain, dns, options) {
    const [mtaSts, tlsRpt, bimi, caa, ds, soa] = await Promise.all([
      dns.txt(`_mta-sts.${domain}`),
      dns.txt(`_smtp._tls.${domain}`),
      dns.txt(`default._bimi.${domain}`),
      dns.resolve(domain, 'CAA'),
      dns.resolve(domain, 'DS'),
      dns.resolve(domain, 'SOA'),
    ]);
    const mtaRecord = mtaSts.records.find((r) => /^v=STSv1/i.test(r)) || null;
    const out = {
      mtaSts: { record: mtaRecord, present: Boolean(mtaRecord), mode: null, policyChecked: false },
      tlsRpt: { record: tlsRpt.records.find((r) => /^v=TLSRPTv1/i.test(r)) || null },
      bimi: { record: bimi.records.find((r) => /^v=BIMI1/i.test(r)) || null },
      caa: { records: caa.answers.map((a) => parseCaa(a.data)).filter(Boolean) },
      dnssec: { signed: ds.answers.length > 0, validated: soa.ad === true, bogus: ds.answers.length > 0 && soa.status === 'SERVFAIL' },
    };
    out.tlsRpt.present = Boolean(out.tlsRpt.record);
    out.bimi.present = Boolean(out.bimi.record);
    out.caa.present = out.caa.records.length > 0;

    if (mtaRecord && options.fetchMtaStsPolicy && options.fetch) {
      try {
        const res = await options.fetch(`https://mta-sts.${domain}/.well-known/mta-sts.txt`, { redirect: 'error', signal: AbortSignal.timeout ? AbortSignal.timeout(5000) : undefined });
        if (res.ok) {
          const text = (await res.text()).slice(0, 2048);
          const m = /^mode:\s*(enforce|testing|none)\s*$/mi.exec(text);
          out.mtaSts.mode = m ? m[1].toLowerCase() : 'invalid';
        } else out.mtaSts.mode = 'unreachable';
      } catch (_) {
        out.mtaSts.mode = 'unreachable';
      }
      out.mtaSts.policyChecked = true;
    }
    return out;
  }

  // ------------------------------------------------- veredicto y puntuación

  const RISK = {
    critical: { level: 'critical', label: 'Crítico', order: 4 },
    high: { level: 'high', label: 'Alto', order: 3 },
    medium: { level: 'medium', label: 'Medio', order: 2 },
    low: { level: 'low', label: 'Bajo', order: 1 },
  };

  function spoofVerdict(report) {
    const { spf, dmarc } = report;
    if (spf.openToAll) {
      return { ...RISK.critical, headline: 'Cualquiera puede enviar correos como tu dominio y pasarán las verificaciones.', detail: 'Tu SPF autoriza a todo Internet. Un correo falso no solo llegaría: aparecería como legítimo.' };
    }
    if (!dmarc.present) {
      return { ...RISK.critical, headline: 'Sí: cualquiera puede enviar correos haciéndose pasar por tu dominio.', detail: 'No hay DMARC. Ningún receptor tiene la instrucción de rechazar correos falsos con tu nombre; llegan o no según los filtros de cada proveedor.' };
    }
    const effective = effectivePolicy(dmarc.appliedPolicy, dmarc.testing);
    if (effective === 'none') {
      return { ...RISK.high, headline: 'Sí: tu dominio puede ser suplantado.', detail: 'Tienes DMARC, pero en modo de solo observación ("none" o modo prueba). Los correos falsos no se rechazan.' };
    }
    if (effective === 'quarantine' || dmarc.partial) {
      return { ...RISK.medium, headline: 'Parcialmente protegido: los correos falsos irían a spam, no a la basura.', detail: 'Tu DMARC está en "quarantine" o aplicado a una parte del correo. Un empleado que revise su carpeta de spam todavía podría caer.' };
    }
    if (dmarc.subdomainPolicy === 'none') {
      return { ...RISK.medium, headline: 'Tu dominio principal está protegido, pero tus subdominios no.', detail: 'Un atacante puede usar direcciones como facturacion.tu-dominio para engañar a clientes y proveedores.' };
    }
    return { ...RISK.low, headline: 'No: los correos falsos con tu dominio exacto serían rechazados.', detail: 'Tu DMARC está en "reject". Aún existen ataques con dominios parecidos (typosquatting) o cuentas robadas, que DMARC no detiene.' };
  }

  function effectivePolicy(policy, testing) {
    if (!testing) return policy;
    return policy === 'reject' ? 'quarantine' : 'none';
  }

  function score(report) {
    const { spf, dmarc, dkim, extras, mx } = report;
    const parts = [];
    let dmarcPts = 0;
    if (dmarc.present) {
      const eff = effectivePolicy(dmarc.appliedPolicy, dmarc.testing);
      dmarcPts = eff === 'reject' ? 40 : eff === 'quarantine' ? 26 : 8;
      if (dmarc.partial) dmarcPts -= 8;
      if (eff !== 'none' && dmarc.subdomainPolicy === 'none') dmarcPts -= 8;
    }
    parts.push({ key: 'dmarc', label: 'Política DMARC', points: Math.max(0, dmarcPts), max: 40 });

    let spfPts = 0;
    if (spf.status === 'ok') spfPts = spf.allQualifier === '-' ? 20 : spf.allQualifier === '~' ? 17 : spf.allQualifier === '+' ? 0 : 6;
    else if (spf.status === 'permerror') spfPts = 3;
    parts.push({ key: 'spf', label: 'SPF', points: spfPts, max: 20 });

    const noMail = !mx.acceptsMail;
    parts.push({ key: 'dkim', label: 'Firma DKIM', points: dkim.active > 0 || noMail ? 15 : 5, max: 15 });
    parts.push({ key: 'rua', label: 'Reportes DMARC', points: dmarc.reporting ? 10 : 0, max: 10 });
    parts.push({ key: 'transport', label: 'Cifrado en tránsito (MTA-STS / TLS-RPT)', points: (extras.mtaSts.present ? 5 : 0) + (extras.tlsRpt.present ? 3 : 0), max: 8 });
    parts.push({ key: 'dnssec', label: 'DNSSEC', points: extras.dnssec.validated ? 4 : 0, max: 4 });
    parts.push({ key: 'caa', label: 'CAA', points: extras.caa.present ? 3 : 0, max: 3 });

    let total = parts.reduce((s, p) => s + p.points, 0);
    const verdict = report.verdict;
    if (verdict.level === 'critical') total = Math.min(total, 35);
    else if (verdict.level === 'high') total = Math.min(total, 55);
    else if (verdict.level === 'medium') total = Math.min(total, 79);
    const grade = total >= 90 ? 'A' : total >= 80 ? 'B' : total >= 65 ? 'C' : total >= 50 ? 'D' : total >= 36 ? 'E' : 'F';
    return { total, grade, parts };
  }

  // ------------------------------------------------------------ simulador

  const ATTACKER_IP = '203.0.113.66'; // TEST-NET-3 (RFC 5737), reservada para documentación

  function simulateSpoof(report, opts = {}) {
    const target = opts.subdomain ? `pagos.${report.orgDomain}` : report.domain;
    const steps = [];
    const { spf, dmarc } = report;
    const usingSub = Boolean(opts.subdomain);

    let spfResult;
    if (usingSub) spfResult = 'none';
    else if (spf.openToAll || (spf.status === 'ok' && spfMatchesIp(spf, ATTACKER_IP))) spfResult = 'pass';
    else if (spf.status === 'none') spfResult = 'none';
    else if (spf.status === 'permerror') spfResult = 'permerror';
    else if (spf.status === 'temperror') spfResult = 'temperror';
    else spfResult = { '-': 'fail', '~': 'softfail', '?': 'neutral' }[spf.allQualifier] || 'neutral';

    const spfText = {
      pass: 'El SPF autoriza al servidor del atacante. El receptor lo considera legítimo.',
      fail: 'El servidor del atacante no está en el SPF: resultado "fail".',
      softfail: 'El servidor del atacante no está en el SPF: resultado "softfail" (sospechoso, pero no definitivo).',
      neutral: 'El SPF no se pronuncia: resultado "neutral".',
      none: usingSub ? `El subdominio ${target} no tiene SPF propio: resultado "none".` : 'No hay SPF que consultar: resultado "none".',
      permerror: 'El SPF tiene errores y el receptor lo descarta: resultado "permerror".',
      temperror: 'No se pudo consultar el SPF: resultado "temperror".',
    }[spfResult];
    steps.push({ id: 'spf', title: 'Verificación SPF', result: spfResult, ok: spfResult === 'fail', bad: spfResult === 'pass', text: spfText });

    steps.push({ id: 'dkim', title: 'Firma DKIM', result: 'none', ok: true, bad: false, text: 'El atacante no tiene tu clave privada: el correo llega sin una firma DKIM válida de tu dominio.' });

    const dmarcPass = spfResult === 'pass';
    let disposition;
    let dmarcText;
    if (!dmarc.present) {
      disposition = 'delivered';
      dmarcText = 'No existe política DMARC. El receptor decide solo con sus filtros antispam.';
    } else if (dmarcPass) {
      disposition = 'delivered-pass';
      dmarcText = 'SPF "pass" alineado con el remitente visible: DMARC da el correo por auténtico.';
    } else {
      const base = usingSub ? dmarc.nonexistentPolicy : dmarc.appliedPolicy;
      const eff = effectivePolicy(base, dmarc.testing || dmarc.partial);
      const finalPolicy = dmarc.partial && eff !== 'none' ? `${eff}*` : eff;
      disposition = { none: 'delivered', quarantine: 'quarantine', reject: 'rejected' }[eff];
      dmarcText = `DMARC falla (ni SPF ni DKIM alineados). Política aplicada: "${finalPolicy.replace(/\*/g, '')}"${dmarc.partial ? ` (peor caso: con pct=${dmarc.tags.pct}, el resto del correo recibe una política más suave)` : ''}${dmarc.testing ? ' (rebajada por modo prueba)' : ''}.`;
    }
    steps.push({ id: 'dmarc', title: 'Evaluación DMARC', result: dmarc.present ? (dmarcPass ? 'pass' : 'fail') : 'none', ok: disposition === 'rejected', bad: disposition !== 'rejected' && disposition !== 'quarantine', text: dmarcText });

    const outcome = {
      'delivered-pass': { label: 'Entregado como legítimo', tone: 'critical', text: 'El correo falso llega a la bandeja de entrada y pasa todas las verificaciones.' },
      delivered: { label: 'Puede llegar a la bandeja', tone: 'high', text: 'Nada lo bloquea por política. Llega o no según los filtros antispam del receptor.' },
      quarantine: { label: 'Enviado a spam', tone: 'medium', text: 'El correo falso termina en la carpeta de spam. Todavía puede ser abierto.' },
      rejected: { label: 'Rechazado', tone: 'low', text: 'El servidor receptor rechaza el correo falso. Nunca llega a la víctima.' },
    }[disposition];
    return { from: `gerencia@${target}`, attackerIp: ATTACKER_IP, spfAuthorizesAttacker: spfResult === 'pass', steps, outcome, disposition };
  }

  // ---------------------------------------------------------- remediación

  function remediation(report) {
    const { domain, spf, dmarc, dkim, mx, extras } = report;
    const items = [];
    const provider = mx.provider;
    const reportAddr = `dmarc@${report.orgDomain}`;

    if (!mx.acceptsMail && !(spf.present && spf.tree.terms.some((t) => t.mechanism !== 'all'))) {
      items.push({
        priority: 1,
        title: 'Blindar un dominio que no envía correo',
        why: 'Este dominio no recibe correo. Si tampoco lo envía, debe declararlo para que nadie lo use en fraudes.',
        records: [
          { type: 'TXT', name: domain, value: 'v=spf1 -all' },
          { type: 'TXT', name: `_dmarc.${domain}`, value: 'v=DMARC1; p=reject; sp=reject; np=reject; adkim=s; aspf=s' },
          { type: 'MX', name: domain, value: '0 .' },
        ],
        note: 'Confirma antes que ningún sistema (web, facturación, CRM) envía correo con este dominio.',
      });
      return items;
    }

    if (!spf.present || spf.status !== 'ok' || spf.allQualifier === '+' || spf.allQualifier === '?' || spf.allQualifier === null) {
      let value;
      if (spf.present && spf.status === 'ok') {
        const kept = spf.tree.terms.filter((t) => t.mechanism !== 'all')
          .map((t) => `${t.qualifier === '+' ? '' : t.qualifier}${t.mechanism}${t.value ? (t.value.startsWith('/') ? t.value : ':' + t.value) : ''}`);
        value = ['v=spf1', ...kept, '~all'].join(' ');
      } else {
        const inc = provider && SPF_PROVIDER_INCLUDE[provider.id];
        value = ['v=spf1', inc || 'include:<tu-proveedor-de-correo>', '~all'].join(' ');
      }
      items.push({
        priority: 1,
        title: spf.present ? 'Corregir el registro SPF' : 'Publicar un registro SPF',
        why: 'SPF le dice al mundo qué servidores pueden enviar correo con tu dominio.',
        records: [{ type: 'TXT', name: domain, value }],
        note: 'Agrega todos los servicios que envían correo en tu nombre (facturación electrónica, CRM, marketing). Cuando DMARC llegue a "reject", cambia "~all" por "-all".',
      });
    }
    if (spf.issues.some((i) => i.code === 'spf-too-many-lookups')) {
      items.push({ priority: 1, title: 'Reducir las consultas del SPF', why: 'Superar 10 consultas DNS invalida el SPF completo.', records: [], note: 'Elimina proveedores que ya no usas, reemplaza "a" y "mx" por rangos ip4 explícitos o mueve envíos masivos a un subdominio con SPF propio.' });
    }

    const eff = dmarc.present ? effectivePolicy(dmarc.appliedPolicy, dmarc.testing) : null;
    if (eff !== 'reject' || dmarc.partial || dmarc.subdomainPolicy === 'none') {
      const phases = [];
      const keepRua = dmarc.present && dmarc.reporting;
      const rua = keepRua ? dmarc.tags.rua : `mailto:${reportAddr}`;
      if (!keepRua) {
        phases.push({ label: 'Semana 0: observar', value: `v=DMARC1; p=none; rua=${rua}`, note: 'Recibe reportes de 2 a 4 semanas e identifica todos los servicios legítimos que envían con tu dominio.' });
      }
      if (eff !== 'quarantine' || dmarc.partial || dmarc.testing) {
        phases.push({ label: keepRua ? 'Ahora: cuarentena' : 'Semana 3 o 4: cuarentena', value: `v=DMARC1; p=quarantine; sp=quarantine; rua=${rua}`, note: 'Lo que no pase SPF o DKIM alineado va a spam. Revisa los reportes cada semana.' });
      }
      phases.push({ label: keepRua ? '2 a 4 semanas después: rechazo' : 'Semana 6 a 8: rechazo', value: `v=DMARC1; p=reject; sp=reject; np=reject; rua=${rua}`, note: 'Los correos falsos con tu dominio son rechazados. Esta es la meta.' });
      items.push({
        priority: 1,
        title: dmarc.present ? 'Llevar DMARC hasta "reject"' : 'Publicar DMARC con un plan gradual',
        why: 'DMARC es la única instrucción que hace que Gmail, Outlook y los demás rechacen correos falsos con tu dominio.',
        records: [],
        phases: phases.map((ph) => ({ ...ph, type: 'TXT', name: `_dmarc.${report.orgDomain}` })),
        note: keepRua ? 'Conservamos tu dirección actual de reportes DMARC. Avanza de fase solo cuando los reportes muestren que todo tu correo legítimo pasa SPF o DKIM alineado.' : `Crea el buzón ${reportAddr} (o usa un servicio que procese reportes DMARC) antes de la primera fase.`,
      });
    }

    if (mx.acceptsMail && dkim.active === 0) {
      const how = {
        m365: 'En Microsoft Defender (security.microsoft.com) → Políticas → Autenticación de correo → DKIM: crea los registros CNAME selector1 y selector2 que te indica el portal y activa la firma.',
        google: 'En la Consola de administración de Google → Apps → Gmail → Autenticar correo: genera una clave de 2048 bits, publica el TXT google._domainkey y pulsa "Iniciar autenticación".',
        zoho: 'En Zoho Mail Admin → Dominios → Autenticación de correo → DKIM: agrega un selector, publica el TXT y verifica.',
      }[provider && provider.id] || 'Activa la firma DKIM en tu proveedor de correo (2048 bits) y publica el registro que te entregue.';
      items.push({ priority: 2, title: 'Activar la firma DKIM', why: 'DKIM firma criptográficamente tus correos: prueba que salieron de ti y que nadie los modificó.', records: [], note: how });
    }

    if (mx.acceptsMail && !extras.mtaSts.present) {
      items.push({
        priority: 3,
        title: 'Forzar cifrado del correo entrante (MTA-STS + TLS-RPT)',
        why: 'Impide que un atacante en la red degrade la conexión y lea el correo en tránsito.',
        records: [
          { type: 'TXT', name: `_mta-sts.${domain}`, value: 'v=STSv1; id=<fecha-AAAAMMDD01>' },
          { type: 'TXT', name: `_smtp._tls.${domain}`, value: `v=TLSRPTv1; rua=mailto:tlsrpt@${report.orgDomain}` },
        ],
        note: `Además publica la política en https://mta-sts.${domain}/.well-known/mta-sts.txt (empieza con "mode: testing").`,
      });
    }
    if (!extras.caa.present) {
      items.push({ priority: 3, title: 'Restringir quién emite certificados (CAA)', why: 'Solo las autoridades que autorices podrán emitir certificados HTTPS para tu dominio.', records: [{ type: 'CAA', name: domain, value: '0 issue "<tu-autoridad-certificadora>"' }], note: 'Ejemplo: 0 issue "letsencrypt.org". Verifica qué autoridad usa hoy tu sitio antes de publicarlo.' });
    }
    return items.sort((a, b) => a.priority - b.priority);
  }

  // ------------------------------------------------------------- orquestador

  async function analyzeDomain(input, options = {}) {
    const norm = normalizeDomain(input);
    if (!norm.ok) return { ok: false, error: norm.error };
    const domain = norm.domain;
    const dns = options.resolver || createResolver(options);
    const started = Date.now();

    const ns = await dns.resolve(domain, 'NS');
    const soa = await dns.resolve(domain, 'SOA');
    if (ns.status === 'NXDOMAIN' && soa.status === 'NXDOMAIN') {
      return { ok: false, error: `El dominio ${domain} no existe en DNS.` };
    }
    if (ns.status === 'ERROR' && soa.status === 'ERROR') {
      return { ok: false, error: 'No pudimos contactar los servidores DNS públicos. Revisa tu conexión e inténtalo de nuevo.' };
    }

    const [mx, spf, dmarc, dkim, extras] = await Promise.all([
      evaluateMx(domain, dns),
      evaluateSpf(domain, dns),
      evaluateDmarc(domain, dns),
      evaluateDkim(domain, dns, options.dkimSelectors),
      evaluateExtras(domain, dns, { fetchMtaStsPolicy: options.fetchMtaStsPolicy, fetch: options.fetch || (typeof fetch !== 'undefined' ? fetch.bind(globalThis) : null) }),
    ]);

    const report = {
      ok: true,
      domain,
      orgDomain: organizationalDomain(domain),
      analyzedAt: new Date().toISOString(),
      durationMs: 0,
      mx, spf, dmarc, dkim, extras,
    };
    if (extras.dnssec.bogus) {
      dmarc.issues.push(issue('high', 'dnssec-bogus', 'DNSSEC está mal configurado (firma inválida): algunos resolvers no pueden resolver el dominio.'));
    }
    report.verdict = spoofVerdict(report);
    report.score = score(report);
    report.simulation = simulateSpoof(report);
    report.subdomainSimulation = simulateSpoof(report, { subdomain: true });
    report.remediation = remediation(report);
    report.issues = [...spf.issues, ...dmarc.issues, ...dkim.issues];
    report.durationMs = Date.now() - started;
    report.dnsQueries = dns.stats().queries;
    return report;
  }

  return {
    TYPE, DOH_ENDPOINTS, DKIM_SELECTORS,
    normalizeDomain, organizationalDomain, parseTxtData, parseCaa, parseMx,
    parseSpf, parseDmarc, estimateDkimKey, cidrContains, detectProvider,
    createResolver, evaluateSpf, evaluateDmarc, evaluateDkim, evaluateMx, evaluateExtras,
    spoofVerdict, effectivePolicy, score, simulateSpoof, remediation, analyzeDomain,
  };
});
