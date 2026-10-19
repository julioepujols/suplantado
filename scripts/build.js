'use strict';
// Ensambla dos salidas a partir de src/app.html:
//   dist/artifact.html   página sin esqueleto (vitrina embebible)
//   dist/site/           sitio estático desplegable (Cloudflare Pages / GitHub Pages)
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const b64 = (p) => fs.readFileSync(path.join(root, p)).toString('base64');
const safeJson = (v) => JSON.stringify(v).replace(/</g, '\\u003c');

const config = JSON.parse(read('site.config.json'));
const siteUrl = (process.env.SITE_URL || config.siteUrl).replace(/\/+$/, '');
if (!/^https:\/\/[a-z0-9.-]+$/i.test(siteUrl)) throw new Error(`siteUrl inválida: ${siteUrl}`);
const contact = {
  email: config.contact.email || '',
  linkedin: config.contact.linkedin || '',
  github: config.contact.github || '',
};
for (const [key, value] of Object.entries(contact)) {
  if (key !== 'email' && value && !/^https:\/\//.test(value)) throw new Error(`contact.${key} debe usar https://`);
}

const fonts = [
  `@font-face{font-family:'Archivo';font-style:normal;font-weight:100 900;font-stretch:62% 125%;font-display:swap;src:url(data:font/woff2;base64,${b64('assets/fonts/archivo.woff2')}) format('woff2');}`,
  `@font-face{font-family:'IBM Plex Mono';font-style:normal;font-weight:400;font-display:swap;src:url(data:font/woff2;base64,${b64('assets/fonts/plex400.woff2')}) format('woff2');}`,
  `@font-face{font-family:'IBM Plex Mono';font-style:normal;font-weight:500;font-display:swap;src:url(data:font/woff2;base64,${b64('assets/fonts/plex500.woff2')}) format('woff2');}`,
].join('\n');

const data = {
  observatory: JSON.parse(read('data/observatory.json')),
  samples: JSON.parse(read('data/samples.json')),
};

const page = read('src/app.html')
  .split('__SITE_URL__').join(siteUrl)
  .replace('/*__FONTS__*/', () => fonts)
  .replace('/*__ENGINE__*/', () => read('src/engine.js'))
  .replace('/*__DATA__*/', () => safeJson(data))
  .replace('/*__CONTACT__*/', () => safeJson(contact))
  .replace('/*__APP__*/', () => read('src/ui.js'));

if (/\/\*__[A-Z]+__\*\//.test(page)) throw new Error('Quedó un marcador sin reemplazar');

const dist = path.join(root, 'dist');
const site = path.join(dist, 'site');
fs.rmSync(dist, { recursive: true, force: true });
fs.mkdirSync(site, { recursive: true });
fs.writeFileSync(path.join(dist, 'artifact.html'), page);

const scriptHashes = [...page.matchAll(/<script>([\s\S]*?)<\/script>/g)]
  .map((m) => `'sha256-${crypto.createHash('sha256').update(m[1], 'utf8').digest('base64')}'`);

const csp = [
  "default-src 'none'",
  `script-src ${scriptHashes.join(' ')}`,
  "style-src 'unsafe-inline'",
  'font-src data:',
  'img-src data:',
  'connect-src https://cloudflare-dns.com https://dns.google',
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

const splitAt = page.indexOf('<div class="airmail"');
const html = `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light dark">
${page.slice(0, splitAt)}</head>
<body>
${page.slice(splitAt)}
</body>
</html>
`;
fs.writeFileSync(path.join(site, 'index.html'), html);

fs.writeFileSync(path.join(site, '_headers'), `/*
  Content-Security-Policy: ${csp}; frame-ancestors 'none'; upgrade-insecure-requests
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Referrer-Policy: no-referrer
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Resource-Policy: same-origin
`);
fs.writeFileSync(path.join(site, 'robots.txt'), `User-agent: *\nAllow: /\nSitemap: ${siteUrl}/sitemap.xml\n`);
fs.writeFileSync(path.join(site, 'sitemap.xml'), `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${siteUrl}/</loc></url></urlset>\n`);
fs.copyFileSync(path.join(root, 'assets/og.png'), path.join(site, 'og.png'));

if (contact.email) {
  const expires = new Date(Date.now() + 365 * 864e5).toISOString().replace(/\.\d+Z$/, 'Z');
  fs.mkdirSync(path.join(site, '.well-known'), { recursive: true });
  fs.writeFileSync(path.join(site, '.well-known/security.txt'),
    `Contact: mailto:${contact.email}\nExpires: ${expires}\nPreferred-Languages: es, en\nCanonical: ${siteUrl}/.well-known/security.txt\n`);
}

const kb = (s) => `${Math.round(Buffer.byteLength(s) / 1024)} KB`;
console.log(`dist/artifact.html ${kb(page)} | dist/site/index.html ${kb(html)} | ${scriptHashes.length} scripts con hash CSP | ${siteUrl}`);
