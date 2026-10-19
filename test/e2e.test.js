'use strict';
// Pruebas de extremo a extremo sobre dist/site/index.html con Chromium.
// Ejecutar después de `npm run build`. Las respuestas DNS se simulan para que
// la prueba sea determinista y no dependa de la red.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { chromium } = require('playwright');

const SITE = pathToFileURL(path.join(__dirname, '..', 'dist', 'site', 'index.html')).href;
const HOSTILE = '<img src=x onerror="window.__pwned=1">';

const ZONE = {
  'ejemplo.do|2': ['ns1.ejemplo.do.'],
  'ejemplo.do|6': ['ns1.ejemplo.do. admin. 1 2 3 4 5'],
  'ejemplo.do|15': ['0 ejemplo-do.mail.protection.outlook.com.'],
  'ejemplo.do|16': [`"v=spf1 include:spf.protection.outlook.com ~all"`],
  'spf.protection.outlook.com|16': ['"v=spf1 ip4:40.92.0.0/15 -all"'],
  '_dmarc.ejemplo.do|16': [`"v=DMARC1; p=none; rua=mailto:${HOSTILE}"`],
};

function dohResponder(route) {
  const url = new URL(route.request().url());
  const key = `${url.searchParams.get('name')}|${url.searchParams.get('type')}`;
  const answers = ZONE[key];
  const body = answers
    ? { Status: 0, AD: false, Answer: answers.map((data) => ({ type: Number(url.searchParams.get('type')), TTL: 300, data })) }
    : { Status: 3, AD: false };
  return route.fulfill({ status: 200, contentType: 'application/dns-json', headers: { 'access-control-allow-origin': '*' }, body: JSON.stringify(body) });
}

async function openPage(browser, viewport, colorScheme) {
  const context = await browser.newContext({ viewport, colorScheme });
  const page = await context.newPage();
  const problems = [];
  page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
  page.on('console', (m) => { if (m.type() === 'error') problems.push(`console: ${m.text()}`); });
  return { context, page, problems };
}

test('sitio publicado: análisis, simulación y seguridad', async (t) => {
  const browser = await chromium.launch();
  t.after(() => browser.close());

  await t.test('análisis con DNS simulado y registro hostil inerte', async () => {
    const { context, page, problems } = await openPage(browser, { width: 1366, height: 900 }, 'light');
    await context.route(/cloudflare-dns\.com|dns\.google/, dohResponder);
    await page.goto(SITE);
    await page.fill('#domain-input', 'https://www.Ejemplo.do/contacto');
    await page.click('#check-btn');
    await page.waitForSelector('#resultado:not([hidden])', { timeout: 15000 });
    assert.equal(await page.textContent('#r-domain'), 'ejemplo.do');
    assert.equal(await page.getAttribute('#r-risk', 'data-tone'), 'high');
    assert.match(await page.textContent('#mark-text'), /Puede llegar/);
    assert.equal(await page.evaluate(() => window.__pwned), undefined, 'el contenido DNS no debe ejecutarse');
    assert.equal(await page.locator('#r-tech img').count(), 0, 'el contenido DNS no debe convertirse en HTML');
    await page.click('#tab-sub');
    assert.match(await page.textContent('#route-from'), /pagos\.ejemplo\.do/);
    assert.deepEqual(problems, []);
    await context.close();
  });

  await t.test('sin red: muestra un ejemplo guardado y explica el bloqueo', async () => {
    const { context, page } = await openPage(browser, { width: 390, height: 844 }, 'dark');
    await context.route(/cloudflare-dns\.com|dns\.google/, (route) => route.abort());
    await page.goto(SITE);
    await page.fill('#domain-input', 'microsoft.com');
    await page.click('#check-btn');
    await page.waitForSelector('#resultado:not([hidden])', { timeout: 20000 });
    assert.match(await page.textContent('#r-source'), /guardado/);
    await page.click('#check-another');
    await page.fill('#domain-input', 'otro-dominio.do');
    await page.click('#check-btn');
    await page.waitForFunction(() => document.getElementById('status').classList.contains('error'), null, { timeout: 20000 });
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
    assert.equal(overflow, false, 'sin desplazamiento horizontal en móvil');
    await context.close();
  });

  await t.test('entrada inválida muestra un error claro', async () => {
    const { context, page } = await openPage(browser, { width: 1024, height: 800 }, 'light');
    await page.goto(SITE);
    await page.fill('#domain-input', '8.8.8.8');
    await page.click('#check-btn');
    assert.match(await page.textContent('#status'), /no una dirección IP/);
    await context.close();
  });
});
