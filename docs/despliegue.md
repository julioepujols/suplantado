# Despliegue

El sitio es estático: `npm run build` genera `dist/site/` con `index.html`, `_headers`, `og.png`, `robots.txt` y `sitemap.xml`.

## Antes de publicar

1. Ajusta `site.config.json`:
   - `siteUrl`: la URL definitiva, sin barra final. Se usa en la vista previa para redes sociales, la URL canónica y el sitemap.
   - `contact`: correo (activa `/.well-known/security.txt`), LinkedIn y GitHub. Las URL deben usar `https://`.
2. Ejecuta `npm test`, `npm run test:e2e` y `npm run build`.

## Opción A: Cloudflare Pages (recomendada)

Aplica las cabeceras de seguridad de `_headers` (HSTS, `frame-ancestors`, etc.).

1. Entra a dash.cloudflare.com y ve a **Workers & Pages**. Crea un proyecto de Pages e importa el repositorio de GitHub `julioepujols/suplantado`.
2. Configuración de construcción:
   - Comando de construcción: `npm run build`
   - Directorio de salida: `dist/site`
   - Variable de entorno: `NODE_VERSION` = `22` (y `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD` = `1`)
3. Nombre del proyecto: `suplantado`. La URL será `https://suplantado.pages.dev` si el nombre está libre. Si cambia, actualiza `siteUrl` y vuelve a desplegar.
4. Verifica:
   - Que el análisis en vivo funcione.
   - Que las cabeceras estén activas: `curl -sI https://suplantado.pages.dev` debe mostrar `content-security-policy` y `strict-transport-security`.
   - La vista previa en el Post Inspector de LinkedIn.

Cada `git push` a `main` vuelve a desplegar automáticamente.

## Opción B: GitHub Pages

1. En el repositorio, ve a **Settings → Pages**. En **Source** elige **GitHub Actions** y usa un flujo que ejecute `npm ci && npm run build` y publique `dist/site`.
2. Limitación: GitHub Pages no permite cabeceras personalizadas. La CSP sigue activa por `<meta>`, pero no hay `frame-ancestors` ni las demás cabeceras de `_headers`.

## Dominio propio (futuro)

En Cloudflare Pages, ve a **Custom domains** y agrega el dominio. Actualiza `siteUrl`, reconstruye y vuelve a desplegar.
