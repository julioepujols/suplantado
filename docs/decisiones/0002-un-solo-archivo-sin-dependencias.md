# 0002. Un solo archivo HTML sin dependencias de producción

- Estado: aceptada
- Fecha: 2026-10-19

## Contexto

Cada dependencia de terceros es un riesgo de cadena de suministro y cada recurso externo amplía la CSP.

## Decisión

JavaScript sin dependencias, fuentes incrustadas en base64 y todo empaquetado en un único `index.html` por `scripts/build.js`. Los scripts se autorizan en la CSP por su hash SHA-256.

## Consecuencias

- CSP estricta sin `unsafe-inline` para scripts y sin dominios de CDN.
- El archivo pesa unos 340 KB, la mayor parte fuentes, que se cargan una sola vez.
- Cualquier cambio en los scripts cambia el hash; la construcción lo recalcula automáticamente.
