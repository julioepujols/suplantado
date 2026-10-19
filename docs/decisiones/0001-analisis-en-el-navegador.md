# 0001. Analizar en el navegador con DNS sobre HTTPS

- Estado: aceptada
- Fecha: 2026-10-19

## Contexto

La herramienta debe ser gratuita, sin costos de servidor, y creíble para profesionales de seguridad. Un backend agregaría superficie de ataque, costos, datos de visitantes que proteger y obligaciones de privacidad.

## Decisión

Toda la lógica corre en el navegador y consulta DNS públicos mediante DoH en formato JSON contra Cloudflare, con Google como respaldo. Ambos permiten CORS.

## Consecuencias

- No almacenamos datos de visitantes: es un argumento de confianza y simplifica el cumplimiento de la Ley 172-13.
- Costo de alojamiento cero y despliegue estático.
- No se pueden hacer comprobaciones que requieran conexiones SMTP o leer cabeceras HTTP de terceros, como STARTTLS o la política MTA-STS desde el navegador.
- El dominio consultado llega a los resolvers DoH; se documenta en el sitio.
