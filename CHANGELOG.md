# Cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/). Versiones según [SemVer](https://semver.org/lang/es/).

## [1.1.0] - 2026-10-19

### Añadido
- Modo de lectura Simple o Técnica, con explicación "en palabras simples" de cada paso del recorrido del correo falso y un resumen para gerencia.
- Recorrido postal animado bajo el sobre (SPF, DKIM, DMARC y destino), anillo de calificación y cifras del observatorio animadas, con respeto a `prefers-reduced-motion`.
- Hallazgos, plan de corrección, detalle técnico, glosario, sección legal y ética y preguntas frecuentes en desplegables.
- Observatorio diario: datos al cierre del día anterior e historial con gráfico de evolución (`data/history.json`).
- Detección de Outlook.com (cuenta personal de Microsoft) como proveedor de correo.
- Las organizaciones con errores DNS temporales persistentes quedan fuera del cálculo como "no concluyentes" (2 en el primer corte; el total analizado pasa de 227 a 225).
- Métricas de uso opcionales con Cloudflare Web Analytics, sin cookies; la CSP solo las permite si están activadas en `site.config.json`.

### Cambiado
- Autoría y contacto se configuran en `site.config.json` (`author`, `contact`).

## [1.0.0] - 2026-10-19

### Añadido
- Motor de análisis pasivo: SPF con árbol de inclusiones y límites de 10 consultas y 2 consultas vacías (RFC 7208), DMARC según RFC 9989 con búsqueda en el dominio organizacional, DKIM en 41 selectores comunes, MX con detección de proveedor, MTA-STS, TLS-RPT, BIMI, DNSSEC y CAA.
- Veredicto de riesgo, calificación de 0 a 100 y simulación de un correo falsificado para el dominio y para un subdominio inventado.
- Plan de corrección con registros listos para copiar y fases graduales de DMARC.
- Observatorio de República Dominicana con 227 organizaciones (datos agregados).
- Sitio estático de un solo archivo con CSP por hash, fuentes incrustadas y cabeceras de seguridad.
- Pruebas unitarias, de abuso y de extremo a extremo; integración continua con Semgrep, gitleaks y OSV-Scanner.

### Seguridad
- Revisión de seguridad independiente antes del lanzamiento: 6 hallazgos (1 alto, 1 medio, 2 bajos y 2 informativos), todos corregidos con pruebas de regresión. Detalle en `docs/revision-seguridad.md`.
