# Cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/). Versiones según [SemVer](https://semver.org/lang/es/).

## [1.0.0] - 2026-10-19

### Añadido
- Motor de análisis pasivo: SPF con árbol de inclusiones y límites de 10 consultas y 2 consultas vacías (RFC 7208), DMARC según RFC 9989 con búsqueda en el dominio organizacional, DKIM en 41 selectores comunes, MX con detección de proveedor, MTA-STS, TLS-RPT, BIMI, DNSSEC y CAA.
- Veredicto de riesgo, calificación de 0 a 100 y simulación de un correo falsificado para el dominio y para un subdominio inventado.
- Plan de corrección con registros listos para copiar y fases graduales de DMARC.
- Observatorio de República Dominicana con 227 organizaciones (datos agregados).
- Sitio estático de un solo archivo con CSP por hash, fuentes incrustadas y cabeceras de seguridad.
- Pruebas unitarias, de abuso y de extremo a extremo; integración continua con Semgrep, gitleaks y OSV-Scanner.
