# Política de seguridad

## Reportar una vulnerabilidad

Usa el reporte privado de vulnerabilidades de GitHub: pestaña **Security**, luego **Report a vulnerability** en este repositorio. No abras un issue público.

Incluye la versión o el commit afectado, los pasos para reproducir el problema, el impacto que observaste y, si la tienes, una propuesta de corrección.

## Qué esperar

| Etapa | Plazo objetivo |
|---|---|
| Acuse de recibo | 3 días hábiles |
| Evaluación inicial y severidad (CVSS 4.0) | 10 días hábiles |
| Corrección de severidad alta o crítica | 30 días |

Te mantendremos al tanto del avance y, si lo deseas, te daremos crédito en el CHANGELOG.

## Alcance

Dentro del alcance:
- El código de este repositorio y el sitio publicado a partir de él.
- Inyección de contenido a través de registros DNS, omisiones de la CSP, fugas de datos del visitante y errores de análisis que produzcan veredictos falsos de "protegido".

Fuera del alcance:
- Los resolvers DNS de terceros (Cloudflare, Google) y la plataforma de alojamiento.
- Ataques de denegación de servicio, ingeniería social o pruebas contra la infraestructura de terceros.
- Dominios de organizaciones que aparecen en el observatorio: no los pruebes ni los ataques.

## Investigación de buena fe

No emprenderemos acciones contra investigaciones que respeten este alcance, eviten afectar a otras personas o datos y nos den un plazo razonable para corregir antes de cualquier publicación.
