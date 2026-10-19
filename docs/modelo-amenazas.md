# Modelo de amenazas

Método: STRIDE sobre el sitio estático y su flujo de datos. Última revisión: 19 de octubre de 2026, actualizada con la [revisión de seguridad independiente](revision-seguridad.md).

## Activos

| Activo | Por qué importa |
|---|---|
| Integridad de la página publicada | Si se altera, el sitio podría robar datos del visitante o dar veredictos falsos |
| Dominio que consulta el visitante | Revela qué empresa le interesa, es decir, su propia empresa o un objetivo |
| Exactitud del veredicto | Un falso "protegido" deja expuesta a una organización |
| Reputación del autor | El sitio es portafolio profesional |

## Actores

- **Visitante legítimo.**
- **Atacante que controla un dominio:** puede publicar registros TXT arbitrarios (SPF, DMARC, DKIM) con contenido hostil.
- **Atacante en la red:** intercepta o altera el tráfico.
- **Atacante en la cadena de suministro:** compromete una dependencia, la plataforma de alojamiento o la cuenta de GitHub.
- **Sitio de terceros:** intenta incrustar la página para engañar al usuario (clickjacking).

## Superficies

Campo de entrada, respuestas DoH (contenido controlado por terceros), archivo HTML desplegado, repositorio y canalización de despliegue.

## Amenazas y mitigaciones

| STRIDE | Amenaza | Mitigación | Riesgo residual |
|---|---|---|---|
| Suplantación | Resolver DoH falso | Solo se contactan `cloudflare-dns.com` y `dns.google` por HTTPS; la CSP `connect-src` lo impone | Confianza en esos dos proveedores |
| Manipulación | Registro TXT con HTML o JavaScript (XSS almacenado en DNS) | Todo el DOM se construye con `textContent`; CSP sin `unsafe-inline` para scripts; prueba de extremo a extremo con un registro hostil | Bajo |
| Manipulación | Inyección de `</script>` a través de los datos embebidos | Al construir, `<` se escapa como `\u003c` en el JSON embebido | Bajo |
| Manipulación | Alteración del HTML desplegado | Hash SHA-256 de cada script en la CSP; despliegue desde un repositorio con rama protegida y 2FA | Compromiso de la cuenta de despliegue |
| Repudio | No aplica: no hay acciones con efectos ni cuentas | | |
| Divulgación | El dominio consultado viaja a terceros | Solo a los resolvers DNS (inevitable para consultar DNS); sin cookies ni `Referer`; la preferencia de lectura Simple/Técnica es el único dato en `localStorage`; las métricas opcionales (Cloudflare Web Analytics) solo ven la visita, no el dominio, porque el análisis no sale del navegador | Cloudflare y Google ven la consulta, como en cualquier resolución DNS |
| Divulgación | Exponer resultados de organizaciones del observatorio | Solo se publican agregados; un control en el repositorio privado impide publicar el agregado si contiene dominios de la muestra | Bajo |
| Denegación de servicio | Registros diseñados para multiplicar consultas (SPF recursivo, cientos de destinos `rua`, nombres muy profundos) | Detección de bucles y límite de 10 consultas en SPF; recorrido DMARC de máximo 8 niveles; máximo 4 destinos `rua` verificados en paralelo; tope global de 150 consultas por análisis; caché, concurrencia limitada y tiempos de espera | Un análisis lento afecta solo al visitante |
| Denegación de servicio | Registro TXT enorme | Truncado a 4096 caracteres | Bajo |
| Elevación de privilegios | Ejecución de código por dependencias | Sin dependencias en producción; Playwright solo en desarrollo, fijado por versión y lockfile | Bajo |
| Integridad del resultado | Falso "protegido" por un error de lógica | Detección de SPF abierto por vía directa o indirecta (`+all`, `include` hacia `+all`, `ip4` hasta /8, `ip6` hasta /32, `exists` sin macro); simulación en el peor caso para `pct` y `t=y`; validación estricta de `v=DMARC1`; pruebas de regresión por cada hallazgo de la revisión independiente | Rangos amplios repartidos en varios términos no se suman; dominio organizacional aproximado sin la Public Suffix List completa |
| Clickjacking | Incrustar la página en un marco | `frame-ancestors 'none'` y `X-Frame-Options: DENY` por cabecera en Cloudflare Pages | En GitHub Pages no se pueden fijar cabeceras |

## Fuera del alcance

Seguridad interna de los resolvers DoH, de la plataforma de alojamiento y de los navegadores.
