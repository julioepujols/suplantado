# Metodología del observatorio

## Pregunta

¿Qué proporción de organizaciones dominicanas puede ser suplantada por correo electrónico, es decir, no le pide a los servidores receptores que rechacen o pongan en cuarentena los correos falsos que usan su dominio?

## Muestra

- **Unidad de análisis:** el dominio web principal de cada organización, que es el que reconocen sus clientes y el que un atacante imitaría.
- **Fuentes de candidatos:** Wikidata (organizaciones con país República Dominicana y sitio web oficial) y directorios públicos de instituciones del Estado, entidades financieras, universidades, medios y empresas.
- **Depuración:**
  - Se descartaron los dominios que no existen en DNS.
  - Se excluyeron duplicados de una misma organización y dominios cuya titularidad no se pudo confirmar, por ejemplo páginas de estacionamiento de registradores o sitios informativos no oficiales.
  - La titularidad se verificó con el título de la página principal.
- **Resultado:** 255 candidatos, 19 sin DNS, 9 excluidos, **227 analizados**, agrupados en 8 sectores.

Es una muestra de conveniencia, no un censo ni una muestra aleatoria. Las cifras describen a esas 227 organizaciones y no deben extrapolarse como estadística nacional.

## Medición

- Mismo motor que la herramienta pública (`src/engine.js`), ejecutado en Node.
- Solo consultas DNS públicas vía DoH y una petición GET a la página principal para confirmar la titularidad. Sin escaneo de puertos, sin conexiones SMTP, sin envío de correos.
- Ejecución lenta a propósito: 3 dominios en paralelo.
- Fecha del corte: 19 de octubre de 2026.

## Definiciones

| Término | Definición |
|---|---|
| Suplantable | Sin registro DMARC válido, o con política efectiva `none` (incluye `quarantine` o `reject` rebajadas por `t=y`). Un correo falso con el dominio exacto no es rechazado ni enviado a spam por política. |
| Política efectiva | `p` del dominio, o `sp` si el registro se hereda del dominio organizacional. El modo prueba `t=y` la rebaja un nivel. |
| Subdominio suplantable | La política aplicable a un subdominio inexistente (`np`, luego `sp`, luego `p`) es `none` o no hay DMARC. |
| SPF con errores | Error permanente: varios registros, más de 10 consultas, más de 2 consultas vacías, inclusiones inexistentes o circulares, o sintaxis inválida. |

## Limitaciones

- DKIM: se prueban 41 selectores comunes; no encontrar una clave no prueba que no exista.
- Una política DMARC estricta no garantiza que el correo esté bien configurado: puede rechazar correo legítimo si SPF o DKIM están incompletos.
- Los receptores aplican además sus propios filtros. "Suplantable" significa que nada lo bloquea por política, no que todo correo falso llegue a la bandeja.
- Las configuraciones cambian: el resultado refleja un día concreto.

## Comparación con otros estudios

PowerDMARC (2026) reporta entre 16% y 25% de dominios con `p=reject` en México, Perú, Argentina, Brasil y Ecuador, y no incluye a República Dominicana. Sus muestras y métodos son distintos, así que la comparación es solo de contexto, no un ranking.

## Ética y divulgación responsable

- Se publican solo cifras agregadas por sector; ninguna organización se nombra en público.
- Los resultados por organización se guardan fuera de este repositorio y se comparten solo con la organización afectada, si lo solicita o al notificarla de forma privada.
- El análisis usa la misma información que consulta cualquier servidor de correo del mundo al recibir un mensaje.
