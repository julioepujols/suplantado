# Revisión de seguridad independiente

- Versión revisada: 1.0.0 previa al lanzamiento (commit `bfff265`).
- Fecha: 19 de octubre de 2026.
- Método: un revisor que no participó en el desarrollo leyó el código completo y ejecutó una prueba de concepto por cada hallazgo, con todo el DNS simulado. Solo se reportó lo que se pudo demostrar.
- Resultado: no hubo XSS, inyección de HTML, ruptura de la CSP ni problemas en la CI. Se confirmaron 6 hallazgos de exactitud y robustez, todos corregidos antes de publicar.

| # | Hallazgo | Severidad | Estado |
|---|---|---|---|
| 1 | Veredicto "riesgo bajo" cuando el SPF autoriza a cualquiera por vías indirectas: `include` hacia `+all`, `ip6:::/0`, `exists` sin macro | Alta | Corregido. Cálculo único de "SPF abierto" (`openToAll`) usado en el veredicto y en la simulación |
| 2 | La simulación mostraba "Rechazado" con `+all` antes de superar el límite de consultas, con un rango ip4 amplio o con `pct` menor que 100 | Media | Corregido. La simulación usa el peor caso posible |
| 3 | Dominio organizacional incorrecto en sufijos como `co.za` o `com.sg` | Baja | Corregido con una aproximación por segundos niveles genéricos de ccTLD. Pendiente: incluir la Public Suffix List |
| 4 | Amplificación de consultas DNS: cientos de destinos `rua` y nombres muy profundos | Baja | Corregido. Máximo 4 destinos `rua` en paralelo, recorrido DMARC de 8 niveles y tope global de 150 consultas |
| 5 | Validación de `v=DMARC1` sin distinguir mayúsculas | Informativa | Corregido. Validación exacta según el ABNF |
| 6 | `contact.email` sin validar al generar `security.txt` | Informativa | Corregido. La construcción falla ante un correo inválido |

Endurecimientos adicionales aplicados: expresión regular lineal para CAA en formato genérico y lectura de TXT acotada a 4096 caracteres.

Verificado como no vulnerable: inyección desde cualquier campo DNS (prueba con cargas hostiles en SPF, DMARC, DKIM, MX, CAA y MTA-STS), escape de datos embebidos al construir, CSP generada, expresiones regulares ante entradas de 4096 caracteres, recursión SPF, contaminación de prototipos y permisos y fijación por SHA de la CI.

Cada hallazgo tiene su prueba de regresión en `test/engine.test.js` (sección "Regresiones de la revisión de seguridad independiente").
