# 0003. Publicar solo cifras agregadas del observatorio

- Estado: aceptada
- Fecha: 2026-10-19

## Contexto

Nombrar públicamente a organizaciones con configuraciones débiles daría visibilidad, pero las expone a atacantes y genera riesgo legal y reputacional para el autor.

## Decisión

El sitio y este repositorio contienen solo agregados por sector. La lista de dominios, los resultados por organización y el escáner por lotes viven en un repositorio privado; los resultados nunca se versionan en Git. Un control automático impide publicar un agregado que contenga dominios de la muestra.

## Consecuencias

- Divulgación responsable: cada organización recibe su resultado de forma privada.
- El observatorio es verificable en su método, pero no replicable sin rehacer la recolección.
