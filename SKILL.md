---
name: shopify-theme-security
description: Auditoría de seguridad completa para temas de Shopify (Liquid, JavaScript, CSS, config y locales). Úsala siempre que el usuario quiera revisar, auditar, validar o endurecer la seguridad de un tema de Shopify, buscar XSS, inyección en Liquid, secretos o tokens expuestos, scripts de terceros inseguros, librerías vulnerables (jQuery viejo), redirecciones abiertas, fugas de datos de clientes o código heredado como checkout.liquid. Actívala también ante frases como "revisa mi tema", "¿es seguro mi theme?", "security review shopify", "auditar theme", "antes de publicar el tema", o cuando el directorio de trabajo tenga la estructura de un tema (layout/, sections/, snippets/, templates/, config/settings_schema.json) y el usuario hable de seguridad, vulnerabilidades o buenas prácticas, aunque no diga "skill" ni "auditoría".
---

# Auditoría de seguridad de temas Shopify

Esta skill revisa un tema de Shopify de punta a punta y entrega un informe priorizado con hallazgos accionables. Combina un escáner automático (rápido, encuentra patrones) con una revisión manual guiada (necesaria, porque muchos problemas dependen del contexto que un regex no entiende).

## Contexto importante

Un tema de Shopify se ejecuta en el navegador de cada cliente de la tienda. Las consecuencias reales de un fallo son: robo de sesión de clientes, páginas de phishing servidas desde el dominio de la tienda, scripts maliciosos inyectados vía datos que controla el visitante (búsqueda, propiedades de línea del carrito, notas, atributos) y secretos de la Admin API filtrados que dan control total de la tienda. Prioriza siempre por impacto real, no por cantidad de hallazgos.

Liquid en Shopify **no escapa automáticamente** la salida de `{{ }}`. Cualquier dato que pueda venir del visitante debe pasar por `| escape` en HTML o `| json` dentro de `<script>`.

## Flujo de trabajo

### 1. Reconocer el tema

Confirma que estás en la raíz de un tema (carpetas `layout/`, `sections/`, `snippets/`, `templates/`, `assets/`, `config/`). Si el tema está en otra ruta, pregúntala o búscala. Anota:
- Si es Online Store 2.0 (templates `.json`) o heredado (`.liquid`).
- Si existe `layout/checkout.liquid` (obsoleto; ver referencia).
- Si hay tooling de build (`package.json`, `node_modules`, `src/`), porque entonces también hay que revisar dependencias.

### 2. Ejecutar el escáner automático

```bash
python3 <ruta-de-la-skill>/scripts/scan_theme.py <ruta-del-tema> --format markdown > /tmp/theme-scan.md
```

Usa `--format json` si vas a procesar los resultados. El escáner revisa: salida Liquid sin escapar de fuentes controladas por el usuario, interpolación de Liquid dentro de `<script>` sin `| json`, sinks peligrosos de JS (`innerHTML`, `eval`, `document.write`, `.html()`…), listeners de `postMessage` sin verificación de origen, redirecciones abiertas, secretos y tokens, scripts externos sin SRI o por HTTP, jQuery vulnerable, `target="_blank"` sin `rel`, iframes sin `sandbox`, comentarios HTML con información sensible, ajustes de tipo `html`/`liquid` en el schema y `checkout.liquid`.

Si además existen herramientas del ecosistema, úsalas, porque cubren cosas que el escáner no:
- `shopify theme check` (Shopify CLI): buenas prácticas y algunos chequeos de assets remotos.
- `npm audit --omit=dev` si hay `package.json`.

Si no están instaladas, no las instales sin preguntar; menciona en el informe que conviene correrlas.

### 3. Validar cada hallazgo a mano

El escáner produce falsos positivos y se le escapan cosas. Para cada hallazgo **crítico, alto y medio**, abre el archivo y confirma:
- **¿De dónde viene el dato?** Un `innerHTML` con un string fijo es inofensivo; con `location.search`, una respuesta de `/search/suggest.json` o propiedades del carrito, no lo es. Sigue la variable hacia atrás.
- **¿En qué contexto se imprime?** HTML, atributo, URL, `<script>`, CSS. Cada uno necesita una defensa distinta (detalle en `references/checklist.md`).
- **¿Quién controla el valor?** Visitante (alto riesgo) > cliente con cuenta > comerciante/colaborador del tema (riesgo bajo, salvo que haya colaboradores externos no confiables).

Descarta los falsos positivos y explica brevemente por qué en el informe (sección "Descartados"), para que el usuario vea que se revisaron.

### 4. Revisión manual de lo que el escáner no detecta

Lee `references/checklist.md` y recorre las secciones relevantes. Las más importantes, que solo se ven leyendo código:
- Flujos de búsqueda predictiva, carrito AJAX, quick view y drawers que construyen HTML en JS a partir de JSON.
- Formularios propios que no usan `{% form %}`.
- Datos personales del cliente expuestos en `window.*`, `data-*` o dataLayer de analítica.
- Lógica de "seguridad" en el cliente (precios, descuentos, páginas "privadas" ocultas con JS o CSS), que no protege nada.
- Apps y snippets de terceros incrustados a mano.

### 5. Entregar el informe

Guarda `SECURITY_REPORT.md` en la raíz del tema (o donde indique el usuario) con esta estructura:

```markdown
# Informe de seguridad del tema: <nombre>
Fecha · Ruta · Tipo de tema · Herramientas usadas

## Resumen
2-4 frases: estado general, número de hallazgos por severidad, los 3 arreglos más urgentes.

## Hallazgos
### [SEVERIDAD] Título corto
- **Archivo:** ruta:línea
- **Problema:** qué pasa y cómo se explotaría, en una o dos frases.
- **Código actual:** fragmento mínimo
- **Arreglo:** fragmento corregido
(ordenados de crítico a bajo)

## Descartados
Hallazgos del escáner que no son problema y por qué.

## Recomendaciones generales
Lo que no es un bug concreto pero conviene (theme check, auditoría de apps, permisos de colaboradores…).
```

Severidades:
- **Crítico:** secreto de Admin API/pago expuesto; XSS explotable por cualquier visitante sin interacción especial.
- **Alto:** XSS que requiere un enlace manipulado o datos del carrito; jQuery < 3.5 usado con HTML dinámico; redirección abierta.
- **Medio:** sinks peligrosos con datos de origen dudoso; scripts externos sin SRI; PII en JS global; `postMessage` sin origen.
- **Bajo / Info:** `target="_blank"` sin `rel`, comentarios HTML, ajustes `html` en el schema, higiene general.

### 6. Ofrecer arreglos

Pregunta al usuario si quiere que apliques las correcciones. Si acepta, aplícalas de una en una empezando por las críticas, mostrando el diff, y no cambies comportamiento visual ni funcional más allá de lo necesario. Nunca hagas `shopify theme push` ni publiques el tema sin permiso explícito; sugiere probar en un tema no publicado (`shopify theme dev` o un duplicado).

## Principios

- Explica el riesgo en términos del negocio ("un atacante puede mandar un enlace que roba la sesión del cliente"), no solo en jerga.
- No generes payloads de explotación funcionales; basta con describir el vector.
- Si encuentras un secreto real, recomienda **rotarlo de inmediato** en el admin de Shopify o el proveedor, además de quitarlo del código: ya está en el historial de versiones del tema y posiblemente en git.
