# Checklist de seguridad para temas Shopify

Contenido:
1. Salida Liquid y escapado por contexto
2. Liquid dentro de JavaScript
3. JavaScript del tema (sinks DOM)
4. Búsqueda, carrito AJAX y vistas dinámicas
5. Secretos y credenciales
6. Scripts y recursos de terceros
7. Formularios y cuentas de cliente
8. Datos personales (PII) y analítica
9. Redirecciones y navegación
10. Configuración del tema (schema, settings_data, locales)
11. Código heredado y dependencias
12. Falsa seguridad del lado del cliente

---

## 1. Salida Liquid y escapado por contexto

Liquid de Shopify no escapa por defecto. Fuentes que controla el visitante y deben escaparse siempre:

- `search.terms`, `search.results` (títulos vienen del comerciante, pero los términos no)
- `request.path`, `request.host`, `canonical_url`, `current_page` en URLs construidas a mano
- `line_item.properties` / `item.properties` (cualquiera puede enviar propiedades arbitrarias a `/cart/add`)
- `cart.note`, `cart.attributes`
- `form.*` (valores devueltos tras un error: `form.email`, `form.body`, `form.first_name`…)
- `customer.*`, `address.*`, `order.*` (los rellena el cliente)
- `blog.comments` / `comment.*`
- `product.metafields` / `metaobject` cuando el contenido se rellena desde apps o importaciones no confiables

Defensa por contexto:

| Contexto | Correcto |
|---|---|
| Cuerpo HTML | `{{ x \| escape }}` |
| Atributo HTML | `value="{{ x \| escape }}"` (siempre entre comillas) |
| URL / query string | `{{ x \| url_encode }}` y además `escape` si va en atributo |
| Dentro de `<script>` | `{{ x \| json }}` sin comillas alrededor |
| Atributo `data-*` con JSON | `data-x="{{ x \| json \| escape }}"` |
| CSS | Evitar datos del usuario; si es inevitable, lista blanca |

Ejemplo vulnerable / corregido:

```liquid
{%- comment -%} Mal {%- endcomment -%}
<h1>Resultados para {{ search.terms }}</h1>
{%- for p in item.properties -%}<span>{{ p.last }}</span>{%- endfor -%}

{%- comment -%} Bien {%- endcomment -%}
<h1>Resultados para {{ search.terms | escape }}</h1>
{%- for p in item.properties -%}<span>{{ p.last | escape }}</span>{%- endfor -%}
```

`escape_once` no es sustituto general de `escape`: no re-escapa entidades existentes y eso puede abrir huecos con entradas preparadas.

Los ajustes de tipo `richtext`, `html`, `inline_richtext` y `liquid` se imprimen sin escapar a propósito. Son del comerciante; el riesgo es bajo salvo colaboradores no confiables. No los marques como XSS, sí menciónalos como superficie.

## 2. Liquid dentro de JavaScript

El error más común en temas: interpolar dentro de strings de JS.

```liquid
<script>
  // Mal: una comilla o </script> en el valor rompe el script
  var term = "{{ search.terms }}";
  var term2 = '{{ search.terms | escape }}'; // escape HTML no protege en JS

  // Bien: json produce un literal JS válido y escapa </script>
  var term = {{ search.terms | json }};
  window.themeData = { product: {{ product | json }} };
</script>
```

Revisa también archivos `assets/*.js.liquid`: se procesan con Liquid y tienen el mismo problema.

## 3. JavaScript del tema (sinks DOM)

Sinks peligrosos: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, `setTimeout/setInterval` con string, jQuery `.html()`, `.append(string)`, `$(string)`, `.before/.after(string)`, `DOMParser` + inserción, `Range.createContextualFragment`.

Fuentes peligrosas: `location.search/hash/href`, `URLSearchParams`, `document.referrer`, `window.name`, `postMessage`, respuestas de endpoints que incluyen datos del visitante (`/search/suggest.json`, `/cart.js` con propiedades/notas).

Arreglo preferido: `textContent`, `createElement` + `setAttribute`, o usar la Section Rendering API (el servidor ya renderiza con escapado correcto) en lugar de construir HTML con plantillas literales.

```js
// Mal
drawer.innerHTML += `<li>${item.properties.Grabado}</li>`;
// Bien
const li = document.createElement('li');
li.textContent = item.properties.Grabado;
drawer.appendChild(li);
```

`postMessage`: todo listener debe verificar `event.origin` contra una lista blanca y validar la forma de `event.data`.

## 4. Búsqueda, carrito AJAX y vistas dinámicas

Recorre explícitamente: predictive search, cart drawer / cart notification, quick view / quick add, filtros de colección, recomendaciones, wishlist, recently viewed (suele leer `localStorage`, que un XSS previo pudo envenenar). En cada uno, identifica dónde se convierte JSON en HTML.

## 5. Secretos y credenciales

Un tema es 100 % público: todo lo de `assets/`, `config/settings_data.json` y el HTML renderizado lo puede descargar cualquiera.

Nunca debe haber:
- Tokens de Admin API (`shpat_`), apps personalizadas (`shpca_`), apps privadas (`shppa_`), secretos compartidos (`shpss_`)
- Claves secretas de pago (`sk_live_`, `rk_live_` de Stripe), claves privadas de Klaviyo (`pk_…` largas), AWS (`AKIA…` + secret), SendGrid (`SG.`), Twilio, Slack webhooks, tokens de GitHub
- Contraseñas, URLs con credenciales (`https://user:pass@`)

Son aceptables en el cliente (están diseñados para ello): token público de la Storefront API, Site ID público de Klaviyo, claves publicables `pk_live_` de Stripe, Measurement IDs de Google. Aun así, la API key de Google Maps debe estar restringida por dominio en su consola.

Si aparece un secreto: rotarlo ya. Quitarlo del archivo no basta (historial del tema, git, copias).

## 6. Scripts y recursos de terceros

- Inventario de todo `<script src>`, `{{ '...' | script_tag }}` con URL externa, y snippets de apps pegados a mano en `theme.liquid`.
- Preferir theme app extensions / app embeds frente a código pegado: se desinstalan limpiamente.
- Restos de apps desinstaladas siguen cargando scripts (a veces de dominios abandonados que alguien puede registrar). Verificar que cada dominio externo sigue siendo legítimo.
- Recursos por `http://` (contenido mixto).
- SRI (`integrity` + `crossorigin`) para librerías de CDN públicos con versión fija. No aplica a scripts que cambian (widgets de apps).
- Fijar versiones; nunca `@latest`.

## 7. Formularios y cuentas de cliente

- Usar siempre `{% form 'contact' %}`, `{% form 'customer_login' %}`, etc. Generan los campos ocultos que Shopify espera (`form_type`, `utf8`) y habilitan la protección anti-spam/captcha. Un `<form action="/contact">` escrito a mano evita esas protecciones.
- Campos de contraseña con `autocomplete="current-password"` / `new-password`; email con `autocomplete="email"`.
- No mostrar mensajes que revelen si un email existe más allá de lo que hace Shopify por defecto.
- Formularios que envían datos a servicios externos (newsletter de terceros, webhooks): revisar que el destino es HTTPS y legítimo y que no se envía más PII de la necesaria.

## 8. Datos personales (PII) y analítica

- Buscar `customer.email`, `customer.phone`, `customer.addresses`, `customer.orders` impresos en JS global, `data-*` o dataLayer. Si una integración lo necesita, que sea solo el mínimo y preferiblemente vía Customer Events / Web Pixels en lugar de código del tema.
- Nada de PII en URLs ni en parámetros de seguimiento.
- Consentimiento: los píxeles de marketing deberían respetar la Customer Privacy API.

## 9. Redirecciones y navegación

- `window.location = params.get('redirect')` o similares → redirección abierta (phishing desde el dominio de la tienda). Validar que la URL es relativa (empieza por `/` y no por `//`) o pertenece a una lista blanca.
- `return_to` en formularios: usar rutas fijas, no valores de la URL.
- `target="_blank"` hacia dominios externos: añadir `rel="noopener noreferrer"` (los navegadores modernos ya aplican `noopener` por defecto, por eso es severidad baja).
- `<iframe>` de terceros: `sandbox` con los permisos mínimos y `allow` restringido cuando sea viable.

## 10. Configuración del tema

- `config/settings_data.json`: buscar secretos pegados en ajustes de texto, scripts en ajustes `html`/`liquid`, y URLs externas sospechosas.
- `config/settings_schema.json` y schemas de secciones: los ajustes `html` y `liquid` permiten a cualquier colaborador con acceso al editor inyectar código. Es por diseño, pero conviene saber cuántos hay y limitar quién edita el tema.
- `locales/*.json`: las claves que terminan en `_html` se imprimen sin escapar. Si las traducciones vienen de servicios externos o colaboradores, revisar que no contienen `<script>` ni handlers `on*=`.

## 11. Código heredado y dependencias

- `layout/checkout.liquid`: Shopify lo dejó de soportar (páginas de información en agosto de 2024; thank you y order status en 2025). Si existe, la personalización debe migrarse a Checkout Extensibility; el archivo es código muerto o un riesgo.
- `{{ content_for_header }}` debe estar presente en `theme.liquid` y no debe manipularse ni parsearse.
- jQuery < 3.5.0 tiene XSS conocidos (CVE-2020-11022/11023) al pasar HTML a `.html()`, `.append()`, etc. Actualizar o, mejor, eliminar la dependencia.
- Otras librerías viejas comunes en temas: Fancybox, Slick, Owl Carousel, Handlebars antiguos, lodash < 4.17.21. Comprobar versiones en la cabecera de los archivos de `assets/`.
- Si hay `package.json`: `npm audit --omit=dev` y revisar lo que acaba en el bundle.

## 12. Falsa seguridad del lado del cliente

Señalar como problema de diseño cualquier "protección" que viva en el tema:
- Páginas o productos "privados" ocultos con CSS/JS o con una contraseña comparada en JavaScript. El contenido sigue en el HTML o en `/products/handle.js`.
- Precios, descuentos o límites de cantidad aplicados solo en JS: el carrito se puede manipular por la API AJAX. Deben imponerse con Shopify Functions, descuentos nativos o reglas del checkout.
- Códigos de descuento escritos en el código del tema.
