# shopify-theme-security

Skill para [Claude Code](https://docs.claude.com/en/docs/claude-code) que audita la seguridad de temas de Shopify: XSS en Liquid y JavaScript, secretos expuestos, scripts de terceros inseguros, librerías vulnerables, redirecciones abiertas, fugas de datos de clientes y código heredado.

Combina un escáner automático (Python, sin dependencias) con una revisión manual guiada, y entrega un informe `SECURITY_REPORT.md` priorizado por severidad con el código corregido para cada hallazgo.

## Instalación

Para todos tus proyectos:

```bash
git clone https://github.com/<TU_USUARIO>/shopify-theme-security.git ~/.claude/skills/shopify-theme-security
```

Solo para un proyecto (desde la raíz del tema):

```bash
git clone https://github.com/<TU_USUARIO>/shopify-theme-security.git .claude/skills/shopify-theme-security
```

Para actualizar: `git pull` dentro de la carpeta de la skill.

## Uso

Abre Claude Code en la raíz de tu tema y pide, por ejemplo:

- "Revisa la seguridad del tema"
- "¿Es seguro mi theme antes de publicarlo?"
- "Busca XSS y tokens expuestos en el tema"

Claude ejecuta el escáner, confirma cada hallazgo leyendo el código, descarta falsos positivos y genera el informe. Antes de modificar archivos te pide permiso, y nunca publica el tema (`shopify theme push`) por su cuenta.

### Escáner sin Claude

El escáner también funciona solo, por ejemplo en CI:

```bash
python3 scripts/scan_theme.py ruta/al/tema                     # informe en Markdown
python3 scripts/scan_theme.py ruta/al/tema --format json       # para procesar
python3 scripts/scan_theme.py ruta/al/tema --min-severity high # solo lo grave
```

Requiere Python 3.8 o superior.

## Qué revisa

| Área | Ejemplos |
|---|---|
| Liquid | Datos del visitante sin `\| escape`; Liquid entrecomillado dentro de `<script>` en lugar de `\| json` |
| JavaScript | `innerHTML`, `eval`, `document.write`, `.html()` con datos de la URL o del carrito; `postMessage` sin verificar origen; redirecciones abiertas |
| Secretos | Tokens de Admin API (`shpat_`, `shpca_`, `shppa_`, `shpss_`), Stripe, AWS, SendGrid, Slack, GitHub, Klaviyo |
| Terceros | jQuery < 3.5, recursos por HTTP, CDN sin SRI, versiones `@latest`, scripts de apps abandonadas |
| Configuración | Traducciones `_html` con scripts, ajustes `html`/`liquid`, `checkout.liquid` heredado, formularios sin `{% form %}` |
| Revisión manual | PII en JS global y dataLayer, seguridad falsa del lado del cliente, búsqueda predictiva y carrito AJAX |

La checklist completa está en [`references/checklist.md`](references/checklist.md).

## Estructura

```
shopify-theme-security/
├── SKILL.md                 # Flujo de auditoría que sigue Claude
├── references/checklist.md  # Guía de revisión manual por áreas
└── scripts/scan_theme.py    # Escáner automático
```

## Limitaciones

El escáner usa patrones y produce falsos positivos y negativos; no sustituye una revisión humana ni un pentest. No analiza apps instaladas fuera del tema (theme app extensions, píxeles) ni la configuración del admin de Shopify.

## Licencia

MIT
