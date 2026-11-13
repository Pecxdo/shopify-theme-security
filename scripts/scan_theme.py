#!/usr/bin/env python3
"""
Escáner de seguridad para temas de Shopify.

Uso:
    python3 scan_theme.py <ruta-del-tema> [--format markdown|json] [--min-severity low]

Detecta patrones de riesgo; NO sustituye la revisión manual. Cada hallazgo
debe confirmarse leyendo el código (ver SKILL.md, paso 3).
Solo usa la biblioteca estándar de Python 3.8+.
"""
import argparse
import json
import os
import re
import sys

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
THEME_DIRS = ["layout", "templates", "sections", "snippets", "blocks", "assets", "config", "locales"]
TEXT_EXT = {".liquid", ".js", ".json", ".css", ".scss", ".html", ".svg", ".mjs", ".ts"}
MAX_FILE_BYTES = 3 * 1024 * 1024

findings = []


def add(sev, rule, path, line, msg, snippet=""):
    findings.append({
        "severity": sev,
        "rule": rule,
        "file": path,
        "line": line,
        "message": msg,
        "snippet": snippet.strip()[:200],
    })


# ---------------------------------------------------------------- Liquid
USER_ROOTS = re.compile(
    r"^\s*(search\.terms|search\.query|request\.(path|host|page_type|origin)|canonical_url|current_page"
    r"|form\.[a-z_]+|line_item\.properties|item\.properties|property\.(last|first)|p\.last|prop\.last"
    r"|cart\.note|cart\.attributes|customer\.(note|first_name|last_name|name|email|phone|tags)"
    r"|address\.[a-z0-9_]+|comment\.(author|body|email)|order\.(note|attributes|customer)"
    r"|blog\.comments|recipient\.[a-z_]+)"
)
SAFE_FILTERS = re.compile(r"\|\s*(escape|json|url_encode|url_escape|url_param_escape|handleize|handle|size|money\w*|date|times|plus|minus|strip_html\s*\|\s*escape)\b")
OUTPUT_TAG = re.compile(r"\{\{-?(.*?)-?\}\}", re.S)
SCRIPT_OPEN = re.compile(r"<script\b(?![^>]*\btype=[\"'](application/ld\+json|text/template|application/json)[\"'])[^>]*>", re.I)
SCRIPT_CLOSE = re.compile(r"</script\s*>", re.I)
QUOTED_LIQUID_IN_JS = re.compile(r"""(["'`])[^"'`\n]*\{\{-?(.*?)-?\}\}[^"'`\n]*\1""")


def scan_liquid(path, text):
    lines = text.splitlines()
    in_script = False
    in_comment = False
    for i, line in enumerate(lines, 1):
        if re.search(r"\{%-?\s*comment\s*-?%\}", line):
            in_comment = True
        if in_comment:
            if re.search(r"\{%-?\s*endcomment\s*-?%\}", line):
                in_comment = False
            continue

        opened = SCRIPT_OPEN.search(line)
        if opened:
            in_script = True
        script_ctx = in_script

        # Salida sin escapar de datos del usuario
        for m in OUTPUT_TAG.finditer(line):
            expr = m.group(1)
            if USER_ROOTS.match(expr) and not SAFE_FILTERS.search(expr):
                sev = "high" if re.match(r"^\s*(search\.terms|request\.|canonical_url|form\.|line_item\.properties|item\.properties|property\.|p\.last|prop\.last|cart\.(note|attributes))", expr) else "medium"
                ctx = "dentro de <script>" if script_ctx else "en HTML"
                add(sev, "liquid-unescaped-user-input", path, i,
                    f"Dato controlado por el usuario impreso sin escapar {ctx}. Usa '| escape' en HTML o '| json' en JS.",
                    line)

        # Liquid entrecomillado dentro de JS
        if script_ctx or path.endswith(".js.liquid"):
            for m in QUOTED_LIQUID_IN_JS.finditer(line):
                expr = m.group(2)
                if "| json" in expr or "|json" in expr:
                    continue
                if re.search(r"\|\s*(asset_url|file_url|img_url|image_url|shopify_asset_url|money|t\b|handleize|url_encode)", expr) or re.match(r"^\s*(routes\.|shop\.(currency|money_format)|settings\.\w+_color|'|\")", expr):
                    sev = "low"
                elif USER_ROOTS.match(expr):
                    sev = "high"
                else:
                    sev = "medium"
                add(sev, "liquid-in-js-string", path, i,
                    "Liquid interpolado dentro de un string de JavaScript. Usa {{ valor | json }} sin comillas.",
                    line)

        if SCRIPT_CLOSE.search(line):
            in_script = False

        # Comentarios HTML con información sensible (se envían al navegador)
        if re.search(r"<!--.*\b(password|contraseña|token|secret|api[_ -]?key|todo|fixme|hack|admin)\b", line, re.I):
            add("low", "html-comment-sensitive", path, i,
                "Comentario HTML visible en el código fuente público con palabras sensibles. Usa {% comment %}.",
                line)

        # target=_blank sin rel
        for m in re.finditer(r"<a\b[^>]*target=[\"']_blank[\"'][^>]*>", line, re.I):
            if not re.search(r"rel=[\"'][^\"']*noopener", m.group(0), re.I):
                add("low", "target-blank-no-rel", path, i,
                    "Enlace target=\"_blank\" sin rel=\"noopener noreferrer\".", m.group(0))

        # iframe sin sandbox
        for m in re.finditer(r"<iframe\b[^>]*>", line, re.I):
            if "sandbox" not in m.group(0).lower():
                add("low", "iframe-no-sandbox", path, i,
                    "iframe sin atributo sandbox; valora restringir permisos si es de terceros.", m.group(0))

        # Formularios a mano a endpoints de Shopify
        if re.search(r"<form\b[^>]*action=[\"']/(contact|account|account/login|account/recover|challenge)", line, re.I):
            add("medium", "manual-shopify-form", path, i,
                "Formulario escrito a mano hacia un endpoint de Shopify. Usa la etiqueta {% form %} para mantener form_type y la protección anti-spam.",
                line)

        # Ajustes html/liquid en el {% schema %} de secciones y bloques
        for _ in re.finditer(r"\"type\"\s*:\s*\"(html|liquid)\"", line):
            add("info", "raw-html-setting", path, i,
                "Ajuste de tipo html/liquid: cualquier colaborador con acceso al editor puede inyectar código.", line)

        # return_to dinámico
        if re.search(r"return_to[\"']?\s+value=[\"']\{\{\s*(request|canonical_url|current_page)", line):
            add("medium", "dynamic-return-to", path, i,
                "return_to construido desde la URL de la petición; usa una ruta fija.", line)


# ---------------------------------------------------------------- JS
JS_SINKS = [
    (r"\.(innerHTML|outerHTML)\s*\+?=", "innerHTML/outerHTML"),
    (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML"),
    (r"\bdocument\.write(ln)?\s*\(", "document.write"),
    (r"(?<![\w.])eval\s*\(", "eval"),
    (r"\bnew\s+Function\s*\(", "new Function"),
    (r"\bset(Timeout|Interval)\s*\(\s*[\"'`]", "setTimeout/setInterval con string"),
    (r"\.html\s*\(\s*[^)\s]", "jQuery .html()"),
    (r"createContextualFragment\s*\(", "createContextualFragment"),
]
JS_SOURCES = re.compile(r"location\.(search|hash|href)|URLSearchParams|document\.referrer|window\.name|event\.data|e\.data|\.properties|cart\.note|\.attributes|searchParams|getParameter|query")


def scan_js(path, text, offset_note=""):
    lines = text.splitlines()
    minified = any(len(l) > 1500 for l in lines[:5])
    for i, line in enumerate(lines, 1):
        for pat, name in JS_SINKS:
            if re.search(pat, line):
                tainted = bool(JS_SOURCES.search(line))
                literal_only = re.search(pat + r"\s*[\"'][^\"'$`]*[\"']\s*;?\s*$", line)
                if literal_only and not tainted:
                    continue
                sev = "high" if tainted else ("low" if minified else "medium")
                add(sev, "js-dangerous-sink", path, i,
                    f"Uso de {name}" + (" con una fuente controlable por el usuario en la misma línea" if tainted else "; verifica el origen del dato") + ". Prefiere textContent/createElement.",
                    line[:200])

        if re.search(r"(window\.)?location(\.href)?\s*=\s*[^=]", line) or re.search(r"location\.(assign|replace)\s*\(", line):
            if re.search(r"get\(|search|hash|param|redirect|return|next|url\b", line, re.I) and not re.search(r"location\.(href|pathname)\s*=\s*[\"'`]/", line):
                add("high", "js-open-redirect", path, i,
                    "Posible redirección abierta: la URL de destino parece venir de la petición. Valida que sea relativa o de una lista blanca.",
                    line[:200])

    if re.search(r"addEventListener\s*\(\s*[\"']message[\"']", text) or re.search(r"\bonmessage\s*=", text):
        if not re.search(r"\.origin\b", text):
            ln = next((n for n, l in enumerate(lines, 1) if "message" in l and ("addEventListener" in l or "onmessage" in l)), 0)
            add("medium", "postmessage-no-origin", path, ln,
                "Listener de postMessage sin comprobación de event.origin.", lines[ln - 1] if ln else "")

    m = re.search(r"jQuery\s+(JavaScript Library\s+)?v?(\d+)\.(\d+)\.(\d+)", text[:3000])
    if m:
        major, minor = int(m.group(2)), int(m.group(3))
        if (major, minor) < (3, 5):
            add("high", "vulnerable-jquery", path, 1,
                f"jQuery {m.group(2)}.{m.group(3)}.{m.group(4)} tiene XSS conocidos (CVE-2020-11022/11023). Actualiza a >= 3.5.0 o elimínalo.", m.group(0))


# ---------------------------------------------------------------- Secretos
SECRETS = [
    ("critical", r"\bshpat_[a-fA-F0-9]{32}\b", "Token de Admin API de Shopify (shpat_)"),
    ("critical", r"\bshpca_[a-fA-F0-9]{32}\b", "Token de app personalizada de Shopify (shpca_)"),
    ("critical", r"\bshppa_[a-fA-F0-9]{32}\b", "Contraseña de app privada de Shopify (shppa_)"),
    ("critical", r"\bshpss_[a-fA-F0-9]{32}\b", "Secreto compartido de app de Shopify (shpss_)"),
    ("critical", r"\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b", "Clave secreta de Stripe"),
    ("critical", r"\bAKIA[0-9A-Z]{16}\b", "Access key de AWS"),
    ("critical", r"\bSG\.[\w-]{22}\.[\w-]{43}\b", "API key de SendGrid"),
    ("critical", r"\bxox[baprs]-[0-9A-Za-z-]{10,}", "Token de Slack"),
    ("high", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", "Webhook de Slack"),
    ("critical", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "Token de GitHub"),
    ("high", r"\bpk_[a-f0-9]{34}\b", "Posible clave privada de Klaviyo"),
    ("critical", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Clave privada"),
    ("high", r"https?://[^\s:/\"']+:[^\s@/\"']+@", "URL con credenciales embebidas"),
    ("medium", r"\bAIza[0-9A-Za-z_-]{35}\b", "API key de Google (verifica que esté restringida por dominio)"),
    ("medium", r"(?i)[\"']?(api[_-]?secret|client[_-]?secret|private[_-]?key|password|passwd)[\"']?\s*[:=]\s*[\"'][^\"'\s{]{8,}[\"']", "Posible secreto asignado en código"),
]


def scan_secrets(path, text):
    for i, line in enumerate(text.splitlines(), 1):
        for sev, pat, name in SECRETS:
            if re.search(pat, line):
                masked = re.sub(pat, lambda m: m.group(0)[:8] + "…[oculto]", line)
                add(sev, "exposed-secret", path, i,
                    f"{name}. Todo el contenido del tema es público: rota el secreto y elimínalo del tema.", masked)


# ---------------------------------------------------------------- Recursos externos
def scan_external(path, text):
    for i, line in enumerate(text.splitlines(), 1):
        for m in re.finditer(r"<(script|link)\b[^>]*(src|href)=[\"']((https?:)?//[^\"']+)[\"'][^>]*>", line, re.I):
            tag, url = m.group(0), m.group(3)
            if "cdn.shopify.com" in url or "{{" in url or "fonts.googleapis" in url or "fonts.shopifycdn" in url:
                continue
            if url.startswith("http://"):
                add("medium", "insecure-http-resource", path, i, "Recurso cargado por HTTP (contenido mixto).", tag)
            if m.group(1).lower() == "script" and "integrity=" not in tag.lower():
                if re.search(r"(cdnjs|jsdelivr|unpkg|code\.jquery|ajax\.googleapis|stackpath|bootstrapcdn)", url):
                    add("medium", "cdn-script-no-sri", path, i,
                        "Librería de CDN público sin Subresource Integrity (integrity + crossorigin).", tag)
                else:
                    add("info", "third-party-script", path, i,
                        "Script de terceros: confirma que el dominio y la app siguen siendo legítimos y necesarios.", tag)
            if re.search(r"@latest|/latest/", url):
                add("medium", "unpinned-version", path, i, "Recurso externo sin versión fija (@latest).", tag)
            jm = re.search(r"jquery[-.@/]?(\d)\.(\d+)", url, re.I)
            if jm and (int(jm.group(1)), int(jm.group(2))) < (3, 5):
                add("high", "vulnerable-jquery", path, i,
                    f"jQuery {jm.group(1)}.{jm.group(2)} cargado desde CDN; versiones < 3.5 tienen XSS conocidos.", tag)


# ---------------------------------------------------------------- Config / locales
def scan_config(path, text):
    name = os.path.basename(path)
    if name == "settings_schema.json" or "/sections/" in path or "/blocks/" in path:
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"\"type\"\s*:\s*\"(html|liquid)\"", line):
                add("info", "raw-html-setting", path, i,
                    "Ajuste de tipo html/liquid: cualquier colaborador con acceso al editor puede inyectar código.", line)
    if path.replace("\\", "/").split("/")[-2:-1] == ["locales"]:
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"_html\"\s*:\s*\".*(<script|on\w+\s*=|javascript:)", line, re.I):
                add("high", "locale-html-script", path, i,
                    "Traducción *_html con script o handler de evento; se imprime sin escapar.", line)
    if name == "settings_data.json":
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"<script|javascript:|on(error|load|click)\s*=", line, re.I):
                add("medium", "settings-data-script", path, i,
                    "settings_data.json contiene script o handlers; revisa quién lo añadió y si sigue siendo necesario.", line[:200])


# ---------------------------------------------------------------- Principal
def iter_files(root):
    for d in THEME_DIRS:
        base = os.path.join(root, d)
        if not os.path.isdir(base):
            continue
        for dp, dns, fns in os.walk(base):
            dns[:] = [x for x in dns if x != "node_modules"]
            for fn in fns:
                full = os.path.join(dp, fn)
                if os.path.splitext(fn)[1].lower() in TEXT_EXT or fn.endswith(".js.liquid"):
                    yield full


def main():
    ap = argparse.ArgumentParser(description="Escáner de seguridad para temas Shopify")
    ap.add_argument("theme", help="Ruta a la raíz del tema")
    ap.add_argument("--format", choices=["markdown", "json"], default="markdown")
    ap.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="info")
    args = ap.parse_args()

    root = os.path.abspath(args.theme)
    if not any(os.path.isdir(os.path.join(root, d)) for d in ("layout", "sections", "templates")):
        print(f"No parece la raíz de un tema de Shopify: {root}", file=sys.stderr)
        sys.exit(2)

    count = 0
    for full in iter_files(root):
        if os.path.getsize(full) > MAX_FILE_BYTES:
            continue
        rel = os.path.relpath(full, root).replace("\\", "/")
        try:
            with open(full, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        count += 1
        scan_secrets(rel, text)
        if rel.endswith(".liquid"):
            scan_liquid(rel, text)
            scan_external(rel, text)
            # JS embebido en Liquid
            scan_js(rel, text)
        elif rel.endswith((".js", ".mjs", ".ts")):
            scan_js(rel, text)
        elif rel.endswith(".json"):
            scan_config(rel, text)

    if os.path.isfile(os.path.join(root, "layout", "checkout.liquid")):
        add("medium", "legacy-checkout-liquid", "layout/checkout.liquid", 0,
            "checkout.liquid ya no está soportado por Shopify; migra a Checkout Extensibility y elimina el archivo.")
    theme_liquid = os.path.join(root, "layout", "theme.liquid")
    if os.path.isfile(theme_liquid):
        with open(theme_liquid, encoding="utf-8", errors="replace") as f:
            if "content_for_header" not in f.read():
                add("medium", "missing-content-for-header", "layout/theme.liquid", 0,
                    "Falta {{ content_for_header }}; rompe scripts de Shopify y apps.")
    if os.path.isfile(os.path.join(root, "package.json")):
        add("info", "has-npm-deps", "package.json", 0,
            "El tema tiene dependencias npm: ejecuta 'npm audit --omit=dev'.")

    # deduplicar y filtrar
    seen, result = set(), []
    for f in findings:
        k = (f["rule"], f["file"], f["line"], f["snippet"])
        if k in seen or SEVERITY_ORDER[f["severity"]] > SEVERITY_ORDER[args.min_severity]:
            continue
        seen.add(k)
        result.append(f)
    result.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["file"], f["line"]))

    summary = {s: sum(1 for f in result if f["severity"] == s) for s in SEVERITY_ORDER}
    if args.format == "json":
        print(json.dumps({"theme": root, "files_scanned": count, "summary": summary, "findings": result},
                         ensure_ascii=False, indent=2))
        return

    print(f"# Escaneo automático de seguridad\n\nTema: `{root}`  \nArchivos analizados: {count}\n")
    print("| Severidad | Hallazgos |\n|---|---|")
    for s, n in summary.items():
        print(f"| {s} | {n} |")
    print("\n> Hallazgos automáticos: confirma cada uno leyendo el código antes de reportarlo.\n")
    current = None
    for f in result:
        if f["severity"] != current:
            current = f["severity"]
            print(f"\n## {current.upper()}\n")
        loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        print(f"- **[{f['rule']}]** `{loc}` — {f['message']}")
        if f["snippet"]:
            print(f"  ```\n  {f['snippet']}\n  ```")


if __name__ == "__main__":
    main()
