# JWT Debug Tool

![HTML](https://img.shields.io/badge/HTML-E34F26?logo=html5&logoColor=white) ![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?logo=javascript&logoColor=black) ![License](https://img.shields.io/badge/license-MIT-green)

Herramienta web para decodificar, verificar y generar JSON Web Tokens (JWT) — todo en el navegador, sin enviar datos a ningún servidor. Deployable directamente en GitHub Pages.

## Instalación en 3 comandos

```bash
git clone https://github.com/Quesillo27/jwt-debug-tool
cd jwt-debug-tool
# Abrir index.html en el navegador — sin servidor necesario
```

## Uso

```bash
# Opción 1: abrir directamente
open index.html    # macOS
xdg-open index.html  # Linux

# Opción 2: servir localmente
python3 -m http.server 8080
# → Abrir http://localhost:8080
```

## Ejemplo

```bash
# JWT de ejemplo para probar:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyIsIm5hbWUiOiJKdWFuIFDDqXJleiIsInJvbGUiOiJhZG1pbiJ9.xyz

# En la pestaña "Verificar firma":
# Secret: secret
# → ✅ Firma válida — Token auténtico
```

## Funcionalidades

| Pestaña | Descripción |
|---------|-------------|
| **Decodificar** | Muestra header, payload y signature con syntax highlighting. Tabla de claims con descripciones y timestamps legibles. Detecta tokens expirados. |
| **Verificar firma** | Verifica firma HMAC (HS256/384/512) y RSA (RS256/384/512) usando la Web Crypto API del navegador. |
| **Generar JWT** | Genera tokens firmados con HS256/384/512. Claims personalizables en JSON. Expiración configurable. |

## Algoritmos soportados

- **HS256, HS384, HS512** — HMAC-SHA (firma y verificación)
- **RS256, RS384, RS512** — RSA-PKCS1v1.5 (solo verificación con clave pública PEM)

## Privacidad

**100% del lado del cliente.** Ningún dato sale del navegador. Usa la [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) nativa para operaciones criptográficas.

## Deploy en GitHub Pages

1. Fork/clonar el repo
2. En Settings → Pages → Source: `main` branch, carpeta `/` (root)
3. Listo — accesible en `https://tuusuario.github.io/jwt-debug-tool/`

## Variables de entorno

No aplica — es una app estática sin backend.

## Contribuir

PRs bienvenidos. La herramienta es intencionalmente un único archivo HTML+JS para facilitar el deploy y uso sin dependencias.
