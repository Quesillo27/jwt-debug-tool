# JWT Debug Tool

![CI](https://github.com/Quesillo27/jwt-debug-tool/actions/workflows/ci.yml/badge.svg)
![Tests](https://img.shields.io/badge/tests-53%20passed-brightgreen)
![HTML](https://img.shields.io/badge/HTML-E34F26?logo=html5&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?logo=javascript&logoColor=black)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-1.1.0-blue)

Herramienta web para decodificar, verificar y generar JSON Web Tokens (JWT) — todo en el navegador, sin enviar datos a ningun servidor. Deployable directamente en GitHub Pages.

## Instalacion rapida

```bash
git clone https://github.com/Quesillo27/jwt-debug-tool
cd jwt-debug-tool
# Abrir index.html en el navegador — sin servidor necesario
```

## Uso

```bash
# Opcion 1: abrir directamente
open index.html    # macOS
xdg-open index.html  # Linux

# Opcion 2: servir localmente
python3 -m http.server 8080
# Abrir http://localhost:8080

# Opcion 3: con npm (instala servidor de desarrollo)
npm run serve
```

## Ejemplo rapido

```
# JWT de ejemplo (pegar en la tab "Decodificar"):
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyIsIm5hbWUiOiJKdWFuIFDDqXJleiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcxMzAwMDAwMCwiZXhwIjo0MDAwMDAwMDAwfQ.sBvV2rT-YxhRz2oiL-WLIJRLvGnYOjPMBHjQGCRU7WM

# Para verificar firma en la tab "Verificar firma":
# Secret: secret
```

O simplemente haz clic en **"Cargar ejemplo"** dentro de la herramienta.

## Funcionalidades

| Tab | Descripcion |
|-----|-------------|
| **Decodificar** | Muestra header, payload y signature con syntax highlighting. Tabla de claims con descripciones y timestamps legibles. Detecta tokens expirados y nbf en el futuro. |
| **Verificar firma** | Verifica HS256/384/512, RS256/384/512 y ES256/384/512 usando la Web Crypto API. Rechaza explicitamente alg:none. |
| **Generar JWT** | Genera tokens firmados con HS256/384/512. Claims personalizables en JSON. Expiracion configurable (15 min a 30 dias). |
| **Historial** | Ultimos 10 tokens decodificados/generados guardados en localStorage. Click para cargar rapidamente. |

### Funciones adicionales

- **Analizador de seguridad** — detecta vulnerabilidades comunes:
  - `alg:none` (critico — sin firma)
  - Ausencia de `exp` (el token nunca expira)
  - Datos sensibles en el payload (`password`, `secret`, `credit_card`, etc.)
  - TTL mayor a 30 dias
  - Ausencia de `iss` y `aud`
- **Countdown en tiempo real** — cuenta regresiva hasta que expira el token (actualiza cada segundo)
- **Indicador de fortaleza del secret** — barra visual (debil / media / fuerte)
- **Enviar a otro tab** — desde Generar puedes abrir el token directamente en Decodificar o Verificar

## Algoritmos soportados

| Algoritmo | Decodificar | Verificar | Generar |
|-----------|-------------|-----------|---------|
| HS256     | Si          | Si        | Si      |
| HS384     | Si          | Si        | Si      |
| HS512     | Si          | Si        | Si      |
| RS256     | Si          | Si (PEM)  | No      |
| RS384     | Si          | Si (PEM)  | No      |
| RS512     | Si          | Si (PEM)  | No      |
| ES256     | Si          | Si (PEM)  | No      |
| ES384     | Si          | Si (PEM)  | No      |
| ES512     | Si          | Si (PEM)  | No      |

## Tests

```bash
npm install
npm test              # 53 tests (Vitest)
npm run test:coverage # con reporte de cobertura
```

Los tests cubren: decodificacion base64url, sanitizacion XSS, validacion de estructura JWT, fortaleza de secrets, analisis de vulnerabilidades, countdown de expiracion y manejo de claims de tiempo.

## Privacidad

**100% del lado del cliente.** Ningun dato sale del navegador. Usa la [Web Crypto API](https://developer.mozilla.org/es/docs/Web/API/Web_Crypto_API) nativa del navegador para todas las operaciones criptograficas.

## Deploy en GitHub Pages

1. Fork/clonar el repo
2. En Settings -> Pages -> Source: rama `main`, carpeta `/` (root)
3. Listo — accesible en `https://tuusuario.github.io/jwt-debug-tool/`

El CI hace deploy automatico en cada push a `main`.

## Variables de entorno

No aplica — es una aplicacion estatica sin backend ni servidor.

## Estructura del proyecto

```
jwt-debug-tool/
├── index.html              # SPA completa (HTML + CSS + JS inline)
├── src/
│   └── jwt-utils.js        # Modulo de utilidades para testing
├── tests/
│   └── jwt-utils.test.js   # 53 tests con Vitest
├── .github/
│   └── workflows/
│       └── ci.yml          # CI: tests + deploy GitHub Pages
├── vitest.config.js
├── package.json
├── LICENSE
└── CHANGELOG.md
```

## Seguridad

- Todos los valores del JWT se sanitizan con `escapeHtml()` antes de insertar en el DOM (previene XSS)
- El algoritmo `alg:none` es detectado y rechazado en el verificador
- Los secrets no se persisten en localStorage ni en el historial
- El historial guarda el token pero no el secret usado para verificarlo

## Contribuir

PRs bienvenidos. La herramienta principal es `index.html` — un unico archivo para facilitar el deploy sin dependencias de build. El directorio `src/` contiene las utilidades para testing sin necesidad de modificar el HTML principal.

## Licencia

[MIT](LICENSE) — Quesillo27
