# Changelog

Todos los cambios notables de este proyecto estan documentados aqui.
Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/).

## [1.1.1] — 2026-04-28

### Corregido
- **Generador JWT**: ahora valida que el payload sea un objeto JSON antes de firmar
- **Claims temporales personalizados**: el generador respeta `iat`, `exp` y `nbf` si ya fueron definidos manualmente en el JSON
- **Validacion de NumericDate**: `iat`, `exp` y `nbf` deben ser timestamps UNIX numericos; si `nbf >= exp` se muestra un error util

### Mejorado
- **Cobertura de tests**: se agregaron casos para claims personalizados y errores de validacion del generador

## [1.1.0] — 2026-04-18

### Agregado
- **Historial de tokens** (tab "Historial"): guarda en localStorage los ultimos 10 JWTs decodificados/generados; click para cargar rapidamente
- **Analizador de seguridad**: detecta vulnerabilidades comunes en la estructura del JWT
  - alg:none (critico)
  - Ausencia de exp, iss, aud (advertencias)
  - Datos sensibles en payload (password, secret, credit_card, etc.)
  - TTL mayor a 30 dias
- **Soporte ES256/ES384/ES512**: verificacion ECDSA con Web Crypto API
- **Rechazo explicito de alg:none** en tab de verificacion (no solo advertencia)
- **Validacion de nbf**: detecta tokens aun no validos y lo muestra en el status
- **Countdown en tiempo real**: muestra tiempo restante hasta expiracion con actualizacion cada segundo
  - Alerta visual cuando quedan menos de 5 minutos
- **Indicador de fortaleza del secret**: en tabs de Generar y Verificar con barra visual (debil / media / fuerte)
- **Botones "Abrir en Decodificar" y "Abrir en Verificar"**: desde el tab de Generar, envia el token directamente
- **Opcion de 15 minutos** en selector de expiracion del generador
- **Modulo `src/jwt-utils.js`**: funciones puras extraidas para testing
- **53 tests con Vitest** cubriendo todas las utilidades:
  - base64urlDecode/Encode
  - escapeHtml (incluyendo casos XSS)
  - validateJWTStructure
  - getSecretStrength
  - analyzeVulnerabilities
  - formatTimeToExpiry
  - parseTimestampClaims
- **GitHub Actions CI** (.github/workflows/ci.yml): tests en Node 18 y 20, validacion de HTML, deploy automatico a GitHub Pages
- **LICENSE MIT**

### Corregido
- **Vulnerabilidad XSS**: todos los valores de claims ahora se sanitizan con `escapeHtml()` antes de insertar en el DOM
- **clearAll()**: ahora funciona correctamente con el parametro tab
- **Ejemplo de token**: actualizado con fecha de expiracion en el futuro (el original ya estaba expirado)
- Los errores de crypto API ahora se muestran sanitizados (evita reflexion de mensajes de error maliciosos)

### Mejorado
- **README**: badges CI, tabla de funcionalidades ampliada, seccion de algoritmos actualizada
- **Claims table**: incluye nuevos claims estandar (scope, azp, nonce)
- Claims de tipo objeto se muestran como JSON serializado (antes podian romper el layout)
- Textarea con `autocomplete="off"` y `spellcheck="false"` para mejor UX con tokens
- `package.json` con version 1.1.0 y scripts de test/coverage

## [1.0.0] — 2024-04-13

### Inicial
- SPA de una sola pagina (index.html) sin dependencias externas
- Tab Decodificar: muestra header, payload y signature con syntax highlighting
- Tab Verificar: verifica firma HS256/384/512 y RS256/384/512 con Web Crypto API
- Tab Generar: genera JWTs firmados con HS256/384/512
- Tabla de claims con descripciones en espanol y timestamps legibles
- Deteccion de tokens expirados
- 100% del lado del cliente — ningun dato sale del navegador
