/**
 * Utilidades JWT — funciones puras extraidas del SPA para testing
 * Estas mismas funciones existen en index.html; este módulo permite testearlas con Vitest.
 */

// ── Polyfill btoa/atob en Node.js ─────────────────────────────────────────
/* istanbul ignore next */
if (typeof btoa === 'undefined') {
  global.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
  global.atob = (b64) => Buffer.from(b64, 'base64').toString('binary');
}

// ── Base64url ──────────────────────────────────────────────────────────────

export function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

export function base64urlEncode(buffer) {
  const bytes = new Uint8Array(buffer);
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function safeBase64urlDecodeJSON(part) {
  try { return JSON.parse(base64urlDecode(part)); }
  catch { return null; }
}

// ── Sanitización XSS ──────────────────────────────────────────────────────

export function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ── Validación de estructura JWT ───────────────────────────────────────────

export function validateJWTStructure(token) {
  if (!token || typeof token !== 'string') return { valid: false, error: 'Token vacío o no es string' };
  const parts = token.split('.');
  if (parts.length !== 3) return { valid: false, error: `JWT debe tener 3 partes (encontradas: ${parts.length})` };

  const header  = safeBase64urlDecodeJSON(parts[0]);
  const payload = safeBase64urlDecodeJSON(parts[1]);

  if (!header)  return { valid: false, error: 'Header no es JSON válido' };
  if (!payload) return { valid: false, error: 'Payload no es JSON válido' };
  if (!header.alg) return { valid: false, error: 'Header no tiene campo alg' };

  return { valid: true, header, payload, signature: parts[2] };
}

// ── Fortaleza del secret ───────────────────────────────────────────────────

const WEAK_SECRETS = [
  'secret', 'password', '123456', 'test', 'admin', 'jwt',
  'token', 'key', 'my_secret', 'mysecret', 'changeme', 'letmein'
];

export function getSecretStrength(secret) {
  if (!secret) return null;
  if (secret.length < 8 || WEAK_SECRETS.includes(secret.toLowerCase())) return 'weak';
  if (secret.length < 16 || !/[A-Z]/.test(secret) || !/[0-9]/.test(secret)) return 'medium';
  return 'strong';
}

// ── Análisis de vulnerabilidades ───────────────────────────────────────────

const SENSITIVE_KEYS = ['password', 'passwd', 'pwd', 'secret', 'credit_card', 'ssn', 'cvv', 'pin'];

export function analyzeVulnerabilities(header, payload) {
  const vulns = [];
  const alg = (header.alg || '').toUpperCase();

  if (alg === 'NONE' || alg === '') {
    vulns.push({ level: 'high', id: 'alg-none', title: 'Algoritmo "none" — sin firma' });
  }

  if (!payload.exp) {
    vulns.push({ level: 'medium', id: 'no-exp', title: 'Sin campo exp (expiración)' });
  }

  if (payload.exp && payload.iat && (payload.exp - payload.iat) > 86400 * 30) {
    vulns.push({ level: 'low', id: 'long-ttl', title: 'Vida útil muy larga' });
  }

  if (!payload.iss) {
    vulns.push({ level: 'low', id: 'no-iss', title: 'Sin campo iss (emisor)' });
  }

  if (!payload.aud) {
    vulns.push({ level: 'low', id: 'no-aud', title: 'Sin campo aud (audiencia)' });
  }

  const payloadKeys = Object.keys(payload).map(k => k.toLowerCase());
  const found = SENSITIVE_KEYS.filter(k => payloadKeys.includes(k));
  if (found.length > 0) {
    vulns.push({ level: 'high', id: 'sensitive-data', title: `Datos sensibles en payload: ${found.join(', ')}` });
  }

  return vulns;
}

// ── Formateo de tiempo hasta expiración ───────────────────────────────────

export function formatTimeToExpiry(expTimestamp) {
  if (!expTimestamp) return null;
  const now = Math.floor(Date.now() / 1000);
  const diff = expTimestamp - now;
  if (diff <= 0) return { expired: true, text: 'Token expirado' };

  const d = Math.floor(diff / 86400);
  const h = Math.floor((diff % 86400) / 3600);
  const m = Math.floor((diff % 3600) / 60);
  const s = diff % 60;

  if (d > 0) return { expired: false, text: `${d}d ${h}h ${m}m`, warning: false };
  if (h > 0) return { expired: false, text: `${h}h ${m}m ${s}s`, warning: false };
  return { expired: false, text: `${m}m ${s}s`, warning: diff < 300 };
}

// ── Truncar token para historial ──────────────────────────────────────────

export function truncateToken(token, maxLen = 80) {
  if (!token) return '';
  return token.length > maxLen ? token.slice(0, maxLen) + '...' : token;
}

// ── Verificar si claims contiene campos de tiempo válidos ──────────────────

export function parseTimestampClaims(payload) {
  const now = Math.floor(Date.now() / 1000);
  return {
    isExpired:   payload.exp ? payload.exp < now  : false,
    isNotYetValid: payload.nbf ? payload.nbf > now : false,
    hasIat:      Boolean(payload.iat),
    hasExp:      Boolean(payload.exp),
    hasNbf:      Boolean(payload.nbf),
  };
}
