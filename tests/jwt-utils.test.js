import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  base64urlDecode,
  base64urlEncode,
  safeBase64urlDecodeJSON,
  escapeHtml,
  validateJWTStructure,
  getSecretStrength,
  analyzeVulnerabilities,
  formatTimeToExpiry,
  truncateToken,
  parseTimestampClaims,
  prepareGeneratedClaims,
} from '../src/jwt-utils.js';

// ── base64urlDecode ────────────────────────────────────────────────────────
describe('base64urlDecode', () => {
  it('decodifica un string base64url simple', () => {
    const encoded = btoa('hello world').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
    expect(base64urlDecode(encoded)).toBe('hello world');
  });

  it('maneja padding faltante (1 mod 4)', () => {
    // eyJhbGciOiJIUzI1NiJ9 = {"alg":"HS256"}
    const result = base64urlDecode('eyJhbGciOiJIUzI1NiJ9');
    expect(result).toBe('{"alg":"HS256"}');
  });

  it('convierte - a + y _ a / correctamente', () => {
    // JSON.stringify({a:1}) en base64url
    const b64url = btoa(JSON.stringify({a:1})).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
    expect(base64urlDecode(b64url)).toBe('{"a":1}');
  });
});

// ── safeBase64urlDecodeJSON ────────────────────────────────────────────────
describe('safeBase64urlDecodeJSON', () => {
  it('decodifica JSON válido', () => {
    const obj = { alg: 'HS256', typ: 'JWT' };
    const encoded = btoa(JSON.stringify(obj)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
    expect(safeBase64urlDecodeJSON(encoded)).toEqual(obj);
  });

  it('retorna null para base64url inválido', () => {
    expect(safeBase64urlDecodeJSON('!!!invalid!!!')).toBeNull();
  });

  it('retorna null si el resultado no es JSON', () => {
    const encoded = btoa('not-json').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
    expect(safeBase64urlDecodeJSON(encoded)).toBeNull();
  });
});

// ── escapeHtml ─────────────────────────────────────────────────────────────
describe('escapeHtml', () => {
  it('escapa < y >', () => {
    expect(escapeHtml('<script>')).toBe('&lt;script&gt;');
  });

  it('escapa &', () => {
    expect(escapeHtml('a & b')).toBe('a &amp; b');
  });

  it('escapa comillas dobles', () => {
    expect(escapeHtml('"quoted"')).toBe('&quot;quoted&quot;');
  });

  it('escapa comillas simples', () => {
    expect(escapeHtml("it's")).toBe('it&#39;s');
  });

  it('maneja null', () => {
    expect(escapeHtml(null)).toBe('');
  });

  it('maneja undefined', () => {
    expect(escapeHtml(undefined)).toBe('');
  });

  it('convierte números a string', () => {
    expect(escapeHtml(42)).toBe('42');
  });

  it('no modifica texto plano', () => {
    expect(escapeHtml('hello world')).toBe('hello world');
  });

  it('previene XSS con payload de ataque', () => {
    const xss = '<img src=x onerror=alert(1)>';
    expect(escapeHtml(xss)).not.toContain('<');
    expect(escapeHtml(xss)).not.toContain('>');
  });
});

// ── validateJWTStructure ───────────────────────────────────────────────────
describe('validateJWTStructure', () => {
  const VALID_JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyIsIm5hbWUiOiJKdWFuIn0.placeholder';

  it('valida un JWT con estructura correcta', () => {
    const result = validateJWTStructure(VALID_JWT);
    expect(result.valid).toBe(true);
    expect(result.header.alg).toBe('HS256');
    expect(result.payload.sub).toBe('user_123');
  });

  it('rechaza token vacío', () => {
    expect(validateJWTStructure('').valid).toBe(false);
  });

  it('rechaza null', () => {
    expect(validateJWTStructure(null).valid).toBe(false);
  });

  it('rechaza token con solo 2 partes', () => {
    const result = validateJWTStructure('aaa.bbb');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('3 partes');
  });

  it('rechaza token con 4 partes', () => {
    const result = validateJWTStructure('a.b.c.d');
    expect(result.valid).toBe(false);
  });

  it('rechaza header con JSON inválido', () => {
    const badHeader = btoa('not-json').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
    const result = validateJWTStructure(`${badHeader}.eyJzdWIiOiIxIn0.sig`);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Header');
  });

  it('rechaza payload con JSON inválido', () => {
    const validHeader = btoa('{"alg":"HS256"}').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
    const badPayload = btoa('not-json').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
    const result = validateJWTStructure(`${validHeader}.${badPayload}.sig`);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Payload');
  });

  it('rechaza header sin campo alg', () => {
    const noAlgHeader = btoa('{"typ":"JWT"}').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
    const payload = btoa('{"sub":"1"}').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
    const result = validateJWTStructure(`${noAlgHeader}.${payload}.sig`);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('alg');
  });

  it('retorna signature cuando es válido', () => {
    const result = validateJWTStructure(VALID_JWT);
    expect(result.signature).toBe('placeholder');
  });
});

// ── getSecretStrength ──────────────────────────────────────────────────────
describe('getSecretStrength', () => {
  it('retorna null para secret vacío', () => {
    expect(getSecretStrength('')).toBeNull();
    expect(getSecretStrength(null)).toBeNull();
  });

  it('secret conocido débil', () => {
    expect(getSecretStrength('secret')).toBe('weak');
    expect(getSecretStrength('password')).toBe('weak');
    expect(getSecretStrength('admin')).toBe('weak');
  });

  it('secret corto es débil', () => {
    expect(getSecretStrength('abc')).toBe('weak');
  });

  it('secret medio — longitud ok pero sin mayúsculas/números', () => {
    expect(getSecretStrength('abcdefghijklmno')).toBe('medium');
  });

  it('secret fuerte — 16+ chars, mayúsculas y números', () => {
    expect(getSecretStrength('MyStr0ngSecret2024!')).toBe('strong');
  });

  it('case insensitive para secrets conocidos', () => {
    expect(getSecretStrength('SECRET')).toBe('weak');
    expect(getSecretStrength('Password')).toBe('weak');
  });
});

// ── analyzeVulnerabilities ────────────────────────────────────────────────
describe('analyzeVulnerabilities', () => {
  it('detecta alg:none como vulnerabilidad alta', () => {
    const vulns = analyzeVulnerabilities({ alg: 'none' }, { sub: '1' });
    const algNone = vulns.find(v => v.id === 'alg-none');
    expect(algNone).toBeDefined();
    expect(algNone.level).toBe('high');
  });

  it('detecta ausencia de exp como vulnerabilidad media', () => {
    const vulns = analyzeVulnerabilities({ alg: 'HS256' }, { sub: '1' });
    const noExp = vulns.find(v => v.id === 'no-exp');
    expect(noExp).toBeDefined();
    expect(noExp.level).toBe('medium');
  });

  it('no reporta no-exp si exp existe', () => {
    const now = Math.floor(Date.now() / 1000);
    const vulns = analyzeVulnerabilities({ alg: 'HS256' }, { sub: '1', exp: now + 3600 });
    const noExp = vulns.find(v => v.id === 'no-exp');
    expect(noExp).toBeUndefined();
  });

  it('detecta TTL mayor a 30 días', () => {
    const now = Math.floor(Date.now() / 1000);
    const vulns = analyzeVulnerabilities(
      { alg: 'HS256' },
      { sub: '1', iat: now, exp: now + 86400 * 60 }
    );
    const longTtl = vulns.find(v => v.id === 'long-ttl');
    expect(longTtl).toBeDefined();
  });

  it('detecta datos sensibles en payload', () => {
    const vulns = analyzeVulnerabilities(
      { alg: 'HS256' },
      { sub: '1', password: 'mypassword', exp: Math.floor(Date.now()/1000) + 3600 }
    );
    const sensitiveVuln = vulns.find(v => v.id === 'sensitive-data');
    expect(sensitiveVuln).toBeDefined();
    expect(sensitiveVuln.level).toBe('high');
  });

  it('detecta ausencia de iss', () => {
    const vulns = analyzeVulnerabilities({ alg: 'HS256' }, { sub: '1' });
    const noIss = vulns.find(v => v.id === 'no-iss');
    expect(noIss).toBeDefined();
  });

  it('sin vulnerabilidades para token bien configurado', () => {
    const now = Math.floor(Date.now() / 1000);
    const vulns = analyzeVulnerabilities(
      { alg: 'HS256' },
      { sub: '1', iss: 'mi-app', aud: 'api', iat: now, exp: now + 3600 }
    );
    // Solo puede quedar no-aud como low pero no high/medium críticos
    const highs = vulns.filter(v => v.level === 'high');
    const mediums = vulns.filter(v => v.level === 'medium');
    expect(highs.length).toBe(0);
    expect(mediums.length).toBe(0);
  });
});

// ── formatTimeToExpiry ────────────────────────────────────────────────────
describe('formatTimeToExpiry', () => {
  it('retorna null si no hay exp', () => {
    expect(formatTimeToExpiry(null)).toBeNull();
    expect(formatTimeToExpiry(undefined)).toBeNull();
  });

  it('retorna expired=true para token ya expirado', () => {
    const pastExp = Math.floor(Date.now() / 1000) - 3600;
    const result = formatTimeToExpiry(pastExp);
    expect(result.expired).toBe(true);
  });

  it('muestra dias cuando faltan mas de 24h', () => {
    const futureExp = Math.floor(Date.now() / 1000) + 86400 * 3 + 3600;
    const result = formatTimeToExpiry(futureExp);
    expect(result.expired).toBe(false);
    expect(result.text).toMatch(/3d/);
  });

  it('muestra horas cuando faltan entre 1 y 24h', () => {
    const futureExp = Math.floor(Date.now() / 1000) + 7200;
    const result = formatTimeToExpiry(futureExp);
    expect(result.expired).toBe(false);
    expect(result.text).toMatch(/h/);
  });

  it('marca warning cuando faltan menos de 5 minutos', () => {
    const futureExp = Math.floor(Date.now() / 1000) + 120; // 2 min
    const result = formatTimeToExpiry(futureExp);
    expect(result.warning).toBe(true);
  });

  it('no marca warning cuando quedan mas de 5 minutos', () => {
    const futureExp = Math.floor(Date.now() / 1000) + 7200;
    const result = formatTimeToExpiry(futureExp);
    expect(result.warning).toBe(false);
  });
});

// ── truncateToken ─────────────────────────────────────────────────────────
describe('truncateToken', () => {
  it('no trunca token corto', () => {
    expect(truncateToken('abc.def.ghi', 80)).toBe('abc.def.ghi');
  });

  it('trunca token largo y agrega puntos suspensivos', () => {
    const longToken = 'a'.repeat(100);
    const result = truncateToken(longToken, 80);
    expect(result.length).toBe(83); // 80 chars + '...'
    expect(result.endsWith('...')).toBe(true);
  });

  it('usa maxLen de 80 por defecto', () => {
    const longToken = 'x'.repeat(100);
    const result = truncateToken(longToken);
    expect(result.startsWith('x'.repeat(80))).toBe(true);
  });

  it('retorna string vacío para token vacío', () => {
    expect(truncateToken('')).toBe('');
    expect(truncateToken(null)).toBe('');
  });
});

// ── parseTimestampClaims ──────────────────────────────────────────────────
describe('parseTimestampClaims', () => {
  it('detecta token expirado', () => {
    const now = Math.floor(Date.now() / 1000);
    const result = parseTimestampClaims({ exp: now - 3600 });
    expect(result.isExpired).toBe(true);
  });

  it('detecta token no expirado', () => {
    const now = Math.floor(Date.now() / 1000);
    const result = parseTimestampClaims({ exp: now + 3600 });
    expect(result.isExpired).toBe(false);
  });

  it('detecta nbf en el futuro', () => {
    const now = Math.floor(Date.now() / 1000);
    const result = parseTimestampClaims({ nbf: now + 3600 });
    expect(result.isNotYetValid).toBe(true);
  });

  it('detecta nbf en el pasado como válido', () => {
    const now = Math.floor(Date.now() / 1000);
    const result = parseTimestampClaims({ nbf: now - 3600 });
    expect(result.isNotYetValid).toBe(false);
  });

  it('retorna false cuando no hay exp', () => {
    const result = parseTimestampClaims({ sub: '1' });
    expect(result.isExpired).toBe(false);
    expect(result.hasExp).toBe(false);
  });

  it('detecta presencia de iat', () => {
    const result = parseTimestampClaims({ iat: 1713000000 });
    expect(result.hasIat).toBe(true);
  });
});

// ── prepareGeneratedClaims ────────────────────────────────────────────────
describe('prepareGeneratedClaims', () => {
  it('agrega iat y exp por defecto cuando no existen', () => {
    const prepared = prepareGeneratedClaims({ sub: 'user_1' }, 1713000000, 3600);
    expect(prepared).toEqual({
      sub: 'user_1',
      iat: 1713000000,
      exp: 1713003600,
    });
  });

  it('respeta iat y exp personalizados', () => {
    const prepared = prepareGeneratedClaims(
      { sub: 'user_1', iat: 1700000000, exp: 1700003600 },
      1713000000,
      3600
    );
    expect(prepared.iat).toBe(1700000000);
    expect(prepared.exp).toBe(1700003600);
  });

  it('acepta nbf numerico personalizado', () => {
    const prepared = prepareGeneratedClaims({ sub: 'user_1', nbf: 1713000300 }, 1713000000, 0);
    expect(prepared.nbf).toBe(1713000300);
    expect(prepared.iat).toBe(1713000000);
    expect(prepared.exp).toBeUndefined();
  });

  it('rechaza claims que no son objeto JSON', () => {
    expect(() => prepareGeneratedClaims([], 1713000000, 3600)).toThrow(/objeto JSON/);
    expect(() => prepareGeneratedClaims(null, 1713000000, 3600)).toThrow(/objeto JSON/);
  });

  it('rechaza claims de tiempo no numericos', () => {
    expect(() => prepareGeneratedClaims({ exp: 'tomorrow' }, 1713000000, 3600)).toThrow(/Claim exp/);
    expect(() => prepareGeneratedClaims({ nbf: -1 }, 1713000000, 3600)).toThrow(/Claim nbf/);
  });

  it('rechaza nbf mayor o igual que exp', () => {
    expect(() => prepareGeneratedClaims({ nbf: 1713003600, exp: 1713003600 }, 1713000000, 0)).toThrow(/nbf/);
  });
});
