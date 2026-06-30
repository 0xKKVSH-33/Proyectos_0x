/**
 * CipherVault ES — Motor de cifrado
 * Abecedario español (28 letras: a-z + ñ + ll)
 * Sustitución con saltos −7 luego +3
 * AES-256-GCM doble capa con PBKDF2-SHA-512
 */

'use strict';

// ─── ABECEDARIO ESPAÑOL ───────────────────────────────────────────────────────
const ABC = [
  'a','b','c','d','e','f','g','h','i','j','k','l',
  'll','m','n','ñ','o','p','q','r','s','t','u','v','w','x','y','z'
];
const N = ABC.length; // 28 posiciones

/**
 * Tokeniza el texto detectando 'll' como unidad antes que 'l' solo.
 * Devuelve array de tokens: { orig, lower, isLetter, isUpper }
 */
function tokenize(text) {
  const tokens = [];
  const low = text.toLowerCase();
  let i = 0;
  while (i < low.length) {
    if (i + 1 < low.length && low[i] === 'l' && low[i + 1] === 'l') {
      const orig = text.slice(i, i + 2);
      tokens.push({
        orig,
        lower: 'll',
        isLetter: true,
        isUpper: orig[0] === orig[0].toUpperCase() && orig[0] !== orig[0].toLowerCase()
      });
      i += 2;
    } else {
      const c = low[i];
      tokens.push({
        orig: text[i],
        lower: c,
        isLetter: ABC.includes(c),
        isUpper: text[i] !== c
      });
      i++;
    }
  }
  return tokens;
}

/** Desplazamiento: −7 luego +3 (neto −4), circular en 28 letras */
function shiftChar(ch) {
  const idx = ABC.indexOf(ch);
  if (idx === -1) return ch;
  return ABC[((idx - 7 + 3) % N + N) % N];
}

/** Inverso: +7 luego −3 (neto +4), para descifrar */
function unshiftChar(ch) {
  const idx = ABC.indexOf(ch);
  if (idx === -1) return ch;
  return ABC[((idx + 7 - 3) % N + N) % N];
}

/** Aplica sustitución española al texto completo */
function substituteES(text) {
  return tokenize(text).map(t => {
    if (!t.isLetter) return t.orig;
    const shifted = shiftChar(t.lower);
    return t.isUpper ? shifted.toUpperCase() : shifted;
  }).join('');
}

/** Revierte la sustitución española */
function unsubstituteES(text) {
  return tokenize(text).map(t => {
    if (!t.isLetter) return t.orig;
    const unshifted = unshiftChar(t.lower);
    return t.isUpper ? unshifted.toUpperCase() : unshifted;
  }).join('');
}

// ─── AES-256-GCM HELPERS ──────────────────────────────────────────────────────
const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();

function toB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function fromB64(s) {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

/**
 * Deriva una clave AES-256 usando PBKDF2-SHA-512
 * @param {string} password
 * @param {Uint8Array} salt  - 16 bytes aleatorios
 * @param {string} layer     - identificador de capa ('L1' | 'L2')
 */
async function deriveKey(password, salt, layer) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    ENCODER.encode(password + '_cvses_' + layer),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 310_000, hash: 'SHA-512' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Cifra con AES-256-GCM una capa.
 * Devuelve string: "salt_b64:iv_b64:tag_b64:body_b64"
 */
async function aesEncrypt(plaintext, password, layer) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveKey(password, salt, layer);

  const raw     = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, ENCODER.encode(plaintext));
  const rawBytes = new Uint8Array(raw);
  const tag  = rawBytes.slice(-16);
  const body = rawBytes.slice(0, -16);

  return [toB64(salt), toB64(iv), toB64(tag), toB64(body)].join(':');
}

/**
 * Descifra una capa AES-256-GCM.
 * Espera string: "salt_b64:iv_b64:tag_b64:body_b64"
 */
async function aesDecrypt(packed, password, layer) {
  const parts = packed.split(':');
  if (parts.length !== 4) throw new Error('Formato de capa inválido');

  const [saltB, ivB, tagB, bodyB] = parts;
  const salt = fromB64(saltB);
  const iv   = fromB64(ivB);
  const tag  = fromB64(tagB);
  const body = fromB64(bodyB);

  const combined = new Uint8Array(body.length + tag.length);
  combined.set(body);
  combined.set(tag, body.length);

  const key   = await deriveKey(password, salt, layer);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, combined);
  return DECODER.decode(plain);
}

// ─── API PÚBLICA ──────────────────────────────────────────────────────────────
const FORMAT_PREFIX = 'cvs2';
const INNER_MARKER  = 'cvs2_inner:';

/**
 * Cifra el texto en 3 fases:
 *   1. Sustitución española (−7+3)
 *   2. AES-256-GCM capa L1
 *   3. AES-256-GCM capa L2 (clave maestra total: 512 bits)
 *
 * @param {string} text      - Texto en claro
 * @param {string} password  - Contraseña maestra (≥ 8 chars)
 * @returns {Promise<string>} Texto cifrado en formato cvs2:...
 */
async function cifrar(text, password) {
  if (!text)           throw new Error('El texto no puede estar vacío.');
  if (password.length < 8) throw new Error('La contraseña necesita al menos 8 caracteres.');

  const fase1 = substituteES(text);
  const fase2 = await aesEncrypt(fase1, password, 'L1');
  const fase3 = await aesEncrypt(INNER_MARKER + fase2, password, 'L2');

  return FORMAT_PREFIX + ':' + fase3;
}

/**
 * Descifra revertiendo las 3 fases.
 *
 * @param {string} ciphertext - Texto cifrado (formato cvs2:...)
 * @param {string} password   - Contraseña maestra
 * @returns {Promise<string>} Texto original
 */
async function descifrar(ciphertext, password) {
  if (!ciphertext.startsWith(FORMAT_PREFIX + ':'))
    throw new Error('Formato inválido. Este texto no fue generado por CipherVault ES.');
  if (!password)
    throw new Error('Ingresa la contraseña.');

  const packed3 = ciphertext.slice(FORMAT_PREFIX.length + 1);
  const inner   = await aesDecrypt(packed3, password, 'L2');

  if (!inner.startsWith(INNER_MARKER))
    throw new Error('Capa externa inválida. Contraseña incorrecta o datos corruptos.');

  const packed2 = inner.slice(INNER_MARKER.length);
  const fase1   = await aesDecrypt(packed2, password, 'L1');

  return unsubstituteES(fase1);
}

// Exponer funciones y abecedario globalmente para app.js
window.CipherVault = { cifrar, descifrar, ABC, N, substituteES, unsubstituteES, shiftChar, unshiftChar };
