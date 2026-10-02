import { OpError } from '../types.ts';

/** Steam uses RSAES-PKCS1-v1_5, which WebCrypto does not expose. Only padding randomness uses WebCrypto. */
export function encryptPassword(password: string, modulusHex: string, exponentHex: string): string {
  if (modulusHex.length > 1024 || exponentHex.length > 8) throw new OpError(502, 'invalid_rsa_key');
  if (!/^[0-9a-f]+$/i.test(modulusHex) || !/^[0-9a-f]+$/i.test(exponentHex)) throw new OpError(502, 'invalid_rsa_key');
  const normalized = modulusHex.replace(/^0+/, '');
  if (normalized.length < 256 || normalized.length > 1024 || exponentHex.length > 8) throw new OpError(502, 'invalid_rsa_key');
  const modulus = BigInt(`0x${normalized}`), exponent = BigInt(`0x${exponentHex}`), size = Math.ceil(normalized.length / 2);
  if (!(modulus & 1n) || exponent < 3n || !(exponent & 1n)) throw new OpError(502, 'invalid_rsa_key');
  const message = new TextEncoder().encode(password);
  if (message.length > size - 11) throw new OpError(400, 'password_too_long');
  const padded = new Uint8Array(size); padded[1] = 2;
  const padLength = size - message.length - 3;
  const random = new Uint8Array(padLength + 32);
  let at = 2;
  while (at < 2 + padLength) {
    crypto.getRandomValues(random);
    for (const b of random) if (b && at < 2 + padLength) padded[at++] = b;
  }
  padded.set(message, size - message.length);
  let base = 0n;
  for (const b of padded) base = (base << 8n) | BigInt(b);
  let e = exponent, result = 1n;
  while (e) { if (e & 1n) result = result * base % modulus; base = base * base % modulus; e >>= 1n; }
  let output = '';
  const cipher = new Uint8Array(size);
  for (let i = size - 1; i >= 0; i--) { cipher[i] = Number(result & 255n); result >>= 8n; }
  for (const b of cipher) output += String.fromCharCode(b);
  message.fill(0); padded.fill(0); random.fill(0);
  return btoa(output);
}
