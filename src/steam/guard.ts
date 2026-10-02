// Steam Guard TOTP and confirmation keys via Web Crypto (algorithm per node-steam-totp, MIT).
const ALPHABET = '23456789BCDFGHJKMNPQRTVWXY';

function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function toB64(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}
async function hmacSha1(key: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, msg));
}
function timeBytes(t: number, extra = 0): Uint8Array {
  const out = new Uint8Array(8 + extra);
  new DataView(out.buffer).setBigUint64(0, BigInt(Math.floor(t)));
  return out;
}

export async function generateAuthCode(sharedSecretB64: string, unixTime: number): Promise<string> {
  const mac = await hmacSha1(fromB64(sharedSecretB64), timeBytes(Math.floor(unixTime / 30)));
  const off = mac[19]! & 0x0f;
  let full = ((mac[off]! & 0x7f) << 24) | (mac[off + 1]! << 16) | (mac[off + 2]! << 8) | mac[off + 3]!;
  let code = '';
  for (let i = 0; i < 5; i++) { code += ALPHABET[full % ALPHABET.length]; full = Math.floor(full / ALPHABET.length); }
  return code;
}

export async function generateConfirmationKey(identitySecretB64: string, tag: string, unixTime: number): Promise<string> {
  const tagBytes = new TextEncoder().encode(tag).subarray(0, 32);
  const msg = timeBytes(unixTime, tagBytes.length);
  msg.set(tagBytes, 8);
  return toB64(await hmacSha1(fromB64(identitySecretB64), msg));
}
