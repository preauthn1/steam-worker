import { OpError, type Json } from '../types.ts';

const HOSTS = new Set(['steamcommunity.com', 'store.steampowered.com', 'login.steampowered.com', 'help.steampowered.com', 'api.steampowered.com', 'checkout.steampowered.com', 'steam.tv']);
export interface SteamCookie {
  name: string; value: string; domain: string; path: string;
  hostOnly: boolean; secure: boolean; expires: number | null;
}
function trusted(raw: URL | string): URL {
  let u: URL;
  try { u = new URL(raw); } catch { throw new OpError(400, 'egress_denied'); }
  if (u.protocol !== 'https:' || !HOSTS.has(u.hostname) || (u.port && u.port !== '443') || u.username || u.password) throw new OpError(400, 'egress_denied');
  return u;
}
const domainMatches = (host: string, domain: string) => host === domain || host.endsWith(`.${domain}`);
// Only Steam-controlled registrable domains may broaden scope, and only allowlisted destinations receive them.
const validDomain = (d: string) => HOSTS.has(d) || d === 'steampowered.com';
function valid(c: unknown): c is SteamCookie {
  if (!c || typeof c !== 'object') return false;
  const x = c as SteamCookie;
  return typeof x.name === 'string' && /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(x.name) && x.name.length <= 256 &&
    typeof x.value === 'string' && !/[\x00-\x20\x7f;,]/.test(x.value) && x.value.length <= 16384 &&
    typeof x.domain === 'string' && validDomain(x.domain) && typeof x.path === 'string' && x.path.startsWith('/') &&
    !/[\x00-\x20\x7f;]/.test(x.path) && typeof x.hostOnly === 'boolean' && typeof x.secure === 'boolean' &&
    (x.expires === null || (typeof x.expires === 'number' && Number.isFinite(x.expires))) &&
    (!x.hostOnly || HOSTS.has(x.domain));
}
export class CookieJar {
  private cookies: SteamCookie[] = [];
  constructor(cookies?: unknown) {
    if (Array.isArray(cookies)) for (const c of cookies) if (valid(c)) this.set(c);
  }
  set(cookie: SteamCookie): void {
    if (!valid(cookie)) throw new OpError(400, 'invalid_cookie');
    const c = { ...cookie };
    this.cookies = this.cookies.filter(x => !(x.name === c.name && x.domain === c.domain && x.path === c.path));
    if (c.expires !== null && c.expires <= Date.now() / 1000) return;
    if (this.cookies.length >= 256) throw new OpError(502, 'cookie_limit');
    this.cookies.push(c);
  }
  header(raw: URL | string): string {
    const u = trusted(raw), now = Date.now() / 1000;
    return this.cookies.filter(c => (c.expires === null || c.expires > now) &&
      (c.hostOnly ? c.domain === u.hostname : domainMatches(u.hostname, c.domain)) &&
      (u.pathname === c.path || (u.pathname.startsWith(c.path) && (c.path.endsWith('/') || u.pathname[c.path.length] === '/'))))
      .sort((a, b) => b.path.length - a.path.length).map(c => `${c.name}=${c.value}`).join('; ');
  }
  export(): Json {
    return this.cookies.filter(c => c.expires === null || c.expires > Date.now() / 1000).map(c => ({ ...c }));
  }
  setFromHeaders(raw: URL | string, headers: Headers): void {
    const u = trusted(raw);
    const ext = headers as Headers & { getSetCookie?: () => string[]; getAll?: (name: string) => string[] };
    const combined = headers.get('set-cookie');
    const values = ext.getSetCookie ? ext.getSetCookie() : ext.getAll ? ext.getAll('set-cookie') : combined ? combined.split(/,(?=\s*[^;,=\s]+\s*=)/) : [];
    for (const value of values) {
      const parts = value.split(';'), pair = parts.shift()!, at = pair.indexOf('=');
      if (at < 1) continue;
      const path = u.pathname.slice(0, u.pathname.lastIndexOf('/')) || '/';
      const c: SteamCookie = { name: pair.slice(0, at).trim(), value: pair.slice(at + 1).trim(), domain: u.hostname, path, hostOnly: true, secure: false, expires: null };
      let maxAge: number | undefined, reject = false;
      for (const part of parts) {
        const i = part.indexOf('='), k = (i < 0 ? part : part.slice(0, i)).trim().toLowerCase(), v = (i < 0 ? '' : part.slice(i + 1)).trim();
        if (k === 'domain') {
          const d = v.replace(/^\./, '').toLowerCase();
          if (!validDomain(d) || !domainMatches(u.hostname, d)) { reject = true; break; }
          c.domain = d; c.hostOnly = false;
        } else if (k === 'path' && v.startsWith('/')) c.path = v;
        else if (k === 'secure') c.secure = true;
        else if (k === 'max-age' && /^-?\d+$/.test(v)) { const n = Number(v); if (Number.isFinite(n)) maxAge = n; }
        else if (k === 'expires') { const n = Date.parse(v); if (Number.isFinite(n)) c.expires = n / 1000; }
      }
      if (maxAge !== undefined) c.expires = Date.now() / 1000 + maxAge;
      if (c.name.startsWith('__Secure-') && !c.secure) reject = true;
      if (c.name.startsWith('__Host-') && (!c.secure || !c.hostOnly || c.path !== '/')) reject = true;
      if (!reject && valid(c)) this.set(c);
    }
  }
}
