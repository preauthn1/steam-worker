// Outbound HTTP to Steam: exact host allowlist, manual redirects, deadlines, request budget,
// streamed response cap. Behaviour ported from the reviewed Python transport.
import { OpError, type SteamTransportLike } from '../types.ts';
import { CookieJar } from './cookies.ts';

const HOSTS = new Set([
  'steamcommunity.com',
  'store.steampowered.com',
  'login.steampowered.com',
  'help.steampowered.com',
  'api.steampowered.com',
  // Exact additional transfer destinations listed in aiosteampy/constants.py.
  'checkout.steampowered.com',
  'steam.tv',
]);
const MAX_REQUESTS = 40;
const DEADLINE_MS = 25_000;
const MAX_BYTES = 8_000_000;
const MAX_REDIRECTS = 10;

export type Fetcher = (url: string, init: RequestInit) => Promise<Response>;

export function validateUrl(raw: string | URL): URL {
  const url = new URL(raw);
  if (url.protocol !== 'https:' || !HOSTS.has(url.hostname) || (url.port && url.port !== '443') ||
      url.username || url.password) {
    throw new OpError(400, 'egress_denied');
  }
  return url;
}

export async function readBounded(body: ReadableStream<Uint8Array> | null, limit = MAX_BYTES, signal?: AbortSignal): Promise<Uint8Array> {
  if (!body) return new Uint8Array();
  const reader = body.getReader();
  const abort = () => { void reader.cancel().catch(() => {}); };
  signal?.addEventListener('abort', abort, { once: true });
  if (signal?.aborted) abort();
  const parts: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel();
        throw new OpError(502, 'upstream_response_too_large');
      }
      parts.push(value);
    }
  } finally {
    signal?.removeEventListener('abort', abort);
    reader.releaseLock();
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.byteLength; }
  return out;
}

export interface SteamResponse { status: number; url: URL; headers: Headers; body: Uint8Array }

export class SteamTransport implements SteamTransportLike {
  requestCount = 0;
  cookieJar?: CookieJar;
  constructor(private readonly fetcher: Fetcher = (u, i) => fetch(u, i), private readonly deadlineMs = DEADLINE_MS) {
    if (!Number.isFinite(deadlineMs) || deadlineMs <= 0 || deadlineMs > DEADLINE_MS) throw new OpError(400, 'invalid_deadline');
  }
  /** Fetch has no persistent resources in Workers; kept for core lifecycle symmetry. */
  close(): void {}

  async request(method: string, target: string | URL, init: { headers?: Record<string, string>; body?: BodyInit } = {}): Promise<SteamResponse> {
    let url = validateUrl(target);
    let headers: Record<string, string> = { 'User-Agent': 'steam-worker', ...init.headers };
    let body = init.body;
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      if (this.requestCount >= MAX_REQUESTS) throw new OpError(429, 'upstream_request_budget');
      this.requestCount++;
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), this.deadlineMs);
      let active: Response | undefined;
      const aborted = new Promise<never>((_, reject) => ctl.signal.addEventListener('abort', () => {
        if (active?.body && !active.body.locked) { try { void active.body.cancel().catch(() => {}); } catch {} }
        reject(new OpError(504, 'upstream_unreachable'));
      }, { once: true }));
      try {
        const requestHeaders = { ...headers };
        if (this.cookieJar) {
          for (const k of Object.keys(requestHeaders)) if (/^cookie$/i.test(k)) delete requestHeaders[k];
          const cookie = this.cookieJar.header(url);
          if (cookie) requestHeaders.Cookie = cookie;
        }
        const res = active = await Promise.race([this.fetcher(url.toString(), { method, headers: requestHeaders, body, redirect: 'manual', signal: ctl.signal }), aborted]);
        this.cookieJar?.setFromHeaders(url, res.headers);
        const location = res.headers.get('location');
        if (res.status >= 300 && res.status < 400 && location) {
          await Promise.race([res.body?.cancel() ?? Promise.resolve(), aborted]);
          const next = validateUrl(new URL(location, url));
          if (next.hostname !== url.hostname) {
            if ((res.status === 307 || res.status === 308) && body != null) throw new OpError(400, 'cross_origin_body_redirect_denied');
            headers = Object.fromEntries(Object.entries(headers).filter(([k]) => !/^(cookie|authorization)$/i.test(k)));
          }
          if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === 'POST')) { method = 'GET'; body = undefined; }
          url = next;
          continue;
        }
        const responseBody = await Promise.race([readBounded(res.body, MAX_BYTES, ctl.signal), aborted]);
        return { status: res.status, url, headers: res.headers, body: responseBody };
      } catch (e) {
        if (e instanceof OpError) throw e;
        throw new OpError(504, 'upstream_unreachable');
      } finally { clearTimeout(timer); }
    }
    throw new OpError(502, 'redirect_limit');
  }
}

export function createTransport(): SteamTransport {
  return new SteamTransport();
}
