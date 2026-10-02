// Field numbers and wire types transcribed from aiosteampy/webapi/protobufs/auth.py.
import { OpError, type Json, type OpContext, type OperationSpec } from '../types.ts';
import { Writer, decode, get, type Field } from './protobuf.ts';
import { callService } from './webapi.ts';
import { CookieJar, type SteamCookie } from './cookies.ts';
import { SteamTransport, validateUrl } from './transport.ts';
import { encryptPassword } from './rsa.ts';

type Obj = Record<string, Json>;
const object = (x: Json | undefined): Obj | undefined => x && typeof x === 'object' && !Array.isArray(x) ? x : undefined;
const now = () => Date.now() / 1000;
const text = new TextDecoder();
const b64 = (b: Uint8Array): string => btoa(Array.from(b, x => String.fromCharCode(x)).join(''));
function unb64(s: string): Uint8Array { return Uint8Array.from(atob(s), x => x.charCodeAt(0)); }
function random(): string { return Array.from(crypto.getRandomValues(new Uint8Array(24)), b => b.toString(16).padStart(2, '0')).join(''); }
function invalid(): never { throw new OpError(502, 'upstream_invalid_response'); }
function parsed(b: Uint8Array): Map<number, Field[]> { try { return decode(b); } catch { return invalid(); } }
function float(m: Map<number, Field[]>, n: number): number {
  const f = m.get(n)?.[0]; if (f?.wire !== 5 || f.int === undefined) return invalid();
  const b = new ArrayBuffer(4); new DataView(b).setUint32(0, Number(f.int), true);
  const v = new DataView(b).getFloat32(0, true); if (!Number.isFinite(v) || v <= 0 || v > 600) return invalid(); return v;
}
async function auth(c: OpContext, method: string, w: Writer, http: 'GET' | 'POST' = 'POST'): Promise<Map<number, Field[]>> {
  return parsed(await callService(c.transport as SteamTransport, 'IAuthenticationService', method, w.finish(), { http }));
}
function platform(args: Obj): string {
  const p = args.platform ?? 'web'; if (p !== 'web' && p !== 'mobile') throw new OpError(400, 'invalid_arguments'); return p;
}
function device(p: string, name: string): Uint8Array {
  const w = new Writer().string(1, name).uint(2, p === 'web' ? 2 : 3);
  if (p === 'mobile') w.uint(3, -500).uint(4, 528);
  return w.finish();
}
function challenge(raw: string): string {
  let u: URL; try { u = new URL(raw); } catch { return invalid(); }
  if (u.protocol !== 'https:' || u.hostname !== 's.team' || u.port || u.username || u.password || !/^\/q\/\d+\/\d+$/.test(u.pathname) || u.search || u.hash) return invalid();
  return raw;
}
function confirmations(m: Map<number, Field[]>, field: number): Json[] {
  return get.all(m, field).map(f => {
    if (!f.data) return invalid(); const a = parsed(f.data), type = Number(get.int(a, 1) ?? 0);
    if (type < 1 || type > 7) return invalid();
    return { confirmation_type: type, associated_message: get.str(a, 2) ?? '' };
  });
}
function start(c: OpContext): void {
  if (object(c.state.session)?.refresh_token) throw new OpError(409, 'session_already_authenticated');
  // Startup failure cannot leave a partial or stale challenge resumable.
  delete c.state.pending_login;
}
function persist(c: OpContext, m: Map<number, Field[]>, p: string, qr: boolean): Json {
  const client = get.int(m, 1), request = get.bytes(m, qr ? 3 : 2), interval = float(m, qr ? 4 : 3);
  const allowed = confirmations(m, qr ? 5 : 4);
  const steam = qr ? undefined : get.int(m, 5);
  if (!client || !request?.length || !allowed.length || (!qr && !steam)) return invalid();
  const url = qr ? challenge(get.str(m, 2) ?? '') : null;
  const pending: Obj = { login_handle: random(), client_id: client.toString(), request_id: b64(request), poll_interval: interval,
    next_poll_at: 0, expires_at: now() + 600, attempts: 0, platform: p, allowed_confirmations: allowed,
    steam_id: steam?.toString() ?? null, challenge_url: url, version: qr ? Number(get.int(m, 6) ?? 0) : null };
  c.state.pending_login = pending;
  return pendingResult(pending);
}
function pendingResult(p: Obj): Json {
  return { status: 'pending', login_handle: p.login_handle!, poll_interval: p.poll_interval!, expires_at: p.expires_at!,
    challenge_url: p.challenge_url ?? null, version: p.version ?? null, allowed_confirmations: p.allowed_confirmations ?? [] };
}
function pending(c: OpContext, args: Obj, attempt = true): Obj {
  const p = object(c.state.pending_login);
  if (!p || typeof p.client_id !== 'string' || typeof p.request_id !== 'string' || !p.request_id || typeof p.login_handle !== 'string') throw new OpError(409, 'login_required');
  if (p.login_handle !== args.login_handle) throw new OpError(409, 'login_handle_mismatch');
  if (typeof p.expires_at !== 'number' || p.expires_at <= now()) { delete c.state.pending_login; throw new OpError(409, 'login_expired'); }
  if (attempt) {
    const n = Number(p.attempts ?? 0); if (n >= 30) throw new OpError(429, 'login_attempt_limit'); p.attempts = n + 1;
  }
  return p;
}
function jwt(raw: string): { sub: string; exp: number; aud: string[] } {
  try {
    if (raw.length > 16384) return invalid();
    const parts = raw.split('.'); if (parts.length !== 3) return invalid();
    const s = parts[1]!.replace(/-/g, '+').replace(/_/g, '/');
    const j = JSON.parse(text.decode(unb64(s + '='.repeat((4 - s.length % 4) % 4))));
    if (typeof j.sub !== 'string' || !/^[1-9]\d{0,19}$/.test(j.sub) || BigInt(j.sub) > 0xffffffffffffffffn || !Number.isFinite(j.exp) || j.exp <= now() || !Array.isArray(j.aud) || !j.aud.every((v: unknown) => typeof v === 'string')) return invalid();
    return { sub: j.sub, exp: j.exp, aud: j.aud };
  } catch { return invalid(); }
}
function tokens(access: string, refresh: string, p: string, expected?: Json): { steam_id: string; access_expires_at: number; refresh_expires_at: number } {
  const a = jwt(access), r = jwt(refresh);
  if (a.sub !== r.sub || (expected && expected !== a.sub) || a.aud.includes('derive') || !r.aud.includes('derive') || !a.aud.includes(p) || !r.aud.includes(p)) return invalid();
  // Claims are accepted ONLY for tokens returned by the trusted Steam transport, never caller input.
  return { steam_id: a.sub, access_expires_at: a.exp, refresh_expires_at: r.exp };
}
function session(c: OpContext): Obj {
  const s = object(c.state.session); if (!s || typeof s.refresh_token !== 'string' || typeof s.steam_id !== 'string') throw new OpError(409, 'session_required');
  if (Number(s.refresh_expires_at) <= now()) throw new OpError(409, 'session_expired'); return s;
}
async function credentials(c: OpContext, args: Obj): Promise<Json> {
  start(c); const p = platform(args), name = String(args.device_friendly_name ?? 'Steam Worker');
  const rsa = await auth(c, 'GetPasswordRSAPublicKey', new Writer().string(1, String(args.account_name)), 'GET');
  const mod = get.str(rsa, 1), exp = get.str(rsa, 2), ts = get.int(rsa, 3); if (!mod || !exp || !ts) return invalid();
  const encrypted = encryptPassword(String(args.password), mod, exp);
  const persistLogin = args.persistence !== false;
  const req = new Writer().string(1, name).string(2, String(args.account_name)).string(3, encrypted).uint(4, ts).bool(5, persistLogin)
    .uint(6, p === 'web' ? 2 : 3).uint(7, persistLogin ? 1 : 0).string(8, p === 'web' ? 'Community' : 'Mobile').bytes(9, device(p, name)).uint(11, 0).uint(12, 2);
  return persist(c, await auth(c, 'BeginAuthSessionViaCredentials', req), p, false);
}
async function qr(c: OpContext, args: Obj): Promise<Json> {
  start(c); if (platform(args) !== 'web') throw new OpError(400, 'invalid_arguments');
  const name = String(args.device_friendly_name ?? 'Steam Worker');
  return persist(c, await auth(c, 'BeginAuthSessionViaQR', new Writer().string(1, name).uint(2, 2).bytes(3, device('web', name)).string(4, 'Community')), 'web', true);
}
async function code(c: OpContext, args: Obj): Promise<Json> {
  const p = pending(c, args), type = args.code_type ?? 'device';
  if ((type !== 'device' && type !== 'email') || typeof p.steam_id !== 'string') throw new OpError(400, 'invalid_arguments');
  const n = type === 'device' ? 3 : 2;
  if (!(p.allowed_confirmations as Json[]).some(x => object(x)?.confirmation_type === n)) throw new OpError(409, 'guard_code_not_allowed');
  try { await auth(c, 'UpdateAuthSessionWithSteamGuardCode', new Writer().uint(1, BigInt(String(p.client_id))).fixed64(2, BigInt(p.steam_id)).string(3, String(args.auth_code)).uint(4, n)); }
  catch (e) { if (!(e instanceof OpError) || e.code !== 'upstream_eresult_29') throw e; }
  return { status: 'pending', login_handle: p.login_handle! };
}
async function poll(c: OpContext, args: Obj): Promise<Json> {
  const p = pending(c, args, false);
  if (now() < Number(p.next_poll_at)) throw new OpError(429, 'poll_too_soon');
  pending(c, args); p.next_poll_at = now() + Number(p.poll_interval);
  let m: Map<number, Field[]>;
  try { m = await auth(c, 'PollAuthSessionStatus', new Writer().uint(1, BigInt(String(p.client_id))).bytes(2, unb64(String(p.request_id)))); }
  catch (e) { if (e instanceof OpError && ['upstream_eresult_27', 'upstream_eresult_5', 'upstream_eresult_15'].includes(e.code)) delete c.state.pending_login; throw e; }
  const rotated = get.int(m, 1); if (rotated) p.client_id = rotated.toString();
  const url = get.str(m, 2); if (url) p.challenge_url = challenge(url);
  const refresh = get.str(m, 3), access = get.str(m, 4);
  if (!refresh) return pendingResult(p);
  if (!access) return invalid();
  const meta = tokens(access, refresh, String(p.platform), p.steam_id);
  const s: Obj = { ...meta, access_token: access, refresh_token: refresh, platform: p.platform!, session_id: random().slice(0, 24), cookies: [], account_name: get.str(m, 6) ?? null };
  const guardData = get.str(m, 7); if (guardData) s.guard_data = guardData;
  c.state.session = s; c.state.authenticated = true; delete c.state.pending_login;
  return { status: 'authenticated', steam_id: meta.steam_id, ready_for_web: false };
}
function attach(c: OpContext, s: Obj): CookieJar {
  const j = new CookieJar(s.cookies); (c.transport as SteamTransport).cookieJar = j; return j;
}
function put(j: CookieJar, name: string, value: string, domain: string, expires: number | null): void {
  j.set({ name, value, domain, path: '/', hostOnly: true, secure: true, expires });
}
function seed(j: CookieJar, s: Obj): void {
  put(j, 'steamRefresh_steam', encodeURIComponent(`${s.steam_id}||${s.refresh_token}`), 'login.steampowered.com', Number(s.refresh_expires_at));
  put(j, 'sessionid', String(s.session_id), 'login.steampowered.com', null);
}
async function requestJson(c: OpContext, url: URL | string, fields: Record<string, string>): Promise<Obj> {
  const form = new FormData(); for (const [k, v] of Object.entries(fields)) form.set(k, v);
  const r = await (c.transport as SteamTransport).request('POST', url, { headers: { Origin: 'https://steamcommunity.com', Referer: 'https://steamcommunity.com/' }, body: form });
  if (r.status >= 400) throw new OpError(502, 'upstream_login_failed');
  try { const j = object(JSON.parse(text.decode(r.body))); if (!j || j.error) return invalid(); return j; } catch { return invalid(); }
}
function cookieToken(j: CookieJar, host: string, name: string, s: Obj, refresh = false): string {
  const pair = j.header(`https://${host}/`).split('; ').find(x => x.startsWith(`${name}=`)); if (!pair) return invalid();
  let value: string; try { value = decodeURIComponent(pair.slice(name.length + 1)); } catch { return invalid(); }
  const i = value.indexOf('||'); if (i < 0 || value.slice(0, i) !== s.steam_id) return invalid();
  const raw = value.slice(i + 2), meta = jwt(raw);
  if (meta.sub !== s.steam_id || meta.aud.includes('derive') !== refresh || !(meta.aud.includes('web') || meta.aud.some(a => a.startsWith('web:')))) return invalid();
  // Bound cookie lifespan by the actual token, not the multi-year Set-Cookie expiration.
  for (const c of j.export() as unknown as SteamCookie[]) if (c.name === name && (c.domain === host || host.endsWith(`.${c.domain}`))) j.set({ ...c, expires: meta.exp });
  return raw;
}
async function cookies(c: OpContext): Promise<Json> {
  const s = session(c), j = attach(c, s);
  if (typeof s.session_id !== 'string' || !s.session_id) s.session_id = random().slice(0, 24);
  try {
    if (s.platform === 'mobile') {
      if (Number(s.access_expires_at) <= now()) await refresh(c, {});
      for (const host of ['steamcommunity.com', 'store.steampowered.com', 'help.steampowered.com', 'checkout.steampowered.com', 'steam.tv']) {
        put(j, 'steamLoginSecure', encodeURIComponent(`${s.steam_id}||${s.access_token}`), host, Number(s.access_expires_at));
        put(j, 'sessionid', String(s.session_id), host, null);
      }
    } else {
      seed(j, s);
      const data = await requestJson(c, 'https://login.steampowered.com/jwt/finalizelogin', { nonce: String(s.refresh_token), sessionid: String(s.session_id), redir: 'https://steamcommunity.com/login/home/?goto=' });
      if (data.steamID !== s.steam_id || !Array.isArray(data.transfer_info) || !data.transfer_info.length || data.transfer_info.length > 10) return invalid();
      const transfers = data.transfer_info.map(v => {
        const d = object(v); if (!d || typeof d.url !== 'string') return invalid();
        const u = validateUrl(d.url); if (!['steamcommunity.com', 'store.steampowered.com', 'help.steampowered.com', 'checkout.steampowered.com', 'steam.tv'].includes(u.hostname)) throw new OpError(400, 'egress_denied');
        const params = object(d.params); if (!params) return invalid();
        const fields: Record<string, string> = {};
        for (const [k, value] of Object.entries(params)) { if (typeof value !== 'string' || k.length > 128 || value.length > 16384) return invalid(); fields[k] = value; }
        fields.steamID = String(s.steam_id); return { u, fields };
      });
      for (const { u, fields } of transfers) {
        // Transfers may return an empty body; only successful HTTP + issued auth cookie is required.
        const form = new FormData(); for (const [k, v] of Object.entries(fields)) form.set(k, v);
        const r = await (c.transport as SteamTransport).request('POST', u, { body: form }); if (r.status >= 400) throw new OpError(502, 'upstream_login_failed');
        const access = cookieToken(j, u.hostname, 'steamLoginSecure', s);
        if (u.hostname === 'steamcommunity.com') { s.access_token = access; s.access_expires_at = jwt(access).exp; }
        put(j, 'sessionid', String(s.session_id), u.hostname, null);
      }
      const rotated = cookieToken(j, 'login.steampowered.com', 'steamRefresh_steam', s, true);
      s.refresh_token = rotated; s.refresh_expires_at = jwt(rotated).exp;
    }
    s.cookies = j.export(); s.ready_for_web = true;
    return { status: 'authenticated', steam_id: s.steam_id!, ready_for_web: true };
  } finally { s.cookies = j.export(); }
}
async function refresh(c: OpContext, args: Obj): Promise<Json> {
  const s = session(c);
  if (s.platform === 'mobile') {
    const m = await auth(c, 'GenerateAccessTokenForApp', new Writer().string(1, String(s.refresh_token)).fixed64(2, BigInt(String(s.steam_id))).uint(3, args.renew_refresh_token === true ? 1 : 0));
    const access = get.str(m, 1); if (!access) return invalid(); const r = get.str(m, 2) || String(s.refresh_token);
    const meta = tokens(access, r, 'mobile', s.steam_id); Object.assign(s, meta, { access_token: access, refresh_token: r });
    // Existing auth cookies refer to the old access token; rebuild them on session.cookies.
    s.cookies = []; s.ready_for_web = false;
  } else {
    if (args.renew_refresh_token === true) throw new OpError(400, 'web_refresh_renewal_unsupported');
    const j = attach(c, s); seed(j, s);
    try {
      const url = new URL('https://login.steampowered.com/jwt/refresh'); url.searchParams.set('redir', 'https://steamcommunity.com');
      const r = await (c.transport as SteamTransport).request('GET', url); if (r.status >= 400) throw new OpError(502, 'upstream_login_failed');
      const access = cookieToken(j, 'steamcommunity.com', 'steamLoginSecure', s);
      s.access_token = access; s.access_expires_at = jwt(access).exp;
      const rotated = cookieToken(j, 'login.steampowered.com', 'steamRefresh_steam', s, true);
      s.refresh_token = rotated; s.refresh_expires_at = jwt(rotated).exp;
    } finally { s.cookies = j.export(); }
  }
  return { status: 'authenticated', steam_id: s.steam_id! };
}
async function status(c: OpContext): Promise<Json> {
  const s = object(c.state.session), p = object(c.state.pending_login), g = object(c.state.guard);
  const validPending = !!p && typeof p.client_id === 'string' && typeof p.request_id === 'string' && !!p.request_id && Number(p.expires_at) > now();
  const authenticated = !!s?.refresh_token && Number(s.refresh_expires_at) > now();
  return { status: authenticated ? 'authenticated' : validPending ? 'pending' : 'unauthenticated', steam_id: authenticated ? s!.steam_id ?? null : null,
    expires_at: authenticated ? s!.access_expires_at ?? null : validPending ? p!.expires_at! : null,
    login_handle: validPending ? p!.login_handle! : null, challenge_url: validPending ? p!.challenge_url ?? null : null,
    poll_interval: validPending ? p!.poll_interval! : null, guard_configured: !!(g?.shared_secret || g?.identity_secret),
    ready_for_web: authenticated && new CookieJar(s!.cookies).header('https://steamcommunity.com/').includes('steamLoginSecure=') };
}
async function configure(c: OpContext, args: Obj): Promise<Json> {
  if (args.clear === true) { delete c.state.guard; return { configured: false }; }
  const g: Obj = { ...object(c.state.guard) };
  for (const k of ['shared_secret', 'identity_secret']) if (args[k] !== undefined) {
    const s = args[k]; if (typeof s !== 'string' || !/^[A-Za-z0-9+/]{27}=$/.test(s)) throw new OpError(400, 'invalid_arguments');
    try { if (unb64(s).length !== 20) throw new Error(); } catch { throw new OpError(400, 'invalid_arguments'); }
    g[k] = s;
  }
  for (const k of ['device_id', 'revocation_code']) if (args[k] !== undefined) g[k] = args[k]!;
  c.state.guard = g; return { configured: !!(g.shared_secret || g.identity_secret) };
}
const str = (maxLength: number) => ({ type: 'string', minLength: 1, maxLength });
const handle = { login_handle: str(128) };
function spec(name: string, properties: Record<string, Record<string, Json>>, required: string[], run: OperationSpec['run']): OperationSpec {
  return { name, scope: 'admin', mutating: name !== 'session.status', description: 'Bounded Steam session transition; sensitive material remains encrypted.', schema: { type: 'object', additionalProperties: false, properties, required }, run: async (ctx, args) => { if (ctx.scope !== 'admin') throw new OpError(403, 'scope_denied'); return run(ctx, args); } };
}
export const SESSION_OPS: OperationSpec[] = [
  spec('session.credentials', { account_name: str(128), password: str(1024), platform: { type: 'string', enum: ['web', 'mobile'] }, persistence: { type: 'boolean' }, device_friendly_name: str(128) }, ['account_name', 'password'], credentials),
  spec('session.qr', { platform: { type: 'string', enum: ['web'] }, device_friendly_name: str(128) }, [], qr),
  spec('session.code', { ...handle, auth_code: { type: 'string', minLength: 5, maxLength: 8, pattern: '^[A-Za-z0-9]+$' }, code_type: { type: 'string', enum: ['device', 'email'] } }, ['login_handle', 'auth_code'], code),
  spec('session.poll', handle, ['login_handle'], poll),
  spec('session.cookies', {}, [], cookies),
  spec('session.refresh', { renew_refresh_token: { type: 'boolean' } }, [], refresh),
  spec('session.cancel', handle, ['login_handle'], async (c, a) => { pending(c, a, false); delete c.state.pending_login; return { status: 'cancelled' }; }),
  spec('session.status', {}, [], status),
  spec('guard.configure', { shared_secret: str(128), identity_secret: str(128), device_id: { type: 'string', maxLength: 128, pattern: '^android:[0-9a-f-]{36}$' }, revocation_code: str(128), clear: { type: 'boolean' } }, [], configure),
];
