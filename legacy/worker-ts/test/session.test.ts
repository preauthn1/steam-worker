import assert from 'node:assert/strict';
import test from 'node:test';
import { generateKeyPairSync, privateDecrypt, constants } from 'node:crypto';
import { encryptPassword } from '../src/steam/rsa.ts';
import { CookieJar } from '../src/steam/cookies.ts';
import { SESSION_OPS } from '../src/steam/session.ts';
import { SteamTransport } from '../src/steam/transport.ts';
import { Writer, decode, get } from '../src/steam/protobuf.ts';
import type { OpContext, Json } from '../src/types.ts';

const op = (name: string) => SESSION_OPS.find(x => x.name === name)!;
function float(field: number, value: number): Uint8Array {
  const b = new Uint8Array(5); b[0] = (field << 3) | 5; new DataView(b.buffer).setFloat32(1, value, true); return b;
}
const concat = (...a: Uint8Array[]) => Uint8Array.from(a.flatMap(x => [...x]));
const qr = () => concat(new Writer().uint(1, 123n).string(2, 'https://s.team/q/1/123').bytes(3, new Uint8Array([1, 2])).bytes(5, new Writer().uint(1, 4).finish()).uint(6, 1).finish(), float(4, 5));
function ctx(responses: Uint8Array[], seen: string[] = []): OpContext {
  return { scope: 'admin', state: {}, transport: new SteamTransport(async (url, init) => {
    seen.push(url); return new Response(responses.shift()!, { headers: { 'x-eresult': '1' } });
  }) };
}
const run = (c: OpContext, name: string, args: Record<string, Json> = {}) => op(name).run(c, args);

test('cookie scope, expiry and trusted-host enforcement', () => {
  const j = new CookieJar();
  j.setFromHeaders('https://steamcommunity.com/login/start', new Headers({ 'set-cookie': 'a=secret; Path=/login; Secure' }));
  assert.equal(j.header('https://steamcommunity.com/login/x'), 'a=secret');
  assert.equal(j.header('https://steamcommunity.com/loginish'), '');
  assert.equal(j.header('https://store.steampowered.com/login/x'), '');
  j.setFromHeaders('https://steamcommunity.com/', new Headers({ 'set-cookie': 'b=secret; Domain=example.com; Path=/' }));
  assert.equal((j.export() as Json[]).length, 1);
  assert.throws(() => j.header('https://example.com/'));
  j.setFromHeaders('https://steamcommunity.com/login/start', new Headers({ 'set-cookie': 'a=gone; Path=/login; Max-Age=0' }));
  assert.equal(j.header('https://steamcommunity.com/login/x'), '');
});

test('QR persists a complete challenge and rejects wrong handles', async () => {
  const c = ctx([qr()]); const result = await run(c, 'session.qr') as Record<string, Json>;
  assert.equal(result.status, 'pending'); assert.equal(typeof result.login_handle, 'string');
  assert.equal(result.poll_interval, 5);
  assert.ok(c.state.pending_login);
  await assert.rejects(run(c, 'session.poll', { login_handle: 'wrong' }), /login_handle_mismatch/);
});

test('malformed startup never persists partial pending state', async () => {
  const c = ctx([new Writer().uint(1, 123).finish()]);
  await assert.rejects(run(c, 'session.qr'), /upstream_invalid_response/);
  assert.equal(c.state.pending_login, undefined);
});

test('single poll rotates client ID and enforces upstream interval', async () => {
  const seen: string[] = [], c = ctx([qr(), new Writer().uint(1, 456).string(2, 'https://s.team/q/1/456').finish()], seen);
  const r = await run(c, 'session.qr') as Record<string, Json>;
  const args = { login_handle: r.login_handle! };
  await run(c, 'session.poll', args);
  assert.equal((c.state.pending_login as Record<string, Json>).client_id, '456');
  await assert.rejects(run(c, 'session.poll', args), /poll_too_soon/);
  assert.equal(seen.length, 2);
});

test('expiry and cancel remove resumable challenge', async () => {
  const c = ctx([qr()]); const r = await run(c, 'session.qr') as Record<string, Json>;
  (c.state.pending_login as Record<string, Json>).expires_at = 0;
  await assert.rejects(run(c, 'session.poll', { login_handle: r.login_handle! }), /login_expired/);
  assert.equal(c.state.pending_login, undefined);
  const d = ctx([qr()]); const q = await run(d, 'session.qr') as Record<string, Json>;
  await run(d, 'session.cancel', { login_handle: q.login_handle! });
  assert.equal(d.state.pending_login, undefined);
});

test('all session schemas admin-scoped and status alone read-only', () => {
  assert.equal(SESSION_OPS.length, 9);
  for (const s of SESSION_OPS) { assert.equal(s.scope, 'admin'); assert.equal(s.mutating, s.name !== 'session.status'); assert.equal(s.schema.additionalProperties, false); }
});

test('status and guard configure never disclose secret material', async () => {
  const c = ctx([]);
  const r = await run(c, 'guard.configure', { shared_secret: 'AAAAAAAAAAAAAAAAAAAAAAAAAAA=', identity_secret: 'AAAAAAAAAAAAAAAAAAAAAAAAAAA=' });
  assert.ok(!JSON.stringify(r).includes('AAAAAAAA'));
  assert.ok(!JSON.stringify(await run(c, 'session.status')).includes('AAAAAAAA'));
});

test('transport preserves cross-origin body redirect denial', async () => {
  const t = new SteamTransport(async () => new Response(null, { status: 307, headers: { location: 'https://store.steampowered.com/' } }));
  await assert.rejects(t.request('POST', 'https://steamcommunity.com/', { body: 'secret' }), /cross_origin_body_redirect_denied/);
});

test('body deadline cancels the locked reader without uncaught errors', async () => {
  let cancelled = false;
  const t = new SteamTransport(async () => new Response(new ReadableStream<Uint8Array>({ cancel() { cancelled = true; } })), 10);
  await assert.rejects(t.request('GET', 'https://steamcommunity.com/'), /upstream_unreachable/);
  assert.equal(cancelled, true);
});

test('credentials send valid RSA padding and never persist the password', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
  const key = publicKey.export({ format: 'jwk' });
  const hex = (v: string) => Buffer.from(v, 'base64url').toString('hex');
  const responses = [new Writer().string(1, hex(key.n!)).string(2, hex(key.e!)).uint(3, 42).finish(),
    concat(new Writer().uint(1, 123).bytes(2, new Uint8Array([1])).bytes(4, new Writer().uint(1, 3).finish()).uint(5, 123).finish(), float(3, 1))];
  let encrypted = '';
  const c: OpContext = { state: {}, scope: 'admin', transport: new SteamTransport(async (_url, init) => {
    if (init.method === 'POST') {
      const m = decode(Buffer.from(new URLSearchParams(String(init.body)).get('input_protobuf_encoded')!, 'base64'));
      encrypted = get.str(m, 3)!; assert.equal(get.int(m, 4), 42n);
    }
    return new Response(responses.shift()!);
  }) };
  const r = await run(c, 'session.credentials', { account_name: 'synthetic', password: 'synthetic-password' });
  const padded = privateDecrypt({ key: privateKey, padding: constants.RSA_NO_PADDING }, Buffer.from(encrypted, 'base64'));
  assert.equal(padded[0], 0); assert.equal(padded[1], 2);
  const zero = padded.indexOf(0, 2); assert.ok(zero >= 10);
  assert.equal(padded.subarray(zero + 1).toString(), 'synthetic-password');
  assert.ok(!JSON.stringify(c.state).includes('synthetic-password')); assert.ok(!JSON.stringify(r).includes('synthetic-password'));
  assert.throws(() => encryptPassword('x', 'f'.repeat(1025), '10001'), /invalid_rsa_key/);
});

function token(refresh = false, p = 'web'): string {
  return `synthetic.${Buffer.from(JSON.stringify({ sub: '123', exp: 4102444800, aud: refresh ? [p, 'derive'] : [p] })).toString('base64url')}.synthetic`;
}
test('complete synthetic QR login obtains domain-scoped web cookies without disclosure', async () => {
  const access = token(), refresh = token(true), hosts = ['steamcommunity.com', 'checkout.steampowered.com', 'steam.tv'];
  let stage = 0;
  const c: OpContext = { state: {}, scope: 'admin', transport: new SteamTransport(async (url, init) => {
    stage++;
    if (stage === 1) return new Response(qr());
    if (stage === 2) return new Response(new Writer().string(3, refresh).string(4, access).finish());
    if (stage === 3) {
      assert.equal((init.body as FormData).get('nonce'), refresh);
      return new Response(JSON.stringify({ steamID: '123', transfer_info: hosts.map(h => ({ url: `https://${h}/login/transfer`, params: { nonce: 'synthetic' } })) }));
    }
    assert.ok(hosts.includes(new URL(url).hostname));
    assert.equal((init.body as FormData).get('steamID'), '123');
    return new Response('', { headers: { 'set-cookie': `steamLoginSecure=${encodeURIComponent('123||' + access)}; Secure; Path=/` } });
  }) };
  const p = await run(c, 'session.qr') as Record<string, Json>;
  const login = await run(c, 'session.poll', { login_handle: p.login_handle! });
  assert.equal((login as Record<string, Json>).status, 'authenticated'); assert.equal(c.state.pending_login, undefined);
  const r = await run(c, 'session.cookies') as Record<string, Json>;
  assert.equal(r.ready_for_web, true);
  assert.ok(!JSON.stringify(r).includes(access)); assert.ok(!JSON.stringify(r).includes(refresh));
  const jar = new CookieJar((c.state.session as Record<string, Json>).cookies);
  for (const host of hosts) assert.ok(jar.header(`https://${host}/`).includes('steamLoginSecure='));
  assert.ok(!jar.header('https://api.steampowered.com/').includes('steamLoginSecure='));
});

test('mobile refresh rotates tokens and invalidates old web cookies', async () => {
  const a = token(false, 'mobile'), r = token(true, 'mobile');
  const c = ctx([new Writer().string(1, a).string(2, r).finish()]);
  c.state.session = { steam_id: '123', platform: 'mobile', refresh_token: r, access_token: a, refresh_expires_at: 4102444800, access_expires_at: 4102444800, cookies: [], session_id: 'synthetic' };
  const result = await run(c, 'session.refresh', { renew_refresh_token: true });
  assert.equal((c.state.session as Record<string, Json>).access_token, a);
  assert.ok(!JSON.stringify(result).includes(a));
  assert.deepEqual((c.state.session as Record<string, Json>).cookies, []);
});

test('web refresh collects cookies across exact-host redirect and accepts web-scoped audience', async () => {
  const r = token(true), a = token(false, 'web:community');
  let n = 0;
  const c: OpContext = { scope: 'admin', state: { session: { steam_id: '123', platform: 'web', refresh_token: r, access_token: token(), refresh_expires_at: 4102444800, session_id: 'synthetic', cookies: [] } }, transport: new SteamTransport(async (_u, init) => {
    n++;
    if (n === 1) { assert.ok(init.headers && JSON.stringify(init.headers).includes('steamRefresh_steam')); return new Response(null, { status: 302, headers: { location: 'https://steamcommunity.com/login/transfer' } }); }
    assert.ok(!JSON.stringify(init.headers).includes('steamRefresh_steam'));
    return new Response('', { headers: { 'set-cookie': `steamLoginSecure=${encodeURIComponent('123||' + a)}; Secure; Path=/` } });
  }) };
  await run(c, 'session.refresh');
  assert.equal((c.state.session as Record<string, Json>).access_token, a);
  assert.equal(n, 2);
});

test('session operations reject direct non-admin calls before upstream requests', async () => {
  for (const scope of ['read', 'write'] as const) {
    const c = ctx([]); c.scope = scope;
    for (const s of SESSION_OPS) await assert.rejects(s.run(c, {}), /scope_denied/);
    assert.equal(c.transport.requestCount, 0);
  }
});
