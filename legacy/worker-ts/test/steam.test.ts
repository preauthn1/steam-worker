import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateAuthCode, generateConfirmationKey } from '../src/steam/guard.ts';
import { Writer, decode, get } from '../src/steam/protobuf.ts';
import { SteamTransport, validateUrl } from '../src/steam/transport.ts';
import { callService } from '../src/steam/webapi.ts';
import { OPERATIONS, OPERATIONS_JSON, describeOperations, validateArgs } from '../src/steam/registry.ts';
import { OpError, type OpContext } from '../src/types.ts';

// Vectors produced by the upstream Python SDK (aiosteampy.guard.secrets) with a synthetic secret.
const SECRET = 'MDEyMzQ1Njc4OWFiY2RlZmdoaWo=';
const VECTORS: [number, string, string, string][] = [
  [1700000000, 'C96G3', 'BlugZOBFqoeysQ4l5Uct3qjTnSs=', 'BSu41NpWWmSpfl7qH2RZJE/Ea14='],
  [1234567890, 'K7FBH', 'JZCBZ7Ro9JFyh74A8mFJCHenwtI=', '9bV48dx921UzTWmdftiH9x8dpvo='],
  [1, 'CX2MR', '2TQo9NmIEhxflEcvHagTX4TVyYI=', 'bzFkzYCj2e4EW5stg1JLlgdaAhI='],
];

test('guard codes match the Python implementation', async () => {
  for (const [t, code, conf, allow] of VECTORS) {
    assert.equal(await generateAuthCode(SECRET, t), code);
    assert.equal(await generateConfirmationKey(SECRET, 'conf', t), conf);
    assert.equal(await generateConfirmationKey(SECRET, 'allow', t), allow);
  }
});

test('protobuf round trip incl. 64-bit and negative values', () => {
  const big = 76561197960265729n;
  const bytes = new Writer().uint(1, 150).string(2, 'héllo').fixed64(3, big).uint(4, big).bool(5, true).uint(6, -1).finish();
  const m = decode(bytes);
  assert.equal(get.int(m, 1), 150n);
  assert.equal(get.str(m, 2), 'héllo');
  assert.equal(get.int(m, 3), big);
  assert.equal(get.int(m, 4), big);
  assert.equal(get.int(m, 5), 1n);
  assert.equal(get.int(m, 6), 0xffffffffffffffffn);
  assert.deepEqual([...new Writer().uint(1, 150).finish()], [0x08, 0x96, 0x01]);
  assert.throws(() => decode(Uint8Array.from([0x0a, 0x05, 0x01])), /truncated/);
});

test('egress allowlist', () => {
  validateUrl('https://api.steampowered.com/x');
  for (const bad of ['http://steamcommunity.com/', 'https://evil.example.com/', 'https://steamcommunity.com.example.com/',
    'https://user:pw@steamcommunity.com/', 'https://steamcommunity.com:8443/']) {
    assert.throws(() => validateUrl(bad), (e: unknown) => e instanceof OpError && e.code === 'egress_denied', bad);
  }
});

type Call = { url: string; init: RequestInit };
function fake(responses: (() => Response)[]): { t: SteamTransport; calls: Call[] } {
  const calls: Call[] = [];
  let i = 0;
  const t = new SteamTransport(async (url, init) => {
    calls.push({ url, init });
    const r = responses[Math.min(i++, responses.length - 1)];
    return r!();
  });
  return { t, calls };
}

test('redirects: same host followed, foreign host denied, cookies stripped cross-origin', async () => {
  const a = fake([
    () => new Response(null, { status: 302, headers: { location: '/b' } }),
    () => new Response('ok'),
  ]);
  const r = await a.t.request('GET', 'https://steamcommunity.com/a');
  assert.equal(r.url.pathname, '/b');
  assert.equal(a.t.requestCount, 2);

  const b = fake([() => new Response(null, { status: 302, headers: { location: 'https://evil.example.com/' } })]);
  await assert.rejects(b.t.request('GET', 'https://steamcommunity.com/a'), (e: unknown) => e instanceof OpError && e.code === 'egress_denied');

  const c = fake([
    () => new Response(null, { status: 302, headers: { location: 'https://store.steampowered.com/x' } }),
    () => new Response('ok'),
  ]);
  await c.t.request('GET', 'https://steamcommunity.com/a', { headers: { Cookie: 'sid=synthetic' } });
  assert.equal((c.calls[1]!.init.headers as Record<string, string>).Cookie, undefined);

  const d = fake([() => new Response(null, { status: 307, headers: { location: 'https://store.steampowered.com/x' } })]);
  await assert.rejects(d.t.request('POST', 'https://steamcommunity.com/a', { body: 'x=1' }),
    (e: unknown) => e instanceof OpError && e.code === 'cross_origin_body_redirect_denied');
});

test('request budget and response cap', async () => {
  const loop = fake([() => new Response(null, { status: 302, headers: { location: '/loop' } })]);
  await assert.rejects(loop.t.request('GET', 'https://steamcommunity.com/loop'), (e: unknown) => e instanceof OpError);
  assert.ok(loop.t.requestCount <= 40);

  const huge = fake([() => new Response(new Uint8Array(8_000_001))]);
  await assert.rejects(huge.t.request('GET', 'https://steamcommunity.com/'),
    (e: unknown) => e instanceof OpError && e.code === 'upstream_response_too_large');
});

test('webapi call encodes protobuf and maps EResult', async () => {
  const ok = fake([() => new Response(new Writer().uint(1, 1800000000).finish(), { headers: { 'x-eresult': '1' } })]);
  const body = await callService(ok.t, 'ITwoFactorService', 'QueryTime', new Writer().uint(1, 5).finish());
  assert.equal(get.int(decode(body), 1), 1800000000n);
  assert.match(ok.calls[0]!.url, /ITwoFactorService\/QueryTime\/v1$/);
  assert.equal(String(ok.calls[0]!.init.body), 'input_protobuf_encoded=CAU%3D');

  const limited = fake([() => new Response('', { headers: { 'x-eresult': '84' } })]);
  await assert.rejects(callService(limited.t, 'I', 'M', new Uint8Array()), (e: unknown) => e instanceof OpError && e.status === 429);
});

function ctx(t: SteamTransport): OpContext { return { state: {}, transport: t, scope: 'read' }; }

test('public.server_time returns uint64 as string', async () => {
  const f = fake([() => new Response(new Writer().uint(1, 1800000000).finish(), { headers: { 'x-eresult': '1' } })]);
  assert.deepEqual(await OPERATIONS.get('public.server_time')!.run(ctx(f.t), {}), { server_time: '1800000000' });
});

test('price overview takes median from median_price', async () => {
  const f = fake([() => Response.json({ success: true, lowest_price: '$1.23', median_price: '$4.56', volume: '7' })]);
  const out = await OPERATIONS.get('public.market.get_price_overview')!.run(ctx(f.t), { obj: 'Synthetic Item', app: 730 });
  assert.deepEqual(out, { lowest_price: '$1.23', median_price: '$4.56', lowest_price_minor: 123, median_price_minor: 456, volume: '7' });
  const u = new URL(f.calls[0]!.url);
  assert.equal(u.searchParams.get('market_hash_name'), 'Synthetic Item');
  assert.equal(u.searchParams.get('appid'), '730');
});

test('price overview preserves upstream rate limiting', async () => {
  const f = fake([() => new Response('', { status: 429 })]);
  await assert.rejects(
    OPERATIONS.get('public.market.get_price_overview')!.run(ctx(f.t), { obj: 'Synthetic Item' }),
    (e: unknown) => e instanceof OpError && e.status === 429 && e.code === 'upstream_rate_limited',
  );
});

test('argument validation and cached catalog', () => {
  const spec = OPERATIONS.get('public.market.get_price_overview')!;
  assert.deepEqual(validateArgs(spec, { obj: 'x' }), { obj: 'x' });
  for (const bad of [null, [], {}, { obj: 1 }, { obj: 'x', extra: 1 }, { obj: 'x', app: 1.5 }, { obj: 'x', app: 0 }]) {
    assert.throws(() => validateArgs(spec, bad), (e: unknown) => e instanceof OpError && e.status === 400);
  }
  assert.equal(describeOperations(), describeOperations());
  assert.equal(JSON.parse(OPERATIONS_JSON).operations.length, OPERATIONS.size);
});
