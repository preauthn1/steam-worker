import test from 'node:test';
import assert from 'node:assert/strict';
import { AUTHENTICATED_OPS } from '../src/steam/authenticated.ts';
import { SteamTransport } from '../src/steam/transport.ts';
import { OpError, type Json, type OpContext, type AccountState } from '../src/types.ts';

const state = (): AccountState => ({ session: { steam_id: '76561198000000001', access_token: 'token', refresh_token: 'refresh', session_id: 'session', cookies: ['sessionid', 'steamLoginSecure'].map(name => ({ name, value: name === 'sessionid' ? 'session' : 'auth', domain: 'steamcommunity.com', path: '/', hostOnly: true, secure: true, expires: null })) }, wallet: { currency: 23 }, guard: { identity_secret: 'AAAAAAAAAAAAAAAAAAAAAAAAAAA=', device_id: 'android:12345678-1234-1234-1234-123456789abc' } });
function setup(responses: Json[] = [{ success: true }], account = state(), scope: OpContext['scope'] = 'admin') {
  const calls: { url: URL; init: RequestInit }[] = [];
  const transport = new SteamTransport(async (url, init) => { calls.push({ url: new URL(url), init }); return new Response(JSON.stringify(responses.shift()), { status: 200 }); });
  return { calls, ctx: { state: account, transport, scope } satisfies OpContext };
}
function run(ctx: OpContext, name: string, args: Record<string, Json> = {}) { return AUTHENTICATED_OPS.find(o => o.name === name)!.run(ctx, args); }
function form(init: RequestInit) { return new URLSearchParams(String(init.body)); }

test('every authenticated operation rejects absent session before network', async () => {
  for (const op of AUTHENTICATED_OPS) {
    const { ctx, calls } = setup([], {});
    await assert.rejects(op.run(ctx, {}), (e: unknown) => e instanceof OpError && e.code === 'authentication_required');
    assert.equal(calls.length, 0);
  }
});
test('inventory uses session owner and authenticated cookies', async () => {
  const { ctx, calls } = setup([{ success: 1, total_inventory_count: 0, assets: [], descriptions: [] }]);
  await run(ctx, 'inventory.get', { app: 730, context_id: '2', count: 75, start_asset_id: '123' });
  assert.equal(calls[0]!.url.pathname, '/inventory/76561198000000001/730/2');
  assert.equal(calls[0]!.url.searchParams.get('start_assetid'), '123');
  assert.equal(calls[0]!.url.searchParams.get('raw_asset_properties'), '1');
  assert.match((calls[0]!.init.headers as Record<string, string>).Cookie!, /steamLoginSecure=auth/);
});
test('money rejects fractions, absent currency, negative fees and unsafe totals before network', async () => {
  for (const [name, args] of [
    ['market.place_sell_listing', { app: 730, context_id: '2', asset_id: '1', to_receive: 1.5, currency: 1 }],
    ['market.place_sell_listing', { app: 730, context_id: '2', asset_id: '1', to_receive: 1 }],
    ['market.buy_listing', { listing_id: '1', app: 730, market_hash_name: 'Item', subtotal: 10, fee: -1, currency: 1 }],
    ['market.buy_listing', { listing_id: '1', app: 730, market_hash_name: 'Item', subtotal: Number.MAX_SAFE_INTEGER, fee: 1, currency: 1 }],
    ['market.place_buy_order', { app: 730, market_hash_name: 'Item', price: Number.MAX_SAFE_INTEGER, quantity: 2, currency: 1 }],
  ] as [string, Record<string, Json>][]) {
    const { ctx, calls } = setup(); await assert.rejects(run(ctx, name, args)); assert.equal(calls.length, 0);
  }
});
test('sell price is to_receive and pending confirmation never auto-approved', async () => {
  const { ctx, calls } = setup([{ success: true, needs_mobile_confirmation: true }]);
  const result = await run(ctx, 'market.place_sell_listing', { app: 730, context_id: '2', asset_id: '99', to_receive: 100, currency: 23 });
  assert.equal(form(calls[0]!.init).get('price'), '100');
  assert.equal(calls.length, 1); assert.equal((result as Record<string, Json>).pending_confirmation, true);
});
test('buy order multiplies integer unit price once and never repeats pending effects', async () => {
  const { ctx, calls } = setup([{ need_confirmation: true, confirmation: { confirmation_id: '321' } }]);
  const result = await run(ctx, 'market.place_buy_order', { app: 730, market_hash_name: 'Item', price: 100, quantity: 3, currency: 23 });
  assert.equal(form(calls[0]!.init).get('price_total'), '300'); assert.equal(form(calls[0]!.init).get('currency'), '23');
  assert.equal(calls.length, 1); assert.equal((result as Record<string, Json>).pending_confirmation, true);
});
test('buy listing sends explicit subtotal fee total as multipart', async () => {
  const { ctx, calls } = setup([{ wallet_info: { success: 1, wallet_balance: '50' } }]);
  await run(ctx, 'market.buy_listing', { listing_id: '1', app: 730, market_hash_name: 'A/B', subtotal: 100, fee: 15, currency: 23 });
  const body = calls[0]!.init.body as FormData;
  assert.equal(body.get('subtotal'), '100'); assert.equal(body.get('fee'), '15'); assert.equal(body.get('total'), '115');
  assert.equal((calls[0]!.init.headers as Record<string,string>).Referer, 'https://steamcommunity.com/market/listings/730/A%2FB');
});
test('trade uses IEconService token parameters and explicit partner assets', async () => {
  const { ctx, calls } = setup([{ response: { offer: { tradeofferid: '1' } } }, { tradeofferid: '9', needs_mobile_confirmation: true }]);
  await run(ctx, 'trade.get', { trade_offer_id: '1' });
  assert.equal(calls[0]!.url.pathname, '/IEconService/GetTradeOffer/v1/'); assert.equal(calls[0]!.url.searchParams.get('access_token'), 'token');
  await run(ctx, 'trade.send', { partner: '76561198000000002', to_partner: [{ appid: 730, contextid: '2', assetid: '7', amount: 1 }], from_partner: [], token: 'abc' });
  const data = form(calls[1]!.init); const offer = JSON.parse(data.get('json_tradeoffer')!);
  assert.equal(offer.me.assets[0].assetid, '7'); assert.equal(data.get('partner'), '76561198000000002'); assert.equal(calls.length, 2);
});
test('invalid IDs and duplicate or malformed asset arrays fail before network', async () => {
  for (const args of [
    { partner: '1/accept', to_partner: [], from_partner: [] },
    { partner: '76561198000000002', to_partner: [{ appid: 730, contextid: '2', assetid: '1', amount: 0 }], from_partner: [] },
    { partner: '76561198000000002', to_partner: [{ appid: 730, contextid: '2', assetid: '1', amount: 1 }, { appid: 730, contextid: '2', assetid: '1', amount: 1 }], from_partner: [] },
  ]) { const { ctx, calls } = setup(); await assert.rejects(run(ctx, 'trade.send', args)); assert.equal(calls.length, 0); }
});
test('confirmation actual type is fetched and unsafe type cannot be spoofed', async () => {
  const { ctx, calls } = setup([{ success: true, conf: [{ id: '1', nonce: '22', type: 9 }] }], state(), 'write');
  await assert.rejects(run(ctx, 'confirmations.accept', { confirmation_id: '1' }), (e: unknown) => e instanceof OpError && e.code === 'confirmation_type_denied');
  assert.equal(calls.length, 1); assert.equal(calls[0]!.url.pathname, '/mobileconf/getlist');
});
test('single confirmation uses refetched nonce and supported actual type', async () => {
  const { ctx, calls } = setup([{ success: true, conf: [{ id: '1', nonce: '22', type: 2 }] }, { success: true }], state(), 'write');
  await run(ctx, 'confirmations.accept', { confirmation_id: '1' });
  assert.equal(calls[1]!.url.pathname, '/mobileconf/ajaxop'); assert.equal(calls[1]!.url.searchParams.get('ck'), '22'); assert.equal(calls[1]!.url.searchParams.get('op'), 'allow');
});
test('bulk requires admin before network and unknown types fail closed even for admin', async () => {
  const first = setup([], state(), 'write'); await assert.rejects(run(first.ctx, 'confirmations.accept_all')); assert.equal(first.calls.length, 0);
  const second = setup([{ success: true, conf: [{ id: '1', nonce: '2', type: 99 }] }]);
  await assert.rejects(run(second.ctx, 'confirmations.accept_all')); assert.equal(second.calls.length, 1);
});
test('multi confirmation sends repeated server-derived cid and ck fields', async () => {
  const { ctx, calls } = setup([{ success: true, conf: [{ id: '1', nonce: '21', type: 3 }, { id: '2', nonce: '22', type: 12 }] }, { success: true }]);
  await run(ctx, 'confirmations.send_multiple', { confirmation_ids: ['1', '2'], accept: false });
  assert.equal(calls[1]!.url.pathname, '/mobileconf/multiajaxop'); assert.deepEqual(form(calls[1]!.init).getAll('cid[]'), ['1', '2']); assert.deepEqual(form(calls[1]!.init).getAll('ck[]'), ['21', '22']);
});
test('wallet info populates trusted currency before sell and buy', async () => {
  const account = state(); delete account.wallet;
  const wallet: Record<string, Json> = { success: 1, wallet_currency: 23, wallet_country: 'CN', wallet_state: '', wallet_fee_percent: '0.05', wallet_publisher_fee_percent_default: '0.1' };
  for (const key of ['wallet_fee', 'wallet_fee_minimum', 'wallet_market_minimum', 'wallet_currency_increment', 'wallet_fee_base', 'wallet_balance', 'wallet_delayed_balance', 'wallet_max_balance', 'wallet_trade_max_balance']) wallet[key] = '100';
  const calls: URL[] = [];
  const transport = new SteamTransport(async (url) => {
    calls.push(new URL(url));
    if (calls.length === 1) return new Response(`g_rgWalletInfo = ${JSON.stringify(wallet)};`, { status: 200 });
    return new Response(JSON.stringify(calls.length === 2 ? { success: true } : { buy_orderid: '12', success: 1 }));
  });
  const ctx: OpContext = { state: account, transport, scope: 'write' };
  await assert.rejects(run(ctx, 'market.place_sell_listing', { app: 730, context_id: '2', asset_id: '1', to_receive: 100, currency: 23 })); assert.equal(calls.length, 0);
  await run(ctx, 'wallet.info'); assert.equal((ctx.state.wallet as Record<string, Json>).currency, 23);
  await run(ctx, 'market.place_sell_listing', { app: 730, context_id: '2', asset_id: '1', to_receive: 100, currency: 23 });
  await run(ctx, 'market.place_buy_order', { app: 730, market_hash_name: 'Item', price: 100, currency: 23 });
  assert.equal(calls.length, 3);
});
test('confirmation reads redact nonce', async () => {
  const { ctx } = setup([{ success: 1, conf: [{ id: '1', nonce: '2', type: 2 }] }]);
  const value = await run(ctx, 'confirmations.get_all') as Record<string, Json>[];
  assert.equal('nonce' in value[0]!, false);
});
test('inventory rejects nonadvancing pagination cursor', async () => {
  const { ctx } = setup([{ success: 1, total_inventory_count: 0, last_assetid: '100', more_items: 1 }]);
  await assert.rejects(run(ctx, 'inventory.get', { app: 730, context_id: '2', start_asset_id: '100' }));
});
test('cancel rejects 200 HTML and reports empty-body metadata without invented success', async () => {
  for (const name of ['market.cancel_sell_listing', 'market.cancel_buy_order']) {
    const args: Record<string, Json> = name.endsWith('sell_listing') ? { listing_id: '1' } : { buy_order_id: '1' };
    const ctx: OpContext = { state: state(), scope: 'write', transport: new SteamTransport(async () => new Response('<html>login</html>')) };
    await assert.rejects(run(ctx, name, args));
    ctx.transport = new SteamTransport(async () => new Response('', { status: 200 }));
    const result = await run(ctx, name, args) as Record<string, Json>; assert.equal(result.upstream_status, 200); assert.equal('success' in result, false);
  }
});
test('cookie rotation persists in finally even when response is rejected', async () => {
  const ctx: OpContext = { state: state(), scope: 'read', transport: new SteamTransport(async () => new Response('{}', { headers: { 'set-cookie': 'steamLoginSecure=rotated; Path=/; Secure' } })) };
  await assert.rejects(run(ctx, 'inventory.get', { app: 730, context_id: '2' }));
  const cookies = (ctx.state.session as Record<string, Json>).cookies as Record<string, Json>[];
  assert.equal(cookies.find(c => c.name === 'steamLoginSecure')!.value, 'rotated');
});
test('HTTP429 maps to rate limit without retry', async () => {
  let count = 0;
  const ctx: OpContext = { state: state(), scope: 'write', transport: new SteamTransport(async () => { count++; return new Response('', { status: 429 }); }) };
  await assert.rejects(run(ctx, 'market.cancel_buy_order', { buy_order_id: '1' }), (e: unknown) => e instanceof OpError && e.status === 429); assert.equal(count, 1);
});
test('remaining market and trade endpoints use exact upstream parameters', async () => {
  const { ctx, calls } = setup([
    { success: 1, listings: [], listings_to_confirm: [], buy_orders: [], num_active_listings: 0 },
    { success: 1, active: 1, purchased: 0, quantity: 2, quantity_remaining: 2 },
    { success: 1 }, { success: 1 },
    { response: { next_cursor: 3, trade_offers_sent: [], trade_offers_received: [] } },
    { tradeid: '20', needs_mobile_confirmation: true }, { tradeofferid: '12' }, { tradeofferid: '13' },
  ]);
  await run(ctx, 'market.get_user_listings', { start: 10, count: 25 }); assert.equal(calls[0]!.url.pathname, '/market/mylistings'); assert.equal(calls[0]!.url.searchParams.get('norender'), '1');
  await run(ctx, 'market.get_buy_order_status', { buy_order_id: '3' }); assert.equal(calls[1]!.url.searchParams.get('sessionid'), 'session'); assert.equal(calls[1]!.url.searchParams.get('buy_orderid'), '3');
  await run(ctx, 'market.cancel_sell_listing', { listing_id: '4' }); assert.equal(calls[2]!.url.pathname, '/market/removelisting/4');
  await run(ctx, 'market.cancel_buy_order', { buy_order_id: '5' }); assert.equal(calls[3]!.url.pathname, '/market/cancelbuyorder/'); assert.equal(form(calls[3]!.init).get('buy_orderid'), '5');
  await run(ctx, 'trade.get_multiple', { historical_cutoff: 100, cursor: 2, sent: false }); assert.equal(calls[4]!.url.pathname, '/IEconService/GetTradeOffers/v1/'); assert.equal(calls[4]!.url.searchParams.get('time_historical_cutoff'), '100'); assert.equal(calls[4]!.url.searchParams.get('get_sent_offers'), '0');
  const accepted = await run(ctx, 'trade.accept', { trade_offer_id: '11', partner: '76561198000000002' }) as Record<string, Json>;
  assert.equal(calls[5]!.url.pathname, '/tradeoffer/11/accept'); assert.equal(form(calls[5]!.init).get('partner'), '76561198000000002'); assert.equal(accepted.pending_confirmation, true);
  await run(ctx, 'trade.decline', { trade_offer_id: '12' }); assert.equal(calls[6]!.url.pathname, '/tradeoffer/12/decline');
  await run(ctx, 'trade.cancel', { trade_offer_id: '13' }); assert.equal(calls[7]!.url.pathname, '/tradeoffer/13/cancel'); assert.equal(calls.length, 8);
});
test('all supported confirmation types work but account-security types remain denied for admin', async () => {
  for (const type of [2, 3, 12, 13]) {
    const { ctx, calls } = setup([{ success: 1, conf: [{ id: '1', nonce: '2', type }] }, { success: 1 }], state(), 'write');
    await run(ctx, 'confirmations.deny', { confirmation_id: '1' }); assert.equal(calls[1]!.url.searchParams.get('op'), 'cancel');
  }
  for (const type of [0, 1, 4, 5, 6, 7, 8, 9, 10, 11]) {
    const { ctx, calls } = setup([{ success: 1, conf: [{ id: '1', nonce: '2', type }] }]);
    await assert.rejects(run(ctx, 'confirmations.deny_all')); assert.equal(calls.length, 1);
  }
});
test('explicit currency mismatch and overflow reject before financial effects', async () => {
  for (const args of [
    { app: 730, market_hash_name: 'Item', price: 100, quantity: 1, currency: 1 },
    { app: 730, market_hash_name: 'Item', price: Number.MAX_SAFE_INTEGER, quantity: 2, currency: 23 },
  ]) { const { ctx, calls } = setup(); await assert.rejects(run(ctx, 'market.place_buy_order', args)); assert.equal(calls.length, 0); }
  const { ctx, calls } = setup();
  await assert.rejects(run(ctx, 'market.buy_listing', { listing_id: '1', app: 730, market_hash_name: 'Item', subtotal: Number.MAX_SAFE_INTEGER, fee: 1, currency: 23 })); assert.equal(calls.length, 0);
});
test('malformed upstream JSON objects are not accepted as success', async () => {
  const { ctx } = setup([{}]); await assert.rejects(run(ctx, 'market.place_sell_listing', { app: 730, context_id: '2', asset_id: '1', to_receive: 100, currency: 23 }));
});
