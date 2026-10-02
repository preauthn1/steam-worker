// Authenticated Steam inventory/market/trade/confirmation operations.
// Session schema: state.session={steam_id:string,access_token:string,session_id:string,
// cookies:Array<{name,value,domain,path,hostOnly,secure,expires:number|null}>,...}.
// Guard confirmations additionally require state.guard={identity_secret,device_id,...}.
// All monetary inputs are safe integer minor units; currency is explicit. No retries,
// fee guessing, USD defaults, automatic confirmation approval or generic forwarding.
import { OpError, type Json, type JsonSchema, type OpContext, type OperationSpec, type Scope } from '../types.ts';
import type { SteamTransport } from './transport.ts';
import { CookieJar } from './cookies.ts';
import { generateConfirmationKey } from './guard.ts';

const COMMUNITY = 'https://steamcommunity.com';
const MARKET = `${COMMUNITY}/market`;
type Obj = Record<string, Json>;
type Params = Record<string, string | number | boolean>;
type Session = { steam_id: string; access_token: string; session_id: string; jar: CookieJar };
const invalid = (): never => { throw new OpError(400, 'invalid_arguments'); };
const malformed = (): never => { throw new OpError(502, 'malformed_upstream_response'); };
function object(v: unknown): Obj { if (!v || typeof v !== 'object' || Array.isArray(v)) return malformed(); return v as Obj; }
function id(v: unknown): string { if (typeof v !== 'string' || !/^[1-9][0-9]{0,19}$/.test(v) || BigInt(v) > 18446744073709551615n) return invalid(); return v; }
function steamId(v: unknown): string { const s = id(v); if (BigInt(s) < 76561197960265729n || BigInt(s) > 76561202255233023n) return invalid(); return s; }
function integer(v: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): number { if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < min || v > max) return invalid(); return v; }
function text(v: unknown, max = 500): string { if (typeof v !== 'string' || !v.length || v.length > max || /[\x00-\x1f\x7f]/.test(v)) return invalid(); return v; }
function upstreamId(v: unknown): string { try { return id(v); } catch { return malformed(); } }
function flag(v: Json | undefined): boolean { if (v === undefined || v === false || v === 0) return false; if (v === true || v === 1) return true; return malformed(); }
function success(r: Obj): void { if (r.success !== true && r.success !== 1) throw new OpError(502, 'upstream_rejected'); }
function pending(r: Obj): boolean { return flag(r.needs_mobile_confirmation) || flag(r.needs_email_confirmation) || flag(r.need_confirmation); }
function result(r: Obj): Obj {
  const mobile = flag(r.needs_mobile_confirmation) || flag(r.need_confirmation);
  const email = flag(r.needs_email_confirmation);
  if (flag(r.need_confirmation) && r.confirmation !== undefined) upstreamId(object(r.confirmation).confirmation_id);
  return { ...r, pending_confirmation: mobile || email, needs_mobile_confirmation: mobile, needs_email_confirmation: email };
}

/** Reads only the documented session schema; never synthesizes authenticated cookies. */
export function readAuthenticatedSession(ctx: OpContext): Session {
  const s = ctx.state.session;
  if (!s || typeof s !== 'object' || Array.isArray(s)) throw new OpError(401, 'authentication_required');
  try {
    const steam_id = steamId(s.steam_id);
    const access_token = text(s.access_token, 8192);
    const session_id = text(s.session_id, 256);
    if (!Array.isArray(s.cookies)) throw new Error();
    // Validate persisted records before passing them to the shared jar. Invalid state is not auth.
    for (const c of s.cookies) {
      if (!c || typeof c !== 'object' || Array.isArray(c) || typeof c.name !== 'string' || typeof c.value !== 'string' ||
          typeof c.domain !== 'string' || typeof c.path !== 'string' || typeof c.hostOnly !== 'boolean' ||
          typeof c.secure !== 'boolean' || (c.expires !== null && (typeof c.expires !== 'number' || !Number.isFinite(c.expires)))) throw new Error();
    }
    const jar = new CookieJar(s.cookies);
    const cookie = jar.header(`${COMMUNITY}/`);
    const entries = new Map(cookie.split(/;\s*/).map(pair => { const at = pair.indexOf('='); return [pair.slice(0, at), pair.slice(at + 1)]; }));
    if (!entries.get('steamLoginSecure') || entries.get('sessionid') !== session_id || /[\r\n]/.test(cookie)) throw new Error();
    return { steam_id, access_token, session_id, jar };
  } catch { throw new OpError(401, 'authentication_required'); }
}

async function request(ctx: OpContext, s: Session, method: 'GET' | 'POST', path: string, params: Params | URLSearchParams = {}, referer = COMMUNITY, opts: { meta?: boolean; multipart?: boolean; pending406?: boolean } = {}): Promise<Obj> {
  const url = new URL(path);
  const data = params instanceof URLSearchParams ? params : new URLSearchParams(Object.entries(params).map(([k, v]) => [k, String(v)]));
  const headers: Record<string, string> = { Cookie: s.jar.header(url), Referer: referer, Accept: 'application/json' };
  let body: BodyInit | undefined;
  if (method === 'GET') url.search = data.toString();
  else if (opts.multipart) { const f = new FormData(); for (const [k, v] of data) f.append(k, v); body = f; }
  else { body = data.toString(); headers['Content-Type'] = 'application/x-www-form-urlencoded'; }
  const r = await (ctx.transport as SteamTransport).request(method, url, { headers, ...(body === undefined ? {} : { body }) });
  if (r.status === 429) throw new OpError(429, 'upstream_rate_limited');
  if (r.status === 401 || r.status === 403) throw new OpError(401, 'authentication_required');
  if (r.status < 200 || r.status >= 300) {
    if (!(opts.pending406 && r.status === 406)) throw new OpError(502, 'upstream_http_error');
  }
  if (r.url.hostname !== url.hostname || /\/(login|openid)(\/|$)/.test(r.url.pathname)) throw new OpError(401, 'authentication_required');
  const eresult = r.headers.get('x-eresult');
  if (eresult !== null && eresult !== '1') throw new OpError(502, 'upstream_rejected');
  // Upstream cancellation methods consume response metadata only. An empty body
  // is acknowledged by Steam's 2xx status, not invented JSON success. Non-empty
  // JSON must explicitly signal success; HTML/login pages are rejected.
  if (opts.meta && r.body.length === 0) return { upstream_status: r.status, pending_confirmation: false };
  let dataJson: unknown;
  try { dataJson = JSON.parse(new TextDecoder().decode(r.body)); } catch { return malformed(); }
  const out = object(dataJson);
  if (flag(out.needauth)) throw new OpError(401, 'authentication_required');
  if (out.error || out.strError) throw new OpError(502, 'upstream_rejected');
  if (r.status === 406 && !flag(out.need_confirmation)) return malformed();
  if (opts.meta) success(out);
  return out;
}

// Schemas and defensive validation are intentionally both present: direct calls to run
// remain safe even if a caller bypasses the core schema validator.
const ID: Record<string, Json> = { type: 'string', format: 'uint64', pattern: '^[1-9][0-9]{0,19}$', maxLength: 20 };
const STEAM_ID: Record<string, Json> = { ...ID, minLength: 17, maxLength: 17 };
const NUM = (minimum = 0, maximum = Number.MAX_SAFE_INTEGER): Record<string, Json> => ({ type: 'integer', minimum, maximum });
const STR: Record<string, Json> = { type: 'string', minLength: 1, maxLength: 500 };
const BOOL: Record<string, Json> = { type: 'boolean' };
const CURRENCY = NUM(1, 47);
const APP = NUM(1, 4294967295);
function validate(v: Json | undefined, schema: Record<string, Json>): void {
  switch (schema.type) {
    case 'string': {
      const s = v === '' && schema.minLength === 0 ? '' : text(v, typeof schema.maxLength === 'number' ? schema.maxLength : 500);
      if (typeof schema.minLength === 'number' && s.length < schema.minLength) invalid();
      if (typeof schema.pattern === 'string' && !new RegExp(schema.pattern).test(s)) invalid();
      if (schema.pattern === ID.pattern) id(s);
      break;
    }
    case 'integer': integer(v, schema.minimum as number, schema.maximum as number); break;
    case 'boolean': if (typeof v !== 'boolean') invalid(); break;
    case 'array': {
      if (!Array.isArray(v) || v.length < (schema.minItems as number ?? 0) || v.length > (schema.maxItems as number ?? 500)) return invalid();
      for (const entry of v) validate(entry, schema.items as Record<string, Json>);
      if (schema.uniqueItems && new Set(v.map(x => JSON.stringify(x))).size !== v.length) invalid();
      break;
    }
    case 'object': {
      if (!v || typeof v !== 'object' || Array.isArray(v)) return invalid();
      checkArgs(v, schema.properties as Record<string, Record<string, Json>>, schema.required as string[]); break;
    }
    default: invalid();
  }
}
function checkArgs(args: Obj, props: JsonSchema['properties'], required: string[]): void {
  for (const key of required) if (!(key in args)) invalid();
  for (const [key, value] of Object.entries(args)) { if (!(key in props)) invalid(); validate(value, props[key]!); }
}
function op(name: string, scope: Scope, properties: JsonSchema['properties'], required: string[], run: (ctx: OpContext, args: Obj, s: Session) => Promise<Json>, description: string): OperationSpec {
  return { name, scope, mutating: scope !== 'read', description, schema: { type: 'object', additionalProperties: false, properties, required }, async run(ctx, args) {
    const s = readAuthenticatedSession(ctx);
    if ((scope === 'admin' && ctx.scope !== 'admin') || (scope === 'write' && ctx.scope === 'read')) throw new OpError(403, 'insufficient_scope');
    checkArgs(args, properties, required);
    const transport = ctx.transport as SteamTransport;
    transport.cookieJar = s.jar;
    try { return await run(ctx, args, s); }
    finally { const session = ctx.state.session as Obj; session.cookies = s.jar.export(); }
  } };
}
function listingReferer(a: Obj): string { return `${MARKET}/listings/${integer(a.app, 1, 4294967295)}/${encodeURIComponent(text(a.market_hash_name))}`; }
function currency(a: Obj, ctx: OpContext): number {
  const c = integer(a.currency, 1, 47);
  // Monetary operations fail closed until a trusted wallet read has populated this state.
  const wallet = ctx.state.wallet;
  if (!wallet || typeof wallet !== 'object' || Array.isArray(wallet) || typeof wallet.currency !== 'number' || !Number.isSafeInteger(wallet.currency)) throw new OpError(409, 'wallet_currency_required');
  if (wallet.currency !== c) throw new OpError(400, 'wallet_currency_mismatch');
  return c;
}
const marketOps: OperationSpec[] = [
  op('wallet.info', 'read', {}, [], async (ctx, _a, s) => {
    // Exact source used by WalletComponent.get_info -> SteamState.sync_wallet_info.
    // Delete stale currency before attempting refresh so a failed read cannot preserve it.
    delete ctx.state.wallet;
    const url = `${COMMUNITY}/profiles/${s.steam_id}/inventory`;
    const r = await (ctx.transport as SteamTransport).request('GET', url, { headers: { Cookie: s.jar.header(url), Referer: `${COMMUNITY}/profiles/${s.steam_id}` } });
    if (r.status === 429) throw new OpError(429, 'upstream_rate_limited');
    if (r.status === 401 || r.status === 403 || /\/(login|openid)(\/|$)/.test(r.url.pathname)) throw new OpError(401, 'authentication_required');
    if (r.status !== 200 || r.url.hostname !== 'steamcommunity.com') throw new OpError(502, 'upstream_http_error');
    const matches = [...new TextDecoder().decode(r.body).matchAll(/\bg_rgWalletInfo\s*=\s*(\{[^\r\n]*\})\s*;/g)];
    if (matches.length !== 1) return malformed();
    let raw: unknown;
    try { raw = JSON.parse(matches[0]![1]!); } catch { return malformed(); }
    const wallet = object(raw); success(wallet);
    let c: number;
    try { c = integer(wallet.wallet_currency, 1, 47); } catch { return malformed(); }
    if (typeof wallet.wallet_country !== 'string' || !/^[A-Z]{2}$/.test(wallet.wallet_country)) return malformed();
    for (const field of ['wallet_fee', 'wallet_fee_minimum', 'wallet_market_minimum', 'wallet_currency_increment', 'wallet_fee_base', 'wallet_balance', 'wallet_delayed_balance', 'wallet_max_balance', 'wallet_trade_max_balance']) {
      const value = wallet[field];
      if (!(typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) && !(typeof value === 'string' && /^[0-9]+$/.test(value) && BigInt(value) <= BigInt(Number.MAX_SAFE_INTEGER))) return malformed();
    }
    for (const field of ['wallet_fee_percent', 'wallet_publisher_fee_percent_default']) {
      const value = wallet[field];
      if ((typeof value !== 'number' && (typeof value !== 'string' || !/^[0-9]+(?:\.[0-9]+)?$/.test(value))) || !Number.isFinite(Number(value)) || Number(value) < 0 || Number(value) > 1) return malformed();
    }
    if (typeof wallet.wallet_state !== 'string') return malformed();
    ctx.state.wallet = { ...wallet, currency: c, country: wallet.wallet_country };
    return ctx.state.wallet;
  }, 'Read wallet info from the authenticated inventory page and persist trusted wallet currency. Required before market monetary writes.'),
  op('inventory.get', 'read', { app: APP, context_id: ID, start_asset_id: ID, count: NUM(1, 2000), language: STR }, ['app', 'context_id'], async (ctx, a, s) => {
    const params: Params = { l: a.language === undefined ? 'english' : text(a.language), count: a.count === undefined ? 2000 : integer(a.count, 1, 2000), raw_asset_properties: 1, preserve_bbcode: 1 };
    if (a.start_asset_id !== undefined) params.start_assetid = id(a.start_asset_id);
    const r = await request(ctx, s, 'GET', `${COMMUNITY}/inventory/${s.steam_id}/${a.app}/${id(a.context_id)}`, params, `${COMMUNITY}/inventory/${s.steam_id}/`);
    success(r);
    if (typeof r.total_inventory_count !== 'number' || !Number.isSafeInteger(r.total_inventory_count) || r.total_inventory_count < 0) return malformed();
    if (r.assets !== undefined && !Array.isArray(r.assets)) return malformed();
    if (r.descriptions !== undefined && !Array.isArray(r.descriptions)) return malformed();
    if (r.total_inventory_count > 0 && (!Array.isArray(r.assets) || !Array.isArray(r.descriptions))) return malformed();
    if (r.last_assetid !== undefined) {
      const cursor = upstreamId(r.last_assetid);
      if (a.start_asset_id !== undefined && BigInt(cursor) <= BigInt(id(a.start_asset_id))) return malformed();
    }
    if (flag(r.more_items) && r.last_assetid === undefined) return malformed();
    for (const value of (r.assets ?? []) as Json[]) {
      const asset = object(value); upstreamId(asset.assetid); upstreamId(asset.contextid); upstreamId(asset.classid);
      if (typeof asset.amount !== 'string' || !/^[1-9][0-9]*$/.test(asset.amount)) return malformed();
    }
    return r;
  }, 'Get a page of the authenticated account inventory.'),
  op('market.get_user_listings', 'read', { start: NUM(), count: NUM(1, 100) }, [], async (ctx, a, s) => {
    const r = await request(ctx, s, 'GET', `${MARKET}/mylistings`, { norender: 1, start: (a.start ?? 0) as number, count: (a.count ?? 100) as number }); success(r);
    for (const field of ['listings', 'listings_to_confirm', 'buy_orders']) if (!Array.isArray(r[field])) return malformed();
    if (typeof r.num_active_listings !== 'number' || !Number.isSafeInteger(r.num_active_listings) || r.num_active_listings < 0) return malformed(); return r;
  }, 'Get active sell listings, pending listings and buy orders.'),
  op('market.place_sell_listing', 'write', { app: APP, context_id: ID, asset_id: ID, to_receive: NUM(1), currency: CURRENCY }, ['app', 'context_id', 'asset_id', 'to_receive', 'currency'], async (ctx, a, s) => {
    currency(a, ctx);
    const r = await request(ctx, s, 'POST', `${MARKET}/sellitem/`, { sessionid: s.session_id, appid: a.app as number, contextid: id(a.context_id), assetid: id(a.asset_id), amount: 1, price: integer(a.to_receive, 1) }, `${COMMUNITY}/profiles/${s.steam_id}/inventory`);
    success(r); return result(r);
  }, 'Sell one asset; to_receive is integer minor units in the explicitly supplied wallet currency. Steam sellitem does not accept a currency parameter. Never auto-confirm.'),
  op('market.cancel_sell_listing', 'write', { listing_id: ID }, ['listing_id'], (ctx, a, s) => request(ctx, s, 'POST', `${MARKET}/removelisting/${id(a.listing_id)}`, { sessionid: s.session_id }, MARKET, { meta: true }), 'Cancel a sell listing once.'),
  op('market.place_buy_order', 'write', { app: APP, market_hash_name: STR, price: NUM(1), quantity: NUM(1, 1000), currency: CURRENCY, confirmation_id: ID }, ['app', 'market_hash_name', 'price', 'currency'], async (ctx, a, s) => {
    const c = currency(a, ctx), quantity = integer(a.quantity ?? 1, 1, 1000), total = integer(integer(a.price, 1) * quantity, 1);
    const r = await request(ctx, s, 'POST', `${MARKET}/createbuyorder/`, { sessionid: s.session_id, currency: c, appid: a.app as number, market_hash_name: text(a.market_hash_name), price_total: total, quantity, confirmation: a.confirmation_id === undefined ? 0 : id(a.confirmation_id) }, listingReferer(a), { pending406: true });
    if (!pending(r)) { success(r); upstreamId(r.buy_orderid); } else if (!r.confirmation) return malformed();
    return result(r);
  }, 'Place a buy order once; price is the unit price in integer minor units. Returns pending confirmation without approval or retry.'),
  op('market.cancel_buy_order', 'write', { buy_order_id: ID }, ['buy_order_id'], (ctx, a, s) => request(ctx, s, 'POST', `${MARKET}/cancelbuyorder/`, { sessionid: s.session_id, buy_orderid: id(a.buy_order_id) }, MARKET, { meta: true }), 'Cancel a buy order once.'),
  op('market.buy_listing', 'write', { listing_id: ID, app: APP, market_hash_name: STR, subtotal: NUM(1), fee: NUM(), currency: CURRENCY, confirmation_id: ID }, ['listing_id', 'app', 'market_hash_name', 'subtotal', 'fee', 'currency'], async (ctx, a, s) => {
    const c = currency(a, ctx), subtotal = integer(a.subtotal, 1), fee = integer(a.fee), total = integer(subtotal + fee, 1);
    const r = await request(ctx, s, 'POST', `${MARKET}/buylisting/${id(a.listing_id)}`, { sessionid: s.session_id, currency: c, subtotal, fee, total, quantity: 1, confirmation: a.confirmation_id === undefined ? 0 : id(a.confirmation_id) }, listingReferer(a), { multipart: true, pending406: true });
    if (!pending(r)) success(object(r.wallet_info)); else if (!r.confirmation) return malformed();
    return result(r);
  }, 'Purchase once using explicit subtotal, fee and currency; all monetary values are integer minor units. No fee calculation or automatic confirmation/retry.'),
  op('market.get_buy_order_status', 'read', { buy_order_id: ID }, ['buy_order_id'], async (ctx, a, s) => {
    const r = await request(ctx, s, 'GET', `${MARKET}/getbuyorderstatus/`, { sessionid: s.session_id, buy_orderid: id(a.buy_order_id) }, MARKET, { pending406: true });
    if (!pending(r)) {
      success(r); if (r.active === undefined || r.purchased === undefined) return malformed(); flag(r.active); flag(r.purchased);
      for (const field of ['quantity', 'quantity_remaining']) if (typeof r[field] !== 'number' || !Number.isSafeInteger(r[field]) || (r[field] as number) < 0) return malformed();
    }
    return result(r);
  }, 'Read buy order status without confirming or repeating the order.'),
];

const ASSET: Record<string, Json> = { type: 'object', additionalProperties: false, properties: { appid: APP, contextid: ID, assetid: ID, amount: NUM(1, 4294967295) }, required: ['appid', 'contextid', 'assetid', 'amount'] };
const ASSETS: Record<string, Json> = { type: 'array', maxItems: 200, items: ASSET, uniqueItems: true };
function assets(v: Json | undefined): Obj[] {
  if (!Array.isArray(v) || v.length > 200) return invalid();
  const seen = new Set<string>();
  return v.map(x => {
    if (!x || typeof x !== 'object' || Array.isArray(x)) return invalid();
    checkArgs(x, ASSET.properties as JsonSchema['properties'], ASSET.required as string[]);
    const key = `${x.appid}:${id(x.contextid)}:${id(x.assetid)}`;
    if (seen.has(key)) return invalid(); seen.add(key);
    return { appid: integer(x.appid, 1, 4294967295), contextid: id(x.contextid), assetid: id(x.assetid), amount: String(integer(x.amount, 1, 4294967295)) };
  });
}
async function econ(ctx: OpContext, s: Session, method: 'GetTradeOffer' | 'GetTradeOffers', params: Params): Promise<Obj> {
  const r = await request(ctx, s, 'GET', `https://api.steampowered.com/IEconService/${method}/v1/`, { access_token: s.access_token, language: 'english', get_descriptions: 1, ...params });
  return object(r.response);
}
const tradeOps: OperationSpec[] = [
  op('trade.get', 'read', { trade_offer_id: ID }, ['trade_offer_id'], async (ctx, a, s) => {
    const r = await econ(ctx, s, 'GetTradeOffer', { tradeofferid: id(a.trade_offer_id) });
    const offer = object(r.offer); if (upstreamId(offer.tradeofferid) !== a.trade_offer_id) return malformed(); return r;
  }, 'Read a trade offer using authenticated IEconService.'),
  op('trade.get_multiple', 'read', { active_only: BOOL, historical_only: BOOL, historical_cutoff: NUM(), sent: BOOL, received: BOOL, cursor: NUM() }, [], async (ctx, a, s) => {
    const historical = a.historical_only === true, active = historical ? false : a.active_only !== false;
    if (a.historical_cutoff !== undefined && !active) invalid();
    if (a.sent === false && a.received === false) invalid();
    const params: Params = { active_only: Number(active), historical_only: Number(historical), get_sent_offers: Number(a.sent !== false), get_received_offers: Number(a.received !== false), cursor: (a.cursor ?? 0) as number };
    if (a.historical_cutoff !== undefined) params.time_historical_cutoff = a.historical_cutoff as number;
    const r = await econ(ctx, s, 'GetTradeOffers', params);
    // Steam omits empty repeated fields from protobuf-derived JSON.
    for (const field of ['trade_offers_sent', 'trade_offers_received', 'descriptions']) if (r[field] !== undefined && !Array.isArray(r[field])) return malformed();
    if (r.next_cursor !== undefined && (typeof r.next_cursor !== 'number' || !Number.isSafeInteger(r.next_cursor) || r.next_cursor < 0)) return malformed();
    for (const field of ['trade_offers_sent', 'trade_offers_received']) for (const offer of (r[field] ?? []) as Json[]) upstreamId(object(offer).tradeofferid);
    return r;
  }, 'Read a page of sent and received trade offers. Historical cutoff is only accepted with active_only.'),
  op('trade.send', 'write', { partner: STEAM_ID, to_partner: ASSETS, from_partner: ASSETS, message: { type: 'string', maxLength: 1000, minLength: 0 }, token: { type: 'string', minLength: 1, maxLength: 128, pattern: '^[A-Za-z0-9_-]+$' }, countered_id: ID }, ['partner', 'to_partner', 'from_partner'], async (ctx, a, s) => {
    const partner = steamId(a.partner); if (partner === s.steam_id) invalid();
    const give = assets(a.to_partner), receive = assets(a.from_partner); if (!give.length && !receive.length) invalid();
    let referer = `${COMMUNITY}/tradeoffer/new/?partner=${BigInt(partner) - 76561197960265728n}`;
    if (a.token !== undefined) referer += `&token=${encodeURIComponent(text(a.token, 128))}`;
    if (a.countered_id !== undefined) referer = `${COMMUNITY}/tradeoffer/${id(a.countered_id)}/`;
    const params: Params = {
      sessionid: s.session_id, serverid: 1, partner, tradeoffermessage: a.message === undefined ? '' : a.message as string,
      json_tradeoffer: JSON.stringify({ newversion: true, version: give.length + receive.length + 1, me: { assets: give, currency: [], ready: false }, them: { assets: receive, currency: [], ready: false } }),
      captcha: '', trade_offer_create_params: JSON.stringify(a.token === undefined ? {} : { trade_offer_access_token: a.token }),
    };
    if (a.countered_id !== undefined) params.tradeofferid_countered = id(a.countered_id);
    const r = await request(ctx, s, 'POST', `${COMMUNITY}/tradeoffer/new/send`, params, referer);
    if (r.tradeofferid !== undefined) upstreamId(r.tradeofferid); else if (!pending(r)) return malformed();
    return result(r);
  }, 'Send a trade offer once with explicitly validated assets and partner SteamID64. Returns pending flags; never confirms automatically.'),
  ...(['accept', 'decline', 'cancel'] as const).map(action => op(`trade.${action}`, 'write', { trade_offer_id: ID, ...(action === 'accept' ? { partner: STEAM_ID } : {}) }, action === 'accept' ? ['trade_offer_id', 'partner'] : ['trade_offer_id'], async (ctx, a, s) => {
    const offerId = id(a.trade_offer_id), params: Params = { sessionid: s.session_id };
    if (action === 'accept') Object.assign(params, { tradeofferid: offerId, serverid: 1, partner: steamId(a.partner), captcha: '' });
    const r = await request(ctx, s, 'POST', `${COMMUNITY}/tradeoffer/${offerId}/${action}`, params, `${COMMUNITY}/tradeoffer/${offerId}`);
    if (action !== 'accept') { if (upstreamId(r.tradeofferid) !== offerId) return malformed(); }
    else if (!pending(r) && r.tradeid === undefined && r.tradeofferid === undefined) return malformed();
    if (r.tradeid !== undefined) upstreamId(r.tradeid);
    return result(r);
  }, `${action} a trade offer once. Accept requires the sender's SteamID64; pending confirmations are never auto-approved.`)),
];

async function confirmationParams(ctx: OpContext, s: Session, tag: 'getlist' | 'allow' | 'cancel'): Promise<Params> {
  const guard = ctx.state.guard;
  if (!guard || typeof guard !== 'object' || Array.isArray(guard) || typeof guard.identity_secret !== 'string' ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(guard.identity_secret) ||
      guard.identity_secret.length < 16 || typeof guard.device_id !== 'string' || !/^android:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(guard.device_id)) throw new OpError(401, 'guard_required');
  const t = Math.floor(Date.now() / 1000);
  return { p: guard.device_id, a: s.steam_id, k: await generateConfirmationKey(guard.identity_secret, tag, t), t, m: 'react', tag };
}
async function confirmations(ctx: OpContext, s: Session): Promise<Obj[]> {
  const r = await request(ctx, s, 'GET', `${COMMUNITY}/mobileconf/getlist`, await confirmationParams(ctx, s, 'getlist')); success(r);
  if (!Array.isArray(r.conf)) return malformed();
  const seen = new Set<string>();
  return r.conf.map(v => {
    const c = object(v), cid = upstreamId(c.id); upstreamId(c.nonce);
    if (seen.has(cid)) return malformed(); seen.add(cid);
    if (typeof c.type !== 'number' || !Number.isInteger(c.type) || c.type < 0 || c.type > 13) throw new OpError(502, 'unknown_confirmation_type');
    return c;
  });
}
function permitted(c: Obj): void { if (![2, 3, 12, 13].includes(c.type as number)) throw new OpError(403, 'confirmation_type_denied'); }
async function confirmWrite(ctx: OpContext, a: Obj, s: Session, mode: 'accept' | 'deny' | 'multiple' | 'accept_all' | 'deny_all'): Promise<Json> {
  const bulk = mode !== 'accept' && mode !== 'deny';
  if (bulk && ctx.scope !== 'admin') throw new OpError(403, 'insufficient_scope');
  let ids: string[] | undefined;
  if (!bulk) ids = [id(a.confirmation_id)];
  else if (mode === 'multiple') {
    if (!Array.isArray(a.confirmation_ids) || !a.confirmation_ids.length || a.confirmation_ids.length > 200) return invalid();
    ids = a.confirmation_ids.map(id); if (new Set(ids).size !== ids.length) return invalid();
  }
  const all = await confirmations(ctx, s);
  const selected = ids === undefined ? all : ids.map(cid => { const c = all.find(x => x.id === cid); if (!c) throw new OpError(404, 'confirmation_not_found'); return c; });
  // Validate the entire batch before any mutation, including admin batches. Known
  // account-security confirmations are not silently skipped or approved by bulk-all.
  for (const c of selected) permitted(c);
  if (selected.length > 200) throw new OpError(400, 'confirmation_batch_too_large');
  if (!selected.length) return { success: true, processed_ids: [] };
  const allow = mode === 'accept' || mode === 'accept_all' || (mode === 'multiple' && a.accept === true), tag = allow ? 'allow' : 'cancel';
  const params = new URLSearchParams(Object.entries(await confirmationParams(ctx, s, tag)).map(([k, v]) => [k, String(v)])); params.set('op', tag);
  for (const c of selected) { params.append(bulk ? 'cid[]' : 'cid', c.id as string); params.append(bulk ? 'ck[]' : 'ck', c.nonce as string); }
  const r = await request(ctx, s, bulk ? 'POST' : 'GET', `${COMMUNITY}/mobileconf/${bulk ? 'multiajaxop' : 'ajaxop'}`, params); success(r);
  return { success: true, processed_ids: selected.map(c => c.id!) };
}
const confirmationOps: OperationSpec[] = [
  op('confirmations.get_all', 'read', {}, [], async (ctx, _a, s) => (await confirmations(ctx, s)).map(({ nonce: _nonce, ...publicConfirmation }) => publicConfirmation), 'Read standing confirmations; unknown types fail closed. No HTML details or implicit mutations.'),
  ...(['accept', 'deny'] as const).map(mode => op(`confirmations.${mode}`, 'write', { confirmation_id: ID }, ['confirmation_id'], (ctx, a, s) => confirmWrite(ctx, a, s, mode), `${mode} one confirmation after refetching its actual server type and nonce. Only types 2,3,12,13 are supported.`)),
  op('confirmations.send_multiple', 'admin', { confirmation_ids: { type: 'array', minItems: 1, maxItems: 200, uniqueItems: true, items: ID }, accept: BOOL }, ['confirmation_ids', 'accept'], (ctx, a, s) => confirmWrite(ctx, a, s, 'multiple'), 'Admin-only explicit batch of confirmations. Refetches actual type and nonce; entire batch must be types 2,3,12,13.'),
  ...(['accept_all', 'deny_all'] as const).map(mode => op(`confirmations.${mode}`, 'admin', {}, [], (ctx, a, s) => confirmWrite(ctx, a, s, mode), `Admin-only ${mode}; fail closed if any standing confirmation is not type 2,3,12,13.`)),
];

export const AUTHENTICATED_OPS: OperationSpec[] = [...marketOps, ...tradeOps, ...confirmationOps];
