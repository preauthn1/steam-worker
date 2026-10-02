import { OpError, type Json, type OpContext, type OperationDescription, type OperationSpec } from '../types.ts';
import { createTransport as makeTransport, SteamTransport } from './transport.ts';
import { Writer, decode, get } from './protobuf.ts';
import { callService } from './webapi.ts';

const text = new TextDecoder();
const schema = (properties: Record<string, Record<string, Json>>, required: string[] = []) => ({ type: 'object' as const, additionalProperties: false as const, properties, required });

async function serverTime(ctx: OpContext, args: Record<string, Json>): Promise<Json> {
  const sender = typeof args.sender_time === 'number' ? args.sender_time : undefined;
  const body = await callService(ctx.transport as SteamTransport, 'ITwoFactorService', 'QueryTime', new Writer().uint(1, sender).finish());
  const time = get.int(decode(body), 1);
  if (time === undefined) throw new OpError(502, 'upstream_invalid_response');
  return { server_time: time.toString() };
}
function parseMoney(v: unknown): number | null {
  if (typeof v !== 'string') return null;
  const n = Number(v.replace(/[^0-9,.-]/g, '').replace(',', '.'));
  return Number.isFinite(n) ? Math.round(n * 100) : null;
}
async function priceOverview(ctx: OpContext, args: Record<string, Json>): Promise<Json> {
  const name = args.obj;
  if (typeof name !== 'string' || name.length > 500) throw new OpError(400, 'invalid_arguments');
  const app = typeof args.app === 'number' ? args.app : 730;
  const currency = typeof args.currency === 'number' ? args.currency : 1;
  const url = new URL('https://steamcommunity.com/market/priceoverview/');
  url.search = new URLSearchParams({ country: 'US', currency: String(currency), appid: String(app), market_hash_name: name }).toString();
  const res = await (ctx.transport as SteamTransport).request('GET', url, { headers: typeof args.if_modified_since === 'string' ? { 'If-Modified-Since': args.if_modified_since } : undefined });
  if (res.status === 304) return { not_modified: true };
  if (res.status === 429) throw new OpError(429, 'upstream_rate_limited');
  if (res.status >= 400) throw new OpError(502, `upstream_http_${res.status}`);
  let data: Record<string, unknown>;
  try { data = JSON.parse(text.decode(res.body)) as Record<string, unknown>; } catch { throw new OpError(502, 'upstream_invalid_response'); }
  if (data.success !== true) throw new OpError(502, 'upstream_unsuccessful');
  return { lowest_price: typeof data.lowest_price === 'string' ? data.lowest_price : null, median_price: typeof data.median_price === 'string' ? data.median_price : null, lowest_price_minor: parseMoney(data.lowest_price), median_price_minor: parseMoney(data.median_price), volume: typeof data.volume === 'string' ? data.volume : null };
}
const OPS: OperationSpec[] = [
  { name: 'public.server_time', scope: 'read', mutating: false, description: 'Steam server time for Guard code alignment.', schema: schema({ sender_time: { type: 'integer' } }), run: serverTime },
  { name: 'public.market.get_price_overview', scope: 'read', mutating: false, description: 'Public market price overview. Monetary strings are preserved without lossy parsing.', schema: schema({ obj: { type: 'string', maxLength: 500 }, app: { type: 'integer', minimum: 1 }, currency: { type: 'integer', minimum: 1 }, if_modified_since: { type: 'string' } }, ['obj']), run: priceOverview },
];
export const OPERATIONS: ReadonlyMap<string, OperationSpec> = new Map(OPS.map(x => [x.name, x]));
const DESCRIPTIONS: readonly OperationDescription[] = Object.freeze(OPS.map(({ name, scope, mutating, description, schema: specSchema }) => Object.freeze({ name, scope, mutating, description, schema: specSchema })));
export function describeOperations(): readonly OperationDescription[] { return DESCRIPTIONS; }
export const OPERATIONS_JSON = JSON.stringify({ operations: DESCRIPTIONS });
export function validateArgs(spec: OperationSpec, args: unknown): Record<string, Json> {
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw new OpError(400, 'invalid_arguments');
  const record = args as Record<string, unknown>, ps = spec.schema.properties;
  for (const k of Object.keys(record)) if (!(k in ps)) throw new OpError(400, 'invalid_arguments');
  for (const k of spec.schema.required) if (!(k in record)) throw new OpError(400, 'invalid_arguments');
  for (const [k, v] of Object.entries(record)) {
    const p = ps[k]!, typ = p.type;
    const ok = (typ === 'string' && typeof v === 'string') || (typ === 'integer' && typeof v === 'number' && Number.isSafeInteger(v)) || (typ === 'boolean' && typeof v === 'boolean');
    if (!ok || (typeof p.maxLength === 'number' && typeof v === 'string' && v.length > p.maxLength) || (typeof p.minimum === 'number' && typeof v === 'number' && v < p.minimum)) throw new OpError(400, 'invalid_arguments');
  }
  return record as Record<string, Json>;
}
export function createTransport(): SteamTransport { return makeTransport(); }
