// Official mobile QR confirmation wire fields: IAuthenticationService auth protobufs.
// This module performs no automatic approval. Core must enforce confirmation/journaling
// for mutating operations and persist context state on success AND failure.
import { OpError, type Json, type OpContext, type OperationSpec } from '../types.ts';
import { Writer, decode, type Field } from './protobuf.ts';
import { callService } from './webapi.ts';
import type { SteamTransport } from './transport.ts';
import { validateArgs } from './schema.ts';

type Obj = Record<string, Json>;
const obj = (v: Json | undefined): Obj | undefined => v && typeof v === 'object' && !Array.isArray(v) ? v : undefined;
const now = () => Date.now() / 1000;
const TTL = 120;
const MAX64 = 0xffffffffffffffffn;
const bad = (): never => { throw new OpError(400, 'invalid_arguments'); };
const invalid = (): never => { throw new OpError(502, 'upstream_invalid_response'); };
function uint64(v: unknown): string {
  if (typeof v !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(v) || BigInt(v) > MAX64) return bad();
  return v;
}
function challenge(v: Json | undefined): { version: number; client_id: string } {
  // Match the original string, not URL-normalized input (ports, escapes, case, etc.).
  if (typeof v !== 'string') return bad();
  const m = /^https:\/\/s\.team\/q\/(0|[1-9][0-9]{0,4})\/(0|[1-9][0-9]{0,19})$/.exec(v);
  if (!m || Number(m[1]) > 65535 || v !== `https://s.team/q/${m[1]}/${m[2]}`) return bad();
  return { version: Number(m[1]), client_id: uint64(m[2]) };
}
function secret(v: Json | undefined): Uint8Array {
  try {
    if (typeof v !== 'string' || !v.length || v.length > 128 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(v)) throw new Error();
    const raw = atob(v);
    if (raw.length !== 20 || btoa(raw) !== v) throw new Error();
    return Uint8Array.from(raw, x => x.charCodeAt(0));
  } catch { throw new OpError(409, 'shared_secret_required'); }
}
function mobile(c: OpContext): { steam_id: string; access_token: string; key: Uint8Array; shared_secret: string } {
  const s = obj(c.state.session);
  if (!s || s.platform !== 'mobile') throw new OpError(409, 'mobile_session_required');
  try { uint64(s.steam_id); if (s.steam_id === '0') throw new Error(); }
  catch { throw new OpError(409, 'mobile_session_required'); }
  if (typeof s.access_token !== 'string' || !s.access_token || s.access_token.length > 16384) throw new OpError(409, 'mobile_session_required');
  if (typeof s.access_expires_at !== 'number' || !Number.isFinite(s.access_expires_at) || s.access_expires_at <= now()) throw new OpError(409, 'session_expired');
  // Tokens originate in encrypted session state, never operation arguments. Claims
  // are only a local consistency gate; Steam authenticates the token server-side.
  try {
    const parts = s.access_token.split('.');
    if (parts.length !== 3 || parts.some(x => !x.length) || !/^[A-Za-z0-9_-]+$/.test(parts[1]!)) throw new Error();
    const p = parts[1]!.replace(/-/g, '+').replace(/_/g, '/');
    const claims = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(p + '='.repeat((4 - p.length % 4) % 4)), x => x.charCodeAt(0))));
    if (claims.sub !== s.steam_id || typeof claims.exp !== 'number' || !Number.isFinite(claims.exp) || claims.exp <= now() || !Array.isArray(claims.aud) || !claims.aud.includes('mobile') || claims.aud.includes('derive')) throw new Error();
  } catch { throw new OpError(409, 'invalid_mobile_access_token'); }
  const g = obj(c.state.guard), key = secret(g?.shared_secret);
  return { steam_id: s.steam_id as string, access_token: s.access_token, key, shared_secret: g!.shared_secret as string };
}
const hex = (v: Uint8Array) => Array.from(v, b => b.toString(16).padStart(2, '0')).join('');
async function binding(s: ReturnType<typeof mobile>): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify([s.steam_id, s.access_token, s.shared_secret])))));
}
async function sign(keyBytes: Uint8Array, version: number, client: string, steam: string): Promise<Uint8Array> {
  const bytes = new ArrayBuffer(18), v = new DataView(bytes);
  v.setUint16(0, version, true); v.setBigUint64(2, BigInt(client), true); v.setBigUint64(10, BigInt(steam), true);
  const key = await crypto.subtle.importKey('raw', new Uint8Array(keyBytes), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, bytes));
}
function metadata(body: Uint8Array, expectedVersion: number): Obj {
  let m: Map<number, Field[]>; try { m = decode(body); } catch { return invalid(); }
  function field(n: number, wire: number): Field | undefined {
    const f = m.get(n); if (f && (f.length !== 1 || f[0]!.wire !== wire)) return invalid(); return f?.[0];
  }
  const str = (n: number): string => {
    const d = field(n, 2)?.data; if (!d) return '';
    if (d.length > 2048) return invalid();
    try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(d); } catch { return invalid(); }
  };
  const int = (n: number): number => { const v = field(n, 0)?.int ?? 0n; if (v > 0x7fffffffn) return invalid(); return Number(v); };
  const bool = (n: number): boolean => { const v = int(n); if (v !== 0 && v !== 1) return invalid(); return v === 1; };
  // Require the response version explicitly; never sign a caller's unverified version.
  if (!field(8, 0) || int(8) !== expectedVersion) return invalid();
  const persistence = int(12); if (persistence !== 0 && persistence !== 1) return invalid();
  return { ip: str(1), geoloc: str(2), city: str(3), state: str(4), country: str(5), platform_type: int(6),
    device_friendly_name: str(7), version: int(8), login_history: int(9), requestor_location_mismatch: bool(10),
    high_usage_login: bool(11), requested_persistence: persistence, device_trust: int(13), app_type: int(14) };
}
async function inspect(c: OpContext, args: Obj): Promise<Json> {
  const q = challenge(args.qr_url), s = mobile(c);
  // A new inspection replaces the sole review, even when upstream inspection fails.
  delete c.state.qr_review;
  const fingerprint = await binding(s);
  const body = await callService(c.transport as SteamTransport, 'IAuthenticationService', 'GetAuthSessionInfo',
    new Writer().uint(1, BigInt(q.client_id)).finish(), { accessToken: s.access_token });
  const meta = metadata(body, q.version);
  if (await binding(mobile(c)) !== fingerprint) throw new OpError(409, 'qr_review_session_changed');
  const reviewed = now(), handle = hex(crypto.getRandomValues(new Uint8Array(24)));
  c.state.qr_review = { review_handle: handle, steam_id: s.steam_id, credential_binding: fingerprint,
    client_id: q.client_id, version: q.version, inspected_at: reviewed, expires_at: reviewed + TTL, metadata: meta };
  return { status: 'review_required', review_handle: handle, expires_at: reviewed + TTL,
    requires_confirmation: true, device_friendly_name: meta.device_friendly_name!, ip: meta.ip!, country: meta.country!, city: meta.city!,
    platform_type: meta.platform_type!, device_trust: meta.device_trust!, version: meta.version!,
    geoloc: meta.geoloc!, state: meta.state!, app_type: meta.app_type!, login_history: meta.login_history!,
    requestor_location_mismatch: meta.requestor_location_mismatch!, high_usage_login: meta.high_usage_login!, requested_persistence: meta.requested_persistence! };
}
async function submit(c: OpContext, args: Obj, confirm: boolean): Promise<Json> {
  const s = mobile(c), r = obj(c.state.qr_review);
  if (!r || typeof r.review_handle !== 'string' || r.review_handle !== args.review_handle) throw new OpError(409, 'qr_review_handle_mismatch');
  if (typeof r.inspected_at !== 'number' || typeof r.expires_at !== 'number' || !Number.isFinite(r.inspected_at) || !Number.isFinite(r.expires_at) || r.inspected_at > now() || r.expires_at <= now() || r.expires_at > r.inspected_at + TTL) {
    delete c.state.qr_review; throw new OpError(409, 'qr_review_expired');
  }
  if (r.steam_id !== s.steam_id || r.credential_binding !== await binding(s)) {
    delete c.state.qr_review; throw new OpError(409, 'qr_review_session_changed');
  }
  // Consume before parsing/signing/submission. Core persists deletion even when
  // the network throws: a timeout is NOT permission to retry this review handle.
  if (c.state.qr_review !== r) throw new OpError(409, 'qr_review_handle_mismatch');
  delete c.state.qr_review;
  if (typeof r.version !== 'number' || !Number.isInteger(r.version) || typeof r.client_id !== 'string') return invalid();
  const q = challenge(`https://s.team/q/${r.version}/${r.client_id}`), meta = obj(r.metadata);
  if (!meta || (meta.requested_persistence !== 0 && meta.requested_persistence !== 1)) return invalid();
  const signature = await sign(s.key, q.version, q.client_id, s.steam_id);
  if (Number(r.expires_at) <= now()) throw new OpError(409, 'qr_review_expired');
  if (await binding(mobile(c)) !== r.credential_binding) throw new OpError(409, 'qr_review_session_changed');
  await callService(c.transport as SteamTransport, 'IAuthenticationService', 'UpdateAuthSessionWithMobileConfirmation',
    new Writer().uint(1, q.version).uint(2, BigInt(q.client_id)).fixed64(3, BigInt(s.steam_id)).bytes(4, signature)
      .bool(5, confirm).uint(6, Number(meta.requested_persistence)).finish(), { accessToken: s.access_token });
  return { status: confirm ? 'approved' : 'denied' };
}
function spec(name: string, mutating: boolean, properties: Record<string, Record<string, Json>>, run: OperationSpec['run']): OperationSpec {
  const op: OperationSpec = { name, scope: 'admin', mutating,
    description: mutating ? 'Submit one inspected mobile QR decision; explicit core confirmation required. Never retry an uncertain submission.' : 'Inspect official QR device/location/risk using the current mobile account; does not approve login.',
    schema: { type: 'object', additionalProperties: false, properties, required: Object.keys(properties) },
    run: async (c, a) => { if (c.scope !== 'admin') throw new OpError(403, 'scope_denied'); return run(c, validateArgs(op, a)); } };
  return op;
}
export const QR_APPROVAL_OPS: OperationSpec[] = [
  spec('session.qr_inspect', false, { qr_url: { type: 'string', minLength: 1, maxLength: 64 } }, inspect),
  spec('session.qr_approve', true, { review_handle: { type: 'string', pattern: '^[0-9a-f]{48}$' } }, (c, a) => submit(c, a, true)),
  spec('session.qr_deny', true, { review_handle: { type: 'string', pattern: '^[0-9a-f]{48}$' } }, (c, a) => submit(c, a, false)),
];
