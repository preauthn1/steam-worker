// Steam WebAPI service calls: protobuf in `input_protobuf_encoded`, protobuf out, EResult header.
import { OpError } from '../types.ts';
import type { SteamTransport } from './transport.ts';

function b64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function mapEResult(code: number): OpError {
  if (code === 84) return new OpError(429, 'upstream_rate_limited');
  if (code === 5 || code === 15 || code === 21) return new OpError(403, `upstream_eresult_${code}`);
  return new OpError(502, `upstream_eresult_${code}`);
}

export async function callService(
  t: SteamTransport, iface: string, method: string, req: Uint8Array,
  opts: { http?: 'GET' | 'POST'; accessToken?: string } = {},
): Promise<Uint8Array> {
  const http = opts.http ?? 'POST';
  const url = new URL(`https://api.steampowered.com/${iface}/${method}/v1`);
  const params = new URLSearchParams({ input_protobuf_encoded: b64(req) });
  if (opts.accessToken) params.set('access_token', opts.accessToken);
  let res;
  if (http === 'GET') {
    url.search = params.toString();
    res = await t.request('GET', url);
  } else {
    res = await t.request('POST', url, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: params.toString(),
    });
  }
  const er = Number(res.headers.get('x-eresult') ?? '1');
  if (er !== 1) throw mapEResult(er);
  if (res.status === 429) throw new OpError(429, 'upstream_rate_limited');
  if (res.status >= 400) throw new OpError(502, `upstream_http_${res.status}`);
  return res.body;
}
