import { test } from 'node:test';
import assert from 'node:assert/strict';
import { body, bounded } from '../src/http.ts';
import { OpError } from '../src/types.ts';

test('malformed UTF-8 is a controlled invalid_json error', async () => {
  const request = new Request('https://example.com', { method: 'POST', body: new Uint8Array([0xff]) });
  await assert.rejects(body(request), (e: unknown) => e instanceof OpError && e.status === 400 && e.code === 'invalid_json');
});

test('bounded resolves normally and times out to an explicit error', async () => {
  assert.equal(await bounded(Promise.resolve('ok'), 30, 'account_unavailable'), 'ok');
  await assert.rejects(bounded(new Promise(() => {}), 5, 'account_unavailable'),
    (e: unknown) => e instanceof OpError && e.status === 503 && e.code === 'account_unavailable');
});
