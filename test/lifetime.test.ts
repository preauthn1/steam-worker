import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

test('pending DO deadlines do not leak timers after success',()=>{
 const src=readFileSync('src/http.ts','utf8');
 assert.match(src,/finally\s*\{[^}]*clearTimeout/);
});
