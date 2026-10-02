import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HTML } from '../src/console.ts';
test('console uses Simplified Chinese document language and workflows',()=>{
 assert.ok(HTML.includes('<html lang="zh-CN">'),'document language must be zh-CN');
 for(const phrase of ['库存','交易','确认','连接','账户'])assert.ok(HTML.includes(phrase),phrase);
 assert.doesNotMatch(HTML,/>Sign in<|>Inventory<|>Trades<|>Review this write<|>Connect</);
});
