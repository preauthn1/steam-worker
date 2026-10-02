import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AccountStore } from '../src/account.ts';
import { Vault } from '../src/vault.ts';
class Mem {m=new Map<string,unknown>();async get<T>(k:string){return this.m.get(k) as T|undefined;}async put(x:Record<string,unknown>){for(const [k,v]of Object.entries(x))this.m.set(k,v);}}
test('replayed create and delete reflect current existence',async()=>{
 const store=new AccountStore(new Mem(),new Vault('33'.repeat(32),'synthetic'),()=>180);
 await store.manage('create',{},'admin','create-key-0000001');
 await store.manage('delete',{},'admin','delete-key-0000001');
 assert.deepEqual(await store.manage('create',{},'admin','create-key-0000001'),{exists:false,version:2});
 await store.manage('create',{},'admin','create-key-0000002');
 assert.deepEqual(await store.manage('delete',{},'admin','delete-key-0000001'),{exists:true,version:3});
});
test('write operation state is recovered after upstream failure and replay cannot rerun it',async()=>{
 const mem=new Mem(); const vault=new Vault('44'.repeat(32),'synthetic');const store=new AccountStore(mem,vault,()=>180);
 await store.manage('create',{},'admin','create-key-0000001');let runs=0;
 await assert.rejects(store.execute('session.poll',{},'admin','poll-key-00000001',true,async state=>{runs++;state.pending_login={login_handle:'synthetic',client_id:'2'};throw Error('synthetic');},()=>1));
 const saved=await vault.open(mem.m.get('account-v1') as string) as {state:unknown};
 assert.deepEqual(saved.state,{pending_login:{login_handle:'synthetic',client_id:'2'}});
 await assert.rejects(store.execute('session.poll',{},'admin','poll-key-00000001',true,async()=>{runs++;return null;},()=>0));
 assert.equal(runs,1);
});
