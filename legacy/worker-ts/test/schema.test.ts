import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateArgs } from '../src/steam/registry.ts';
import { OpError, type OperationSpec } from '../src/types.ts';
const spec:OperationSpec={name:'synthetic',scope:'write',mutating:true,description:'Synthetic',schema:{type:'object',additionalProperties:false,required:['id'],properties:{id:{type:'string',format:'uint64'},amount:{type:'integer',minimum:1,maximum:100},mode:{type:'string',enum:['web','mobile']},assets:{type:'array',maxItems:2,items:{type:'object',additionalProperties:false,required:['assetid'],properties:{assetid:{type:'string',format:'uint64'}}}}}},async run(){return null;}};
const invalid=(v:unknown)=>assert.throws(()=>validateArgs(spec,v),(e:unknown)=>e instanceof OpError&&e.code==='invalid_arguments');
test('uint64 identifiers require canonical bounded decimal strings',()=>{
 assert.deepEqual(validateArgs(spec,{id:'18446744073709551615'}),{id:'18446744073709551615'});
 for(const id of ['01','-1','18446744073709551616','1e2',123])invalid({id});
});
test('schema enforces enum, numeric maximum and nested assets',()=>{
 assert.deepEqual(validateArgs(spec,{id:'1',assets:[{assetid:'2'}]}),{id:'1',assets:[{assetid:'2'}]});
 for(const v of [{id:'1',mode:'bad'},{id:'1',amount:101},{id:'1',assets:[{assetid:'02'}]},{id:'1',assets:[{assetid:'2',unknown:true}]},{id:'1',assets:[{assetid:'2'},{assetid:'3'},{assetid:'4'}]}])invalid(v);
});
test('inherited property names are not schema declarations',()=>{
 invalid(JSON.parse('{"id":"1","toString":"x"}'));
 invalid(JSON.parse('{"id":"1","__proto__":{}}'));
});
