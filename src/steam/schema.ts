import { OpError, type Json, type OperationSpec } from '../types.ts';
const own = (o: object,k:string) => Object.prototype.hasOwnProperty.call(o,k);
function fail():never {throw new OpError(400,'invalid_arguments');}

function check(p:Record<string,Json>,v:unknown,depth:number):void {
 if(depth>16)fail();
 if(Array.isArray(p.enum)&&!p.enum.some(x=>x===v))fail();
 const type=p.type;
 if(type==='string') {
  if(typeof v!=='string')fail();
  if(typeof p.minLength==='number'&&v.length<p.minLength)fail();
  if(typeof p.maxLength==='number'&&v.length>p.maxLength)fail();
  if(typeof p.pattern==='string'&&!new RegExp(p.pattern).test(v))fail();
  if(p.format==='uint64'&&(!/^(0|[1-9][0-9]{0,19})$/.test(v)||BigInt(v)>18446744073709551615n))fail();
 }else if(type==='integer'||type==='number') {
  if(typeof v!=='number'||!Number.isFinite(v)||(type==='integer'&&!Number.isSafeInteger(v)))fail();
  if(typeof p.minimum==='number'&&v<p.minimum)fail();
  if(typeof p.maximum==='number'&&v>p.maximum)fail();
 }else if(type==='boolean'){if(typeof v!=='boolean')fail();}
 else if(type==='array') {
  if(!Array.isArray(v))fail();
  if(typeof p.minItems==='number'&&v.length<p.minItems)fail();
  if(typeof p.maxItems==='number'&&v.length>p.maxItems)fail();
  if(p.items&&typeof p.items==='object'&&!Array.isArray(p.items))for(const item of v)check(p.items,item,depth+1);
 }else if(type==='object') {
  if(v===null||typeof v!=='object'||Array.isArray(v))fail();
  const record=v as Record<string,unknown>;
  const props=p.properties&&typeof p.properties==='object'&&!Array.isArray(p.properties)?p.properties:{};
  if(Array.isArray(p.required))for(const k of p.required)if(typeof k!=='string'||!own(record,k))fail();
  for(const [k,val] of Object.entries(record)){
   if(['__proto__','constructor','prototype'].includes(k))fail();
   if(!own(props,k)){if(p.additionalProperties===false)fail();continue;}
   const sub=props[k];if(!sub||typeof sub!=='object'||Array.isArray(sub))fail();
   check(sub,val,depth+1);
  }
 }else if(type==='null'){if(v!==null)fail();}
 else fail();
}
export function validateArgs(spec:OperationSpec,args:unknown):Record<string,Json>{
 check(spec.schema as unknown as Record<string,Json>,args,0);
 return args as Record<string,Json>;
}
