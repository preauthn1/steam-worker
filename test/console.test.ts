import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import vm from 'node:vm';
import { HTML, consoleHeaders } from '../src/console.ts';
const script = /<script>([\s\S]*?)<\/script>/.exec(HTML)![1]!;
const style = /<style>([\s\S]*?)<\/style>/.exec(HTML)![1]!;
function harness() {
  const elements = new Map<string, any>();
  function element(id: string) {
    if (!elements.has(id)) elements.set(id, {id,value:'',textContent:'',hidden:false,disabled:false,checked:false,open:false,dataset:{},children:[],listeners:new Map<string,Function>(),
      addEventListener(name:string,fn:Function){this.listeners.set(name,fn);},removeAttribute(){},setAttribute(){},append(...items:any[]){this.children.push(...items);},replaceChildren(...items:any[]){this.children=items;},querySelectorAll(){return [];},classList:{add(){}},showModal(){this.open=true;},close(){this.open=false;this.listeners.get('close')?.();},getContext(){return {clearRect(){},fillRect(){},fillStyle:''};}});
    return elements.get(id);
  }
  const calls:any[]=[];
  const context=vm.createContext({document:{getElementById:element,querySelectorAll:()=>[],createElement:()=>element('generated-'+elements.size)},window:{addEventListener(){}},crypto:{randomUUID:(()=>{let n=0;return()=>`intent-${++n}`;})()},fetch:async(path:string,options:any)=>{calls.push({path,options});return {ok:true,status:200,json:async()=>({result:{success:true}})};},URL,AbortController,DOMException,setTimeout,clearTimeout,Event});
  vm.runInContext(script,context);
  return {element, calls, run:(code:string)=>vm.runInContext(code,context)};
}
test('strict CSP matches the exact shipped inline assets',()=>{
  const csp=consoleHeaders()['Content-Security-Policy'];
  for(const [name,asset] of [['script',script],['style',style]]) assert.ok(csp.includes(`${name}-src 'sha256-${createHash('sha256').update(asset!).digest('base64')}'`));
  assert.ok(csp.includes("default-src 'none'"));assert.ok(csp.includes("connect-src 'self'"));assert.ok(csp.includes("frame-ancestors 'none'"));
  assert.doesNotMatch(csp,/unsafe-inline|unsafe-eval|https:|data:/);
  assert.equal(consoleHeaders()['Cache-Control'],'no-store');
});
test('no browser persistence, remote assets, or upstream HTML sinks',()=>{
  assert.doesNotMatch(script,/localStorage|sessionStorage|indexedDB|document\.cookie|innerHTML|outerHTML|insertAdjacentHTML|eval\(/);
  assert.doesNotMatch(HTML,/<(?:script|img|iframe)[^>]+src=|<link[^>]+href=/);
  assert.match(script,/let token = ''/); assert.match(script,/token=\$\('token'\)\.value\.trim\(\);\$\('token'\)\.value=''/);
  assert.match(script,/querySelectorAll\('input\[type=password\]'\)/);
});
test('responsive and keyboard/a11y anchors are present',()=>{
  assert.match(HTML,/name="viewport"/);assert.match(style,/@media\(max-width:700px\)/);assert.match(style,/prefers-reduced-motion/);
  for(const id of ['workspace','status','write-dialog','review-title','acknowledge','challenge-qr','stop-poll']) assert.ok(HTML.includes(`id="${id}"`));
  assert.match(HTML,/class="skip"/);assert.match(HTML,/aria-live="polite"/);assert.match(HTML,/aria-labelledby="review-title"/);assert.match(style,/:focus-visible/);
});
test('second review freezes summary, requires acknowledgement, and cancellation sends nothing',async()=>{
  const h=harness();h.run(`token='memory';reviewWrite({name:'trade.send',account:'fixture',method:'POST',path:'/v1/accounts/fixture/operations/trade.send',body:{arguments:{assets:[{id:'sample',amount:1}],recipient:'<img onerror=bad>',subtotal:100,fee:15,to_receive:85,currency:1}},mutating:true,key:'original'});`);
  assert.equal(h.element('write-dialog').open,true);assert.equal(h.element('confirm-write').disabled,true);
  assert.match(h.element('review-amount').textContent,/subtotal: 100/);assert.match(h.element('review-amount').textContent,/fee: 15/);assert.match(h.element('review-amount').textContent,/to_receive: 85/);
  assert.match(h.element('review-item').textContent,/sample/);assert.match(h.element('review-recipient').textContent,/<img onerror=bad>/);
  h.element('confirm-write').listeners.get('click')();assert.equal(h.calls.length,0);
  h.element('cancel-write').listeners.get('click')();assert.equal(h.calls.length,0);assert.equal(h.run('pendingWrite'),null);
});
test('authorized writes send headers; only explicit retry preserves the key',async()=>{
  const h=harness();h.run(`token='memory';reviewWrite({name:'account.create',account:'fixture',method:'PUT',path:'/v1/accounts/fixture',body:{},mutating:true,key:'original'});`);
  h.element('acknowledge').checked=true;h.element('acknowledge').listeners.get('change')();assert.equal(h.element('confirm-write').disabled,false);
  h.element('confirm-write').listeners.get('click')();await new Promise(resolve=>setImmediate(resolve));
  assert.equal(h.calls.length,1);assert.equal(h.calls[0].options.headers['X-Confirm-Write'],'true');assert.equal(h.calls[0].options.headers['Idempotency-Key'],'original');
  h.element('account').value='fixture';
  assert.notEqual(h.run(`manualIntent({name:'trade.send',mutating:true},{amount:1}).key`),h.run(`manualIntent({name:'trade.send',mutating:true},{amount:1}).key`));
  h.run(`retryWrite={name:'trade.send',account:'fixture',method:'POST',path:'/v1/accounts/fixture/operations/trade.send',body:{arguments:{}},mutating:true,key:'same'};`);
  h.element('retry').listeners.get('click')();assert.equal(h.run('pendingWrite.key'),'same');assert.equal(h.calls.length,1);
});
test('trade array arguments parse newline JSON and password clears before dispatch',()=>{
  const h=harness();h.run(`registry=[{name:'trade.send',schema:{required:['assets']}}];`);h.element('operation').value='trade.send';
  const assets={dataset:{argument:'assets',type:'array'},value:'[\n {"assetid":"fixture-item","amount":1}\n]'},password={dataset:{argument:'password',type:'string'},value:'fixture-secret'};
  h.element('fields').querySelectorAll=(selector:string)=>selector.includes('password')?[password]:[assets,password];
  const args=h.run('readArguments()');assert.equal(args.assets[0].amount,1);assert.equal(password.value,'');
  assets.value='not json';assert.throws(()=>h.run('readArguments()'),/valid JSON/);
  assert.match(script,/document\.createElement\('textarea'\)/);
});
test('secrets scrub recursively and challenge links reject unsafe destinations',()=>{
  const h=harness();const clean=h.run(`scrub({access_token:'fixture-secret',nested:{password:'secret',item:'<svg/onload=bad>'}})`);
  assert.equal(clean.access_token,'[hidden]');assert.equal(clean.nested.password,'[hidden]');assert.equal(clean.nested.item,'<svg/onload=bad>');
  for(const value of ['javascript:alert(1)','https://invalid.example/q/x','https://s.team.evil.example/q/x','https://user:pass@s.team/q/x']) assert.equal(h.run(`safeChallengeURL(${JSON.stringify(value)})`),null);
  assert.equal(h.run(`safeChallengeURL('https://s.team/q/fixture')`),'https://s.team/q/fixture');
});
test('local MIT QR produces deterministic modules with no service call',()=>{
  const h=harness();const size=h.run(`qrcodegen.QrCode.encodeText('https://s.team/q/fixture',qrcodegen.QrCode.Ecc.MEDIUM).size`);
  assert.ok(size>=21&&size<=177);assert.equal(h.run(`qrcodegen.QrCode.encodeText('https://s.team/q/fixture',qrcodegen.QrCode.Ecc.MEDIUM).getModule(0,0)`),true);
  h.run(`renderQR('https://s.team/q/fixture')`);assert.equal(h.element('challenge-qr').hidden,false);assert.equal(h.calls.length,0);
  assert.match(script,/Copyright \(c\) Project Nayuki/);assert.match(script,/Permission is hereby granted/);
});
test('polling is bounded, cancellable and explicitly authorized for session writes',()=>{
  assert.match(script,/attempt<20/);assert.match(script,/controller\.signal/);assert.match(script,/Math\.min\(30,Math\.max\(3/);
  assert.match(script,/intent\.polling=true;reviewWrite\(intent\)/);assert.match(script,/if\(intent\.polling\) void startPolling\(\)/);
  assert.match(script,/result\.next_poll_at/);assert.match(script,/manualIntent\(op,\{login_handle:loginHandle\}\)/);
  assert.match(script,/failed checks are never retried/);
});
