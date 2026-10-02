import type { Json } from './types.ts';
const enc=new TextEncoder(), dec=new TextDecoder();
function b64(bytes:Uint8Array):string {let s='';for(const b of bytes)s+=String.fromCharCode(b);return btoa(s);}
function unb64(value:string):Uint8Array {try {const s=atob(value);return Uint8Array.from(s,c=>c.charCodeAt(0));}catch{throw new Error('invalid envelope');}}
export class Vault { private readonly raw:Uint8Array; private readonly aad:Uint8Array; private key?:Promise<CryptoKey>;
 constructor(hex:string, account:string){if(!/^[0-9a-fA-F]{64}$/.test(hex))throw new Error('AES-256 key required');this.raw=Uint8Array.from(hex.match(/../g)!,x=>parseInt(x,16));this.aad=enc.encode('steam-worker:v1:'+account);}
 private cryptoKey(){return this.key??=(crypto.subtle.importKey('raw',this.raw,{name:'AES-GCM'},false,['encrypt','decrypt']));}
 async seal(value:Json):Promise<string>{const nonce=crypto.getRandomValues(new Uint8Array(12));const encrypted=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:this.aad,tagLength:128},await this.cryptoKey(),enc.encode(JSON.stringify(value))));const all=new Uint8Array(nonce.length+encrypted.length);all.set(nonce);all.set(encrypted,12);return b64(all);}
 async open(value:string):Promise<Json>{const raw=unb64(value);if(raw.length<29)throw new Error('invalid envelope');const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:raw.slice(0,12),additionalData:this.aad,tagLength:128},await this.cryptoKey(),raw.slice(12));return JSON.parse(dec.decode(plain)) as Json;}
}
