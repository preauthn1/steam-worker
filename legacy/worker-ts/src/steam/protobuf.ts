// Minimal hand-written protobuf codec: no reflection, no schema loading (keeps CPU low).
export class Writer {
  private buf: number[] = [];
  private varint(v: bigint): void {
    let n = BigInt.asUintN(64, v);
    while (n > 0x7fn) { this.buf.push(Number(n & 0x7fn) | 0x80); n >>= 7n; }
    this.buf.push(Number(n));
  }
  private tag(field: number, wire: number): void { this.varint(BigInt((field << 3) | wire)); }
  uint(field: number, v: number | bigint | undefined): this {
    if (v === undefined) return this;
    this.tag(field, 0); this.varint(BigInt(v)); return this;
  }
  bool(field: number, v: boolean | undefined): this { return v === undefined ? this : this.uint(field, v ? 1 : 0); }
  bytes(field: number, v: Uint8Array | undefined): this {
    if (v === undefined) return this;
    this.tag(field, 2); this.varint(BigInt(v.length)); for (const b of v) this.buf.push(b); return this;
  }
  string(field: number, v: string | undefined): this { return v === undefined ? this : this.bytes(field, new TextEncoder().encode(v)); }
  fixed64(field: number, v: bigint | undefined): this {
    if (v === undefined) return this;
    this.tag(field, 1);
    let n = BigInt.asUintN(64, v);
    for (let i = 0; i < 8; i++) { this.buf.push(Number(n & 0xffn)); n >>= 8n; }
    return this;
  }
  finish(): Uint8Array { return Uint8Array.from(this.buf); }
}

export type Field = { wire: number; int?: bigint; data?: Uint8Array };

/** Decode one message level into field number -> occurrences. */
export function decode(bytes: Uint8Array): Map<number, Field[]> {
  const out = new Map<number, Field[]>();
  let i = 0;
  const varint = (): bigint => {
    let shift = 0n, result = 0n;
    for (;;) {
      if (i >= bytes.length) throw new Error('truncated');
      const b = bytes[i++]!;
      result |= BigInt(b & 0x7f) << shift;
      if (!(b & 0x80)) return result;
      shift += 7n;
      if (shift > 63n) throw new Error('varint overflow');
    }
  };
  while (i < bytes.length) {
    const key = Number(varint());
    const field = key >>> 3, wire = key & 7;
    let f: Field;
    if (wire === 0) f = { wire, int: varint() };
    else if (wire === 1 || wire === 5) {
      const n = wire === 1 ? 8 : 4;
      if (i + n > bytes.length) throw new Error('truncated');
      let v = 0n;
      for (let k = n - 1; k >= 0; k--) v = (v << 8n) | BigInt(bytes[i + k]!);
      i += n; f = { wire, int: v };
    } else if (wire === 2) {
      const len = Number(varint());
      if (i + len > bytes.length) throw new Error('truncated');
      f = { wire, data: bytes.subarray(i, i + len) }; i += len;
    } else throw new Error('unsupported wire type');
    const list = out.get(field);
    if (list) list.push(f); else out.set(field, [f]);
  }
  return out;
}

const dec = new TextDecoder();
export const get = {
  int: (m: Map<number, Field[]>, f: number): bigint | undefined => m.get(f)?.[0]?.int,
  str: (m: Map<number, Field[]>, f: number): string | undefined => {
    const d = m.get(f)?.[0]?.data; return d ? dec.decode(d) : undefined;
  },
  bytes: (m: Map<number, Field[]>, f: number): Uint8Array | undefined => m.get(f)?.[0]?.data,
  all: (m: Map<number, Field[]>, f: number): Field[] => m.get(f) ?? [],
};
