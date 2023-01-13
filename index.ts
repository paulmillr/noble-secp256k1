/*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
const B256 = 2n ** 256n;
const P = B256 - 2n ** 32n - 977n;
const N = B256 - 0x14551231950b75fc4402da1732fc9bebfn;
const a = 0n;
const b = 7n;
const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
export const CURVE = { P, n: N, a, b, Gx, Gy };
const fLen = 32; // field/group byte length
const stdOpts: { lowS?: boolean; der?: boolean; extraEntropy?: any } = { lowS: true };
type Hex = Uint8Array | string;
const fe = (n: bigint) => typeof n === 'bigint' && 0n < n && n < P;
const ge = (n: bigint) => typeof n === 'bigint' && 0n < n && n < N;
const weierstrass = (x: bigint) => mod(mod(x * mod(x * x)) + a * x + b);
const err = (): never => {
  throw new TypeError();
};
const isBytes = (a: any, len?: number): Uint8Array => {
  if (!(a instanceof Uint8Array)) err();
  if (typeof len === 'number' && len > 0 && a.length !== len) err();
  return a;
};
const ensureBytes = (a: any, len?: number) => isBytes(typeof a === 'string' ? h2b(a) : a, len);
const normPriv = (privKey: Hex | bigint) => {
  if (typeof privKey !== 'bigint') privKey = b2n(ensureBytes(privKey, fLen));
  if (!ge(privKey)) err();
  return privKey;
};
const isProj = (p: any) => {
  if (!(p instanceof Proj)) err();
};
class Proj {
  static readonly G = new Proj(Gx, Gy, 1n);
  static readonly I = new Proj(0n, 1n, 0n);
  static frAff(p: Point) {
    if (!(p instanceof Point)) err();
    return new Proj(p.x, p.y, 1n);
  }
  constructor(readonly x: bigint, readonly y: bigint, readonly z: bigint) {}
  eql(other: Proj): boolean {
    isProj(other);
    const { x: X1, y: Y1, z: Z1 } = this;
    const { x: X2, y: Y2, z: Z2 } = other;
    return mod(X1 * Z2) === mod(X2 * Z1) && mod(Y1 * Z2) === mod(Y2 * Z1);
  }
  dbl() {
    return this.add(this);
  }
  add(other: Proj) {
    isProj(other);
    const { x: X1, y: Y1, z: Z1 } = this;
    const { x: X2, y: Y2, z: Z2 } = other;
    let X3 = 0n, Y3 = 0n, Z3 = 0n; // prettier-ignore
    const { a, b } = CURVE;
    const b3 = mod(b * 3n);
    let t0 = mod(X1 * X2); // step 1
    let t1 = mod(Y1 * Y2);
    let t2 = mod(Z1 * Z2);
    let t3 = mod(X1 + Y1);
    let t4 = mod(X2 + Y2); // step 5
    t3 = mod(t3 * t4);
    t4 = mod(t0 + t1);
    t3 = mod(t3 - t4);
    t4 = mod(X1 + Z1);
    let t5 = mod(X2 + Z2); // step 10
    t4 = mod(t4 * t5);
    t5 = mod(t0 + t2);
    t4 = mod(t4 - t5);
    t5 = mod(Y1 + Z1);
    X3 = mod(Y2 + Z2); // step 15
    t5 = mod(t5 * X3);
    X3 = mod(t1 + t2);
    t5 = mod(t5 - X3);
    Z3 = mod(a * t4);
    X3 = mod(b3 * t2); // step 20
    Z3 = mod(X3 + Z3);
    X3 = mod(t1 - Z3);
    Z3 = mod(t1 + Z3);
    Y3 = mod(X3 * Z3);
    t1 = mod(t0 + t0); // step 25
    t1 = mod(t1 + t0);
    t2 = mod(a * t2);
    t4 = mod(b3 * t4);
    t1 = mod(t1 + t2);
    t2 = mod(t0 - t2); // step 30
    t2 = mod(a * t2);
    t4 = mod(t4 + t2);
    t0 = mod(t1 * t4);
    Y3 = mod(Y3 + t0);
    t0 = mod(t5 * t4); // step 35
    X3 = mod(t3 * X3);
    X3 = mod(X3 - t0);
    t0 = mod(t3 * t1);
    Z3 = mod(t5 * Z3);
    Z3 = mod(Z3 + t0); // step 40
    return new Proj(X3, Y3, Z3);
  }
  mul(n: bigint) {
    if (!ge(n)) err();
    let p = Proj.I;
    for (let d: Proj = this; n > 0n; d = d.dbl(), n >>= 1n) {
      if (n & 1n) p = p.add(d);
    }
    return p;
  }
  aff() {
    const { x, y, z } = this;
    if (this.eql(Proj.I)) return Point.ZERO;
    const iz = inv(this.z);
    if (mod(z * iz) !== 1n) err();
    return new Point(mod(x * iz), mod(y * iz));
  }
}
export class Point {
  static BASE = new Point(Gx, Gy);
  static ZERO = new Point(0n, 0n);
  static fromPrivateKey(privKey: Hex | bigint) {
    return G.multiply(normPriv(privKey));
  }
  constructor(readonly x: bigint, readonly y: bigint) {}
  ok() {
    const { x, y } = this;
    if (!fe(x) || !fe(y)) err();
    if (mod(mod(y * y) - weierstrass(x)) !== 0n) err();
    return this;
  }
  equals(other: Point) {
    return this.x === other.x && this.y === other.y;
  }
  negate() {
    return new Point(this.x, mod(-this.y));
  }
  add(rhs: Point) {
    return Proj.frAff(this).add(Proj.frAff(rhs)).aff();
  }
  multiply(n: bigint) {
    return Proj.frAff(this).mul(n).aff();
  }
  static fromHex(hex: Hex) {
    hex = ensureBytes(hex);
    let p: Point | undefined = undefined;
    const head = hex[0];
    const tail = hex.subarray(1);
    const x = sliceNum(tail, 0, fLen);
    if (hex.length === 33 && [0x02, 0x03].includes(head)) {
      if (!fe(x)) err();
      let y = sqrt(weierstrass(x));
      const isYOdd = (y & 1n) === 1n;
      const isFirstByteOdd = (head & 1) === 1;
      if (isFirstByteOdd !== isYOdd) y = mod(-y);
      p = new Point(x, y);
    }
    if (hex.length === 65 && head === 0x04) p = new Point(x, sliceNum(tail, fLen, 2 * fLen));
    if (!p) err();
    return p!.ok();
  }
  toHex(isCompressed = false) {
    const { x, y } = this;
    const head = isCompressed ? ((y & 1n) === 0n ? '02' : '03') : '04';
    return `${head}${numToFieldStr(x)}${isCompressed ? '' : numToFieldStr(y)}`;
  }
  toRawBytes(isCompressed = false) {
    return h2b(this.toHex(isCompressed));
  }
}
const G = Point.BASE;

const mod = (a: bigint, b: bigint = P) => {
  const r = a % b;
  return r >= 0n ? r : b + r;
};
// Inverses number over modulo
const inv = (number: bigint, md = P): bigint => {
  if (number === 0n || md <= 0n) throw new Error(`n=${number} mod=${md}`);
  // prettier-ignore
  let a = mod(number, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
  while (a !== 0n) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    // prettier-ignore
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (gcd !== 1n) throw new Error('invert: does not exist');
  return mod(x, md);
};
const pow = (num: bigint, power: bigint, md: bigint): bigint => {
  if (md <= 0n || power < 0n) err();
  if (md === 1n) return 0n;
  let res = 1n;
  while (power > 0n) {
    if (power & 1n) res = (res * num) % md;
    num = (num * num) % md;
    power >>= 1n;
  }
  return res;
};
const sqrt = (num: bigint) => {
  return pow(num, (P + 1n) / 4n, P);
};

const b2h = (uint8a: Uint8Array): string => {
  isBytes(uint8a);
  let hex = '';
  for (let i = 0; i < uint8a.length; i++) hex += uint8a[i].toString(16).padStart(2, '0');
  return hex;
};
const h2n = (hex: string): bigint => {
  if (typeof hex !== 'string') err();
  return BigInt(`0x${hex}`);
};
const h2b = (hex: string): Uint8Array => {
  if (typeof hex !== 'string') err();
  if (hex.length % 2) err();
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    const hexByte = hex.slice(j, j + 2);
    const byte = Number.parseInt(hexByte, 16);
    if (Number.isNaN(byte) || byte < 0) err();
    array[i] = byte;
  }
  return array;
};
const b2n = (b: Uint8Array): bigint => h2n(b2h(b));
const sliceNum = (b: Uint8Array, from: number, to: number) => b2n(b.slice(from, to));
const numToField = (num: bigint): Uint8Array => {
  if (typeof num !== 'bigint') err();
  if (!(0n <= num && num < B256)) err();
  return h2b(num.toString(16).padStart(2 * fLen, '0'));
};
const numToFieldStr = (num: bigint): string => b2h(numToField(num));
const concatBytes = (...arrays: Uint8Array[]): Uint8Array => {
  arrays.every((b) => isBytes(b));
  if (arrays.length === 1) return arrays[0];
  const length = arrays.reduce((a, arr) => a + arr.length, 0);
  const result = new Uint8Array(length);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const arr = arrays[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
};

const bits2int_2 = (bytes: Uint8Array) => {
  const delta = bytes.length * 8 - 256;
  const num = b2n(bytes);
  return delta > 0 ? num >> BigInt(delta) : num;
};
const truncH = (hash: Uint8Array): bigint => {
  const h = bits2int_2(hash);
  return h >= N ? h - N : h;
};
const moreThanHalf = (n: bigint) => {
  const h = N >> 1n;
  return n > h;
};

export const getPublicKey = (privKey: Hex | bigint, isCompressed = false) => {
  return Point.fromPrivateKey(privKey).toRawBytes(isCompressed);
};
export class Signature {
  constructor(readonly r: bigint, readonly s: bigint, readonly recovery?: number) {
    this.ok();
  }
  ok(): Signature {
    if (!ge(this.r)) err();
    if (!ge(this.s)) err();
    return this;
  }
  static fromCompact(hex: Hex) {
    hex = ensureBytes(hex, 64);
    return new Signature(sliceNum(hex, 0, fLen), sliceNum(hex, fLen, 2 * fLen));
  }
  static fromKMD(kBytes: Uint8Array, m: bigint, d: bigint, lowS?: boolean): Signature | undefined {
    const k = bits2int_2(kBytes);
    if (!ge(k)) return;
    const kinv = inv(k, N);
    const q = G.multiply(k);
    const r = mod(q.x, N);
    if (r === 0n) return;
    const s = mod(kinv * mod(m + mod(d * r, N), N), N);
    if (s === 0n) return;
    let normS = s;
    let recovery = (q.x === r ? 0 : 2) | Number(q.y & 1n);
    if (lowS && moreThanHalf(s)) {
      normS = mod(-s, N);
      recovery ^= 1;
    }
    return new Signature(r, normS, recovery);
  }
  toCompactRawBytes() {
    return h2b(this.toCompactHex());
  }
  toCompactHex() {
    return numToFieldStr(this.r) + numToFieldStr(this.s);
  }
}

// RFC6979 methods
const b2i = (b: Uint8Array): bigint => {
  isBytes(b);
  const sl = b.length > fLen ? b.slice(0, fLen) : b;
  return b2n(sl);
};
const b2o = (bytes: Uint8Array): Uint8Array => {
  const z1 = b2i(bytes);
  const z2 = mod(z1, N);
  return i2o(z2 < 0n ? z1 : z2);
};
const i2o = (num: bigint): Uint8Array => numToField(num);

// Global symbol available in browsers only. Ensure we do not depend on @types/dom
declare const self: Record<string, any> | undefined;
const cr: { node?: any; web?: any } = {
  node: typeof require === 'function' && require('crypto'),
  web: typeof self === 'object' && 'crypto' in self ? self.crypto : undefined,
};
async function hmac(key: Uint8Array, ...messages: Uint8Array[]): Promise<Uint8Array> {
  const msgs = concatBytes(...messages);
  if (cr.web) {
    // prettier-ignore
    const ckey = await cr.web.subtle.importKey(
      'raw', key, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign']
    );
    return new Uint8Array(await cr.web.subtle.sign('HMAC', ckey, msgs));
  } else if (cr.node) {
    return Uint8Array.from(cr.node.createHmac('sha256', key).update(msgs).digest());
  } else {
    throw new Error('crypto required');
  }
}
function randomBytes(bytesLength: number): Uint8Array {
  if (cr.web) {
    return cr.web.getRandomValues(new Uint8Array(bytesLength));
  } else if (cr.node) {
    return Uint8Array.from(cr.node.randomBytes(bytesLength));
  } else {
    throw new Error('crypto required');
  }
}

// Minimal HMAC-DRBG (NIST 800-90) used only for RFC6979 signatures
class HmacDrbg {
  k: Uint8Array;
  v: Uint8Array;
  counter: number;
  constructor() {
    // Step B, Step C: set hashLen to 8*ceil(hlen/8)
    this.v = new Uint8Array(fLen).fill(1);
    this.k = new Uint8Array(fLen).fill(0);
    this.counter = 0;
  }
  async seed(seed = new Uint8Array()) {
    const hk = (...vs: Uint8Array[]) => hmac(this.k, ...vs);
    const hv = (...vs: Uint8Array[]) => hk(this.v, ...vs);
    this.k = await hv(Uint8Array.from([0x00]), seed);
    this.v = await hv();
    if (seed.length === 0) return;
    this.k = await hv(Uint8Array.from([0x01]), seed);
    this.v = await hv();
  }
  async gen(): Promise<Uint8Array> {
    if (this.counter >= 1000) err();
    this.counter += 1;
    this.v = await hmac(this.k, this.v);
    return this.v;
  }
}

export async function sign(msgHash: Hex, privKey: Hex, opts = stdOpts): Promise<Signature> {
  if (opts?.der === true) err();
  if (opts?.extraEntropy) err();
  if (opts?.lowS == null) opts.lowS = true;
  const _h1 = numToField(truncH(ensureBytes(msgHash))); // Steps A, D of RFC6979 3.2.
  const d = normPriv(privKey);
  if (!ge(d)) err();
  const seedArgs = [i2o(d), b2o(_h1)];
  const seed = concatBytes(...seedArgs);
  const m = b2i(_h1);
  const drbg = new HmacDrbg(); // Steps B, C, D, E, F, G of RFC6979 3.2.
  await drbg.seed(seed);
  let sig: Signature | undefined; // Step H3, repeat until k is in range [1, n-1]
  while (!(sig = Signature.fromKMD(await drbg.gen(), m, d, !!opts?.lowS))) await drbg.seed();
  return sig;
}

type Sig = Hex | Signature;
export function verify(sig: Sig, msgHash: Hex, pubKey: Hex, opts = stdOpts): boolean {
  if (opts?.lowS == null) opts.lowS = true;
  let sig_: Signature;
  try {
    sig_ = sig instanceof Signature ? sig.ok() : Signature.fromCompact(sig);
  } catch (error) {
    return false;
  }
  if (!sig_) return false;
  const { r, s } = sig_;
  if (opts?.lowS && moreThanHalf(s)) return false;
  const h = truncH(ensureBytes(msgHash, fLen));

  let P: Point;
  try {
    P = pubKey instanceof Point ? pubKey.ok() : Point.fromHex(pubKey);
  } catch (error) {
    return false;
  }
  let R: Point | undefined = undefined;
  try {
    const is = inv(s, N); // R = u1⋅G + u2⋅P
    const u1 = mod(h * is, N);
    const u2 = mod(r * is, N);
    R = G.multiply(u1).add(P.multiply(u2));
  } catch (error) {
    return false;
  }
  if (!R) return false;
  const v = mod(R.x, N);
  return v === r;
}
export const getSharedSecret = (privA: Hex, pubB: Hex, isCompressed?: boolean) => {
  return Point.fromHex(pubB).multiply(normPriv(privA)).toRawBytes(isCompressed);
};

export const utils = {
  mod,
  invert: inv,
  concatBytes,
  hexToBytes: h2b,
  bytesToHex: b2h,
  bytesToNumber: b2n,
  numToField,
  hashToPrivateKey: (hash: Hex): Uint8Array => {
    hash = ensureBytes(hash);
    const minLen = fLen + 8;
    if (hash.length < minLen || hash.length > 1024) err();
    const num = mod(b2n(hash), N - 1n) + 1n;
    return numToField(num);
  },
  randomBytes,
  // FIPS 186 B.4.1.
  randomPrivateKey: (): Uint8Array => utils.hashToPrivateKey(utils.randomBytes(fLen + 8)),
  isValidPrivateKey: (key: Hex) => {
    try {
      return !!normPriv(key);
    } catch (e) {
      return false;
    }
  },
};
