/*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
/**
 * 4KB JS implementation of secp256k1 signatures & ECDH. Compliant with RFC6979.
 * @module
 */
const B256 = 2n ** 256n;
const P = B256 - 0x1000003d1n;                          // curve's field prime
const N = B256 - 0x14551231950b75fc4402da1732fc9bebfn;  // curve (group) order
const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n; // base point x
const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n; // base point y
/**
 * secp256k1 curve parameters. Equation is x³ + ax + b.
 * Gx and Gy are generator coordinates. p is field order, n is group order.
 */
const CURVE: { p: bigint; n: bigint; a: bigint; b: bigint; Gx: bigint; Gy: bigint } = {
  p: P, n: N, a: 0n, b: 7n, Gx, Gy };                   // exported variables incl. a, b
const fLen = 32;                                        // field / group byte length
/** Alias to Uint8Array. */
export type Bytes = Uint8Array;
/** Hex-encoded string or Uint8Array. */
export type Hex = Bytes | string;
/** Hex-encoded string, Uint8Array or bigint. */
export type PrivKey = Hex | bigint;
/** Signature instance. Has properties r and s. */
export type SigLike = { r: bigint, s: bigint };
/** Signature instance, which allows recovering pubkey from it. */
export type SignatureWithRecovery = Signature & { recovery: number }
const curve = (x: bigint) => M(M(x * x) * x + CURVE.b); // x³ + ax + b weierstrass formula; a=0
const err = (m = ''): never => { throw new Error(m); }; // error helper, messes-up stack trace
const isB = (n: unknown): n is bigint => typeof n === 'bigint'; // is big integer
const isS = (s: unknown): s is string => typeof s === 'string'; // is string
const arange = (n: bigint, min: bigint, max: bigint, msg = 'bad number: out of range') =>
  isB(n) && min <= n && n < max ? n : err(msg);
const afield0 = (n: bigint) => arange(n, 0n, P);        // assert field element or 0
const afield = (n: bigint) => arange(n, 1n, P);         // assert field element
const agroup = (n: bigint) => arange(n, 1n, N);         // assert group elem
const isu8 = (a: unknown): a is Uint8Array => (
  a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array')
);
const au8 = (a: unknown, l?: number): Bytes =>          // assert is Uint8Array (of specific length)
  !isu8(a) || (typeof l === 'number' && l > 0 && a.length !== l) ?
    err('Uint8Array expected') : a;
const u8n = (len: number) => new Uint8Array(len);       // creates Uint8Array
const u8fr = (buf: ArrayLike<number>) => Uint8Array.from(buf);
const toU8 = (a: Hex, len?: number) => au8(isS(a) ? h2b(a) : u8fr(au8(a)), len); // norm(hex/u8a) to u8a
const M = (a: bigint, b: bigint = P) => {               // mod division
  const r = a % b; return r >= 0n ? r : b + r;
};
const apoint = (p: unknown) => (p instanceof Point ? p : err('Point expected')); // is 3d point
/** Point in 2d xy affine coordinates. */
export interface AffinePoint { x: bigint, y: bigint }
/** Point in 3d xyz projective coordinates. 3d takes less inversions than 2d. */
class Point {
  readonly px: bigint;
  readonly py: bigint;
  readonly pz: bigint;
  constructor(px: bigint, py: bigint, pz: bigint) {
    this.px = afield0(px);
    this.py = afield(py);                              // y can't be 0 in Projective
    this.pz = afield0(pz);
    Object.freeze(this);
  }
  /** Generator / base point */
  static readonly BASE: Point = new Point(Gx, Gy, 1n);
  /** Identity / zero point */
  static readonly ZERO: Point = new Point(0n, 1n, 0n);
  /** Create 3d xyz point from 2d xy. (0, 0) => (0, 1, 0), not (0, 0, 1) */
  static fromAffine(p: AffinePoint): Point {
    return ((p.x === 0n) && (p.y === 0n)) ? I : new Point(p.x, p.y, 1n);
  }
  /** Convert Uint8Array or hex string to Point. */
  static fromHex(hex: Hex): Point {
    hex = toU8(hex);                                    // convert hex string to Uint8Array
    let p: Point | undefined = undefined;
    const head = hex[0], tail = hex.subarray(1);        // first byte is prefix, rest is data
    const x = slc(tail, 0, fLen), len = hex.length;     // next 32 bytes are x coordinate
    if (len === 33 && [0x02, 0x03].includes(head)) {    // compressed points: 33b, start
      afield(x);                                        // with byte 0x02 or 0x03. check 1<=x<P.
      let y = sqrt(curve(x));                           // x³ + ax + b is right side of equation
      const isYOdd = (y & 1n) === 1n;                   // y² is equivalent left-side. Calculate y²:
      const headOdd = (head & 1) === 1;                 // y = √y²; there are two solutions: y, -y
      if (headOdd !== isYOdd) y = M(-y);                // determine proper solution
      p = new Point(x, y, 1n);                          // create point
    }                                                   // Uncompressed points: 65b, start with 0x04
    if (len === 65 && head === 0x04) p = new Point(x, slc(tail, fLen, 2 * fLen), 1n);
    return p ? p.ok() : err('Point invalid: not on curve');   // Verify the result
  }
  /** Create point from a private key. */
  static fromPrivateKey(k: PrivKey): Point { return G.mul(toPriv(k)); }
  get x(): bigint { return this.aff().x; }              // .x, .y will call expensive toAffine:
  get y(): bigint { return this.aff().y; }              // should be used with care.
  /** Equality check: compare points P&Q. */
  equals(other: Point): boolean {
    const { px: X1, py: Y1, pz: Z1 } = this;
    const { px: X2, py: Y2, pz: Z2 } = apoint(other);   // isPoint() checks class equality
    const X1Z2 = M(X1 * Z2), X2Z1 = M(X2 * Z1);
    const Y1Z2 = M(Y1 * Z2), Y2Z1 = M(Y2 * Z1);
    return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
  }
  /** Flip point over y coordinate. */
  negate(): Point { return new Point(this.px, M(-this.py), this.pz); }
  /** Point doubling: P+P, complete formula. */
  double(): Point { return this.add(this); }
  /**
   * Point addition: P+Q, complete, exception-free formula
   * (Renes-Costello-Batina, algo 1 of [2015/1060](https://eprint.iacr.org/2015/1060)).
   * Cost: 12M + 0S + 3*a + 3*b3 + 23add.
   */
  add(other: Point): Point {
    const { px: X1, py: Y1, pz: Z1 } = this;
    const { px: X2, py: Y2, pz: Z2 } = apoint(other);
    const { a, b } = CURVE;
    let X3 = 0n, Y3 = 0n, Z3 = 0n;
    const b3 = M(b * 3n);
    let t0 = M(X1 * X2), t1 = M(Y1 * Y2), t2 = M(Z1 * Z2), t3 = M(X1 + Y1); // step 1
    let t4 = M(X2 + Y2);                                // step 5
    t3 = M(t3 * t4); t4 = M(t0 + t1); t3 = M(t3 - t4); t4 = M(X1 + Z1);
    let t5 = M(X2 + Z2);                                // step 10
    t4 = M(t4 * t5); t5 = M(t0 + t2); t4 = M(t4 - t5); t5 = M(Y1 + Z1);
    X3 = M(Y2 + Z2);                                    // step 15
    t5 = M(t5 * X3); X3 = M(t1 + t2); t5 = M(t5 - X3); Z3 = M(a * t4);
    X3 = M(b3 * t2);                                    // step 20
    Z3 = M(X3 + Z3); X3 = M(t1 - Z3); Z3 = M(t1 + Z3); Y3 = M(X3 * Z3);
    t1 = M(t0 + t0);                                    // step 25
    t1 = M(t1 + t0); t2 = M(a * t2); t4 = M(b3 * t4); t1 = M(t1 + t2);
    t2 = M(t0 - t2);                                    // step 30
    t2 = M(a * t2); t4 = M(t4 + t2); t0 = M(t1 * t4); Y3 = M(Y3 + t0);
    t0 = M(t5 * t4);                                    // step 35
    X3 = M(t3 * X3); X3 = M(X3 - t0); t0 = M(t3 * t1); Z3 = M(t5 * Z3);
    Z3 = M(Z3 + t0);                                    // step 40
    return new Point(X3, Y3, Z3);
  }
  mul(n: bigint, safe = true): Point {                  // Point-by-scalar multiplication.
    if (!safe && n === 0n) return I;                    // in unsafe mode, allow zero
    agroup(n);                                          // must be 1 <= n < CURVE.n
    if (this.equals(G)) return wNAF(n).p;               // use precomputes for base point
    let p = I, f = G;                                   // init result point & fake point
    for (let d: Point = this; n > 0n; d = d.double(), n >>= 1n) { // double-and-add ladder
      if (n & 1n) p = p.add(d);                         // if bit is present, add to point
      else if (safe) f = f.add(d);                      // if not, add to fake for timing safety
    }
    return p;
  }
  mulAddQUns(R: Point, u1: bigint, u2: bigint): Point { // Double scalar mult. Q = u1⋅G + u2⋅R.
    return this.mul(u1, false).add(R.mul(u2, false)).ok(); // Unsafe: do NOT use for stuff related
  }                                                     // to private keys. Doesn't use Shamir trick
  /** Convert point to 2d xy affine point. (x, y, z) ∋ (x=x/z, y=y/z) */
  toAffine(): AffinePoint {
    const { px: x, py: y, pz: z } = this;
    if (this.equals(I)) return { x: 0n, y: 0n };        // fast-path for zero point
    if (z === 1n) return { x, y };                      // if z is 1, pass affine coordinates as-is
    const iz = inv(z, P);                               // z^-1: invert z
    if (M(z * iz) !== 1n) err('inverse invalid');       // (z * z^-1) must be 1, otherwise bad math
    return { x: M(x * iz), y: M(y * iz) };              // x = x*z^-1; y = y*z^-1
  }
  /** Checks if the point is valid and on-curve. */
  assertValidity(): Point {
    const { x, y } = this.aff();                        // convert to 2d xy affine point.
    afield(x); afield(y);                               // must be in range 1 <= x,y < P
    return M(y * y) === curve(x) ?                      // y² = x³ + ax + b, must be equal
      this : err('Point invalid: not on curve');
  }
  multiply(n: bigint): Point { return this.mul(n); }    // Aliases to compress code
  aff(): AffinePoint { return this.toAffine(); }
  ok(): Point { return this.assertValidity(); }
  toHex(isCompressed = true): string {                  // Encode point to hex string.
    const { x, y } = this.aff();                        // convert to 2d xy affine point
    this.assertValidity();
    const head = isCompressed ? ((y & 1n) === 0n ? '02' : '03') : '04'; // 0x02, 0x03, 0x04 prefix
    return head + n2h(x) + (isCompressed ? '' : n2h(y));// prefix||x and ||y
  }
  toRawBytes(isCompressed = true): Bytes {              // Encode point to Uint8Array.
    return h2b(this.toHex(isCompressed));               // re-use toHex(), convert hex to bytes
  }
}
const { BASE: G, ZERO: I } = Point;                     // Generator, identity points
const padh = (n: number | bigint, pad: number) => n.toString(16).padStart(pad, '0');
const b2h = (b: Bytes): string => Array.from(au8(b)).map(e => padh(e, 2)).join(''); // bytes to hex
const C = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 } as const; // ASCII characters
const _ch = (ch: number): number | undefined => {
  if (ch >= C._0 && ch <= C._9) return ch - C._0;       // '2' => 50-48
  if (ch >= C.A && ch <= C.F) return ch - (C.A - 10);   // 'B' => 66-(65-10)
  if (ch >= C.a && ch <= C.f) return ch - (C.a - 10);   // 'b' => 98-(97-10)
  return;
};
const h2b = (hex: string): Bytes => {                   // hex to bytes
  const e = 'hex invalid';
  if (!isS(hex)) return err(e);
  const hl = hex.length, al = hl / 2;
  if (hl % 2) return err(e);
  const array = u8n(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {    // treat each char as ASCII
    const n1 = _ch(hex.charCodeAt(hi));                 // parse first char, multiply it by 16
    const n2 = _ch(hex.charCodeAt(hi + 1));             // parse second char
    if (n1 === undefined || n2 === undefined) return err(e);
    array[ai] = n1 * 16 + n2;                           // example: 'A9' => 10*16 + 9
  }
  return array;
};
const b2n = (b: Bytes): bigint => BigInt('0x' + (b2h(b) || '0')); // bytes to number
const slc = (b: Bytes, from: number, to: number) => b2n(b.slice(from, to)); // slice bytes num
const n2b = (num: bigint): Bytes => {                   // number to 32b. Must be 0 <= num < B256
  return isB(num) && num >= 0n && num < B256 ? h2b(padh(num, 2 * fLen)) : err('bigint expected');
};
const n2h = (num: bigint): string => b2h(n2b(num));     // number to 32b hex
const concatB = (...arrs: Bytes[]): Bytes => {          // concatenate Uint8Array-s
  const r = u8n(arrs.reduce((sum, a) => sum + au8(a).length, 0)); // create u8a of summed length
  let pad = 0;                                          // walk through each array,
  arrs.forEach(a => {r.set(a, pad); pad += a.length});  // ensure they have proper type
  return r;
};
const inv = (num: bigint, md: bigint): bigint => {      // modular inversion
  if (num === 0n || md <= 0n) err('no inverse n=' + num + ' mod=' + md); // no neg exponent for now
  let a = M(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
  while (a !== 0n) {                                    // uses euclidean gcd algorithm
    const q = b / a, r = b % a;                         // not constant-time
    const m = x - u * q, n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  return b === 1n ? M(x, md) : err('no inverse');       // b is gcd at this point
};
const sqrt = (n: bigint) => {                           // √n = n^((p+1)/4) for fields p = 3 mod 4
  let r = 1n;     // So, a special, fast case. Paper: "Square Roots from 1;24,51,10 to Dan Shanks".
  for (let num = n, e = (P + 1n) / 4n; e > 0n; e >>= 1n) { // powMod: modular exponentiation.
    if (e & 1n) r = (r * num) % P;                      // Uses exponentiation by squaring.
    num = (num * num) % P;                              // Not constant-time.
  }
  return M(r * r) === n ? r : err('sqrt invalid');      // check if result is valid
};
const toPriv = (pr: PrivKey): bigint => {               // normalize private key to bigint
  if (!isB(pr)) pr = b2n(toU8(pr, fLen));               // convert to bigint when bytes
  return arange(pr, 1n, N, 'private key invalid 3');    // check if bigint is in range
};
const high = (n: bigint): boolean => n > (N >> 1n);     // if a number is bigger than CURVE.n/2
/** Creates 33/65-byte public key from 32-byte private key. */
const getPublicKey = (privKey: PrivKey, isCompressed = true): Bytes => {
  return Point.fromPrivateKey(privKey).toRawBytes(isCompressed);
}
/** ECDSA Signature class. Supports only compact 64-byte representation, not DER. */
class Signature {
  readonly r: bigint;
  readonly s: bigint;
  readonly recovery?: number;
  constructor(r: bigint, s: bigint, recovery?: number) {
    this.r = agroup(r);                                 // 1 <= r < N
    this.s = agroup(s);                                 // 1 <= s < N
    if (recovery != null) this.recovery = recovery;
    Object.freeze(this);
  }                                                     // constructed outside.
  /** Create signature from 64b compact (r || s) representation. */
  static fromCompact(hex: Hex): Signature {
    const b = toU8(hex, 64);                            // compact repr is (32b r)||(32b s)
    return new Signature(slc(b, 0, fLen), slc(b, fLen, 2 * fLen));
  }
  assertValidity(): Signature { return this; }          // legacy, no-op, now done in constructor
  /** Create new signature, with added recovery bit. */
  addRecoveryBit(rec: number): SignatureWithRecovery {
    return new Signature(this.r, this.s, rec) as SignatureWithRecovery;
  }
  hasHighS(): boolean { return high(this.s); }
  normalizeS(): Signature {
    const { r, s, recovery } = this;
    return high(s) ? new Signature(r, M(-s, N), recovery) : this;
  }
  recoverPublicKey(msgh: Hex): Point { return recover(this as SignatureWithRecovery, msgh); }
  /** Uint8Array 64b compact (r || s) representation. */
  toCompactRawBytes(): Bytes { return h2b(this.toCompactHex()); }
  /** Hex string 64b compact (r || s) representation. */
  toCompactHex(): string { return n2h(this.r) + n2h(this.s); }
}
const bits2int = (bytes: Bytes): bigint => {            // RFC6979: ensure ECDSA msg is X bytes.
  const delta = bytes.length * 8 - 256; // RFC suggests optional truncating via bits2octets
  if (delta > 1024) err('msg invalid');   // our CUSTOM check, "just-in-case"
  const num = b2n(bytes); // FIPS 186-4 4.6 suggests the leftmost min(nBitLen, outLen) bits, which
  return delta > 0 ? num >> BigInt(delta) : num; // matches bits2int. bits2int can produce res>N.
};
const bits2int_modN = (bytes: Bytes): bigint => {       // int2octets can't be used; pads small msgs
  return M(bits2int(bytes), N);                         // with 0: BAD for trunc as per RFC vectors
};
const i2o = (num: bigint): Bytes => n2b(num);           // int to octets
declare const globalThis: Record<string, any> | undefined; // Typescript symbol present in browsers
const cr = () => // We support: 1) browsers 2) node.js 19+ 3) deno, other envs with crypto
  typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined;
const subtle = () => {
  const c = cr();
  return c && c.subtle || err('crypto.subtle must be defined');
};
type HmacFnSync = undefined | ((key: Bytes, ...msgs: Bytes[]) => Bytes);
type OptS = { lowS?: boolean; extraEntropy?: boolean | Hex; };
type OptV = { lowS?: boolean };
const optS: OptS = { lowS: true }; // opts for sign()
const optV: OptV = { lowS: true }; // standard opts for verify()
type BC = { seed: Bytes, k2sig : (kb: Bytes) => SignatureWithRecovery | undefined }; // Bytes+predicate checker
const prepSig = (msgh: Hex, priv: PrivKey, opts: OptS = optS): BC => {// prepare for RFC6979 sig generation
  if (['der', 'recovered', 'canonical'].some(k => k in opts)) err('option not supported'); // legacy opts
  let { lowS } = opts;                                  // generates low-s sigs by default
  if (lowS == null) lowS = true;                        // RFC6979 3.2: we skip step A
  const h1i = bits2int_modN(toU8(msgh));                // msg bigint
  const h1o = i2o(h1i);                                 // msg octets
  const d = toPriv(priv);                               // validate private key, convert to bigint
  const seed = [i2o(d), h1o];                           // Step D of RFC6979 3.2
  let ent = opts.extraEntropy;                          // RFC6979 3.6: additional k' (optional)
  if (ent) // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1) || k')
    seed.push(ent === true ? etc.randomBytes(fLen) : toU8(ent)); // true == fetch from CSPRNG
  const m = h1i;                                        // convert msg to bigint
  const k2sig = (kBytes: Bytes): SignatureWithRecovery | undefined => { // Transform k => Signature.
    const k = bits2int(kBytes);                         // RFC6979 method.
    if (!(1n <= k && k < N)) return;                    // Check 0 < k < CURVE.n
    const ik = inv(k, N);                               // k^-1 mod n, NOT mod P
    const q = G.mul(k).aff();                           // q = Gk
    const r = M(q.x, N);                                // r = q.x mod n
    if (r === 0n) return;                               // r=0 invalid
    const s = M(ik * M(m + M(d * r, N), N), N);         // s = k^-1(m + rd) mod n
    if (s === 0n) return;                               // s=0 invalid
    let normS = s;                                      // normalized S
    let rec = (q.x === r ? 0 : 2) | Number(q.y & 1n);   // recovery bit
    if (lowS && high(s)) {                              // if lowS was passed, ensure s is always
      normS = M(-s, N);                                 // in the bottom half of CURVE.n
      rec ^= 1;
    }
    return new Signature(r, normS, rec) as SignatureWithRecovery;       // use normS, not s
  };
  return { seed: concatB(...seed), k2sig }
}
type Pred<T> = (v: Uint8Array) => T | undefined;
function hmacDrbg<T>(asynchronous: true): (seed: Bytes, predicate: Pred<T>) => Promise<T>;
function hmacDrbg<T>(asynchronous: false): (seed: Bytes, predicate: Pred<T>) => T;
function hmacDrbg<T>(asynchronous: boolean) { // HMAC-DRBG async
  let v = u8n(fLen);  // Minimal non-full-spec HMAC-DRBG from NIST 800-90 for RFC6979 sigs.
  let k = u8n(fLen);  // Steps B, C of RFC6979 3.2: set hashLen, in our case always same
  let i = 0;          // Iterations counter, will throw when over 1000
  const reset = () => { v.fill(1); k.fill(0); i = 0; };
  const _e = 'drbg: tried 1000 values';
  if (asynchronous) {                                   // asynchronous=true
    const h = (...b: Bytes[]) => etc.hmacSha256Async(k, v, ...b); // hmac(k)(v, ...values)
    const reseed = async (seed = u8n(0)) => {           // HMAC-DRBG reseed() function. Steps D-G
      k = await h(u8fr([0x00]), seed);                  // k = hmac(K || V || 0x00 || seed)
      v = await h();                                    // v = hmac(K || V)
      if (seed.length === 0) return;
      k = await h(u8fr([0x01]), seed);                  // k = hmac(K || V || 0x01 || seed)
      v = await h();                                    // v = hmac(K || V)
    };
    const gen = async () => {                           // HMAC-DRBG generate() function
      if (i++ >= 1000) err(_e);
      v = await h();                                    // v = hmac(K || V)
      return v;
    };
    return async (seed: Bytes, pred: Pred<T>): Promise<T> => { // Even though it feels safe to reuse
      reset(); // the returned fn, don't, it's: 1. slower (JIT). 2. unsafe (async race conditions)
      await reseed(seed);                               // Steps D-G
      let res: T | undefined = undefined;               // Step H: grind until k is in [1..n-1]
      while (!(res = pred(await gen()))) await reseed();// test predicate until it returns ok
      reset();
      return res!;
    };
  } else {
    const h = (...b: Bytes[]) => {                      // asynchronous=false; same, but synchronous
      const fn = etc.hmacSha256Sync;
      if (typeof fn !== 'function') err('etc.hmacSha256Sync not set');
      return fn!(k, v, ...b);                            // hmac(k)(v, ...values)
    };
    const reseed = (seed = u8n(0)) => {                 // HMAC-DRBG reseed() function. Steps D-G
      k = h(u8fr([0x00]), seed);                        // k = hmac(k || v || 0x00 || seed)
      v = h();                                          // v = hmac(k || v)
      if (seed.length === 0) return;
      k = h(u8fr([0x01]), seed);                        // k = hmac(k || v || 0x01 || seed)
      v = h();                                          // v = hmac(k || v)
    };
    const gen = () => {                                 // HMAC-DRBG generate() function
      if (i++ >= 1000) err(_e);
      v = h();                                          // v = hmac(k || v)
      return v;
    };
    return (seed: Bytes, pred: Pred<T>): T => {
      reset();
      reseed(seed);                                     // Steps D-G
      let res: T | undefined = undefined;               // Step H: grind until k is in [1..n-1]
      while (!(res = pred(gen()))) reseed();            // test predicate until it returns ok
      reset();
      return res!;
    };
  }
};
/** ECDSA signature generation. via secg.org/sec1-v2.pdf 4.1.2 + RFC6979 deterministic k. */
/**
 * Sign a msg hash using secp256k1. Async.
 * It is advised to use `extraEntropy: true` (from RFC6979 3.6) to prevent fault attacks.
 * Worst case: if randomness source for extraEntropy is bad, it would be as secure as if
 * the option has not been used.
 * @param msgh - message HASH, not message itself e.g. sha256(message)
 * @param priv - private key
 * @param opts - `lowS: true` to prevent malleability (s >= CURVE.n/2), `extraEntropy: boolean | Hex` to improve sig security.
 */
const signAsync = async (msgh: Hex, priv: PrivKey, opts: OptS = optS): Promise<SignatureWithRecovery> => {
  const { seed, k2sig } = prepSig(msgh, priv, opts);    // Extract arguments for hmac-drbg
  return hmacDrbg<SignatureWithRecovery>(true)(seed, k2sig);  // Re-run drbg until k2sig returns ok
};
/**
 * Sign a msg hash using secp256k1.
 * It is advised to use `extraEntropy: true` (from RFC6979 3.6) to prevent fault attacks.
 * Worst case: if randomness source for extraEntropy is bad, it would be as secure as if
 * the option has not been used.
 * @param msgh - message HASH, not message itself e.g. sha256(message)
 * @param priv - private key
 * @param opts - `lowS: true` to prevent malleability (s >= CURVE.n/2), `extraEntropy: boolean | Hex` to improve sig security.
 * @example
 * const sig = sign(sha256('hello'), privKey, { extraEntropy: true }).toCompactRawBytes();
 */
const sign = (msgh: Hex, priv: PrivKey, opts: OptS = optS): SignatureWithRecovery => {
  const { seed, k2sig } = prepSig(msgh, priv, opts);    // Extract arguments for hmac-drbg
  return hmacDrbg<SignatureWithRecovery>(false)(seed, k2sig); // Re-run drbg until k2sig returns ok
};
/**
 * Verify a signature using secp256k1.
 * @param sig - signature, 64-byte or Signature instance
 * @param msgh - message HASH, not message itself e.g. sha256(message)
 * @param pub - public key
 * @param opts - { lowS: true } is default, prohibits s >= CURVE.n/2 to prevent malleability
 */
const verify = (sig: Hex | SigLike, msgh: Hex, pub: Hex, opts: OptV = optV): boolean => {
  let { lowS } = opts;                                  // ECDSA signature verification
  if (lowS == null) lowS = true;                        // Default lowS=true
  if ('strict' in opts) err('option not supported');    // legacy param
  let sig_: Signature, h: bigint, P: Point;             // secg.org/sec1-v2.pdf 4.1.4
  const rs = sig && typeof sig === 'object' && 'r' in sig; // Previous ver supported DER sigs. We
  if (!rs && (toU8(sig).length !== 2 * fLen))           // throw error when DER is suspected now.
    err('signature must be 64 bytes');
  try {
    sig_ = rs ? new Signature(sig.r, sig.s) : Signature.fromCompact(sig);
    h = bits2int_modN(toU8(msgh));                      // Truncate hash
    P = Point.fromHex(pub);                             // Validate public key
  } catch (e) { return false; }                         // Check sig for validity in both cases
  if (!sig_) return false;
  const { r, s } = sig_;
  if (lowS && high(s)) return false;                    // lowS bans sig.s >= CURVE.n/2
  let R: AffinePoint;                                   // Actual verification code begins here
  try {
    const is = inv(s, N);                               // s^-1
    const u1 = M(h * is, N);                            // u1 = hs^-1 mod n
    const u2 = M(r * is, N);                            // u2 = rs^-1 mod n
    R = G.mulAddQUns(P, u1, u2).aff();                  // R = u1⋅G + u2⋅P
  } catch (error) { return false; }
  if (!R) return false;                                 // stop if R is identity / zero point
  const v = M(R.x, N);                                  // R.x must be in N's field, not P's
  return v === r;                                       // mod(R.x, n) == r
};

/** ECDSA public key recovery. Requires msg hash and recovery id. */
const recover = (point: SignatureWithRecovery, msgh: Hex): Point => {
  const { r, s, recovery: rec } = point;              // secg.org/sec1-v2.pdf 4.1.6
  if (![0, 1, 2, 3].includes(rec!)) err('recovery id invalid'); // check recovery id
  const h = bits2int_modN(toU8(msgh, fLen));          // Truncate hash
  const radj = rec === 2 || rec === 3 ? r + N : r;    // If rec was 2 or 3, q.x is bigger than n
  afield(radj);                                       // ensure q.x is still a field element
  const head = (rec & 1) === 0 ? '02' : '03';         // head is 0x02 or 0x03
  const R = Point.fromHex(head + n2h(radj));          // concat head + hex repr of r
  const ir = inv(radj, N);                            // r^-1
  const u1 = M(-h * ir, N);                           // -hr^-1
  const u2 = M(s * ir, N);                            // sr^-1
  return G.mulAddQUns(R, u1, u2);                     // (sr^-1)R-(hr^-1)G = -(hr^-1)G + (sr^-1)
}

/**
 * Elliptic Curve Diffie-Hellman (ECDH) on secp256k1.
 * Result is **NOT hashed**. Use hash on it if you need.
 * @param privA private key A
 * @param pubB public key B
 * @param isCompressed 33-byte or 65-byte output
 * @returns public key C
 */
const getSharedSecret = (privA: Hex, pubB: Hex, isCompressed = true): Bytes => {
  return Point.fromHex(pubB).mul(toPriv(privA)).toRawBytes(isCompressed); // ECDH
};
const hashToPrivateKey = (hash: Hex): Bytes => {        // FIPS 186 B.4.1 compliant key generation
  hash = toU8(hash);                                    // produces private keys with modulo bias
  if (hash.length < fLen + 8 || hash.length > 1024) err('expected 40-1024b'); // being neglible.
  const num = M(b2n(hash), N - 1n);                     // takes n+8 bytes
  return n2b(num + 1n);                                 // returns (hash mod n-1)+1
};
/** Math, hex, byte helpers. Not in `utils` because utils share API with noble-curves. */
const etc = {
  hexToBytes: h2b as (hex: string) => Bytes,
  bytesToHex: b2h as (bytes: Bytes) => string,
  concatBytes: concatB as (...arrs: Bytes[]) => Bytes,
  bytesToNumberBE: b2n as (a: Bytes) => bigint,
  numberToBytesBE: n2b as (n: bigint) => Bytes,
  mod: M as (a: bigint, md?: bigint) => bigint,
  invert: inv as (num: bigint, md?: bigint) => bigint,  // math utilities
  hmacSha256Async: async (key: Bytes, ...msgs: Bytes[]): Promise<Bytes> => {
    const s = subtle();
    const k = await s.importKey('raw', key, {name:'HMAC',hash:{name:'SHA-256'}}, false, ['sign']);
    return u8n(await s.sign('HMAC', k, concatB(...msgs)));
  },
  hmacSha256Sync: undefined as HmacFnSync,              // For TypeScript. Actual logic is below
  hashToPrivateKey: hashToPrivateKey as (hash: Hex) => Bytes,
  randomBytes: (len = 32): Bytes => {                   // CSPRNG (random number generator)
    const crypto = cr(); // Must be shimmed in node.js <= 18 to prevent error. See README.
    if (!crypto || !crypto.getRandomValues) err('crypto.getRandomValues must be defined');
    return crypto.getRandomValues(u8n(len));
  },
};
/** Curve-specific utilities for private keys. */
const utils = {                                         // utilities
  normPrivateKeyToScalar: toPriv as (p: PrivKey) => bigint,
  isValidPrivateKey: (key: Hex): boolean => { try { return !!toPriv(key); } catch (e) { return false; } },
  randomPrivateKey: (): Bytes => hashToPrivateKey(etc.randomBytes(fLen + 16)), // FIPS 186 B.4.1.
  precompute: (w=8, p: Point = G): Point => { p.multiply(3n); w; return p; }, // no-op
};
const W = 8;                                            // Precomputes-related code. W = window size
const scalarBits = 256;
const pwindows = Math.ceil(scalarBits / W) + 1;         // W=8 33
const pwindowSize = 2 ** (W - 1);                       // W=8 128
const precompute = () => {                              // They give 12x faster getPublicKey(),
  const points: Point[] = [];                           // 10x sign(), 2x verify(). To achieve this,
  let p = G, b = p;                                     // a lot of points related to base point G.
  for (let w = 0; w < pwindows; w++) {                  // Points are stored in array and used
    b = p;                                              // any time Gx multiplication is done.
    points.push(b);                                     // They consume 16-32 MiB of RAM.
    for (let i = 1; i < pwindowSize; i++) { b = b.add(p); points.push(b); } // i=1, bc we skip 0
    p = b.double();                                     // Precomputes don't speed-up getSharedKey,
  }                                                     // which multiplies user point by scalar,
  return points;                                        // when precomputes are using base point
}
let Gpows: Point[] | undefined = undefined;             // precomputes for base point G
const wNAF = (n: bigint): { p: Point; f: Point } => {   // w-ary non-adjacent form (wNAF) method.
                                                        // Compared to other point mult methods,
  const comp = Gpows || (Gpows = precompute());         // stores 2x less points using subtraction
  const ctneg = (cnd: boolean, p: Point) => { let n = p.negate(); return cnd ? n : p; } // negate
  let p = I, f = G;                                     // f must be G, or could become I in the end
  const pow_2_w = 2 ** W;                               // W=8 256
  const maxNum = pow_2_w;                               // W=8 256
  const mask = BigInt(pow_2_w - 1);                     // W=8 255 == mask 0b11111111
  const shiftBy = BigInt(W);                            // W=8 8
  for (let w = 0; w < pwindows; w++) {
    let wbits = Number(n & mask);                       // extract W bits.
    n >>= shiftBy;                                      // shift number by W bits.
    if (wbits > pwindowSize) {wbits -= maxNum; n += 1n;}// split if bits > max: +224 => 256-32
    const off = w * pwindowSize;
    const offF = off, offP = off + Math.abs(wbits) - 1; // offsets, evaluate both
    const isEven = w % 2 !== 0, isNeg = wbits < 0;      // conditions, evaluate both
    if (wbits === 0) {
      f = f.add(ctneg(isEven, comp[offF]));             // bits are 0: add garbage to fake point
    } else {                                            //          ^ can't add off2, off2 = I
      p = p.add(ctneg(isNeg, comp[offP]));              // bits are 1: add to result point
    }
  }
  return { p, f }                                       // return both real and fake points for JIT
};        // !! you can disable precomputes by commenting-out call of the wNAF() inside Point#mul()
// !! Remove the export to easily use in REPL / browser console
export {
  CURVE, etc, getPublicKey,
  getSharedSecret, Point as ProjectivePoint, sign, signAsync, Signature, utils, verify
};
