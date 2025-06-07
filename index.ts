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
const _b = 7n;
const _0 = 0n;
const _1 = 1n;
const L = 32;                                           // field / group byte length
const L2 = 64;
/**
 * secp256k1 curve parameters. Equation is x³ + ax + b, but a=0 - which makes it x³+b.
 * Gx and Gy are generator coordinates. p is field order, n is group order.
 */
const CURVE: { p: bigint; n: bigint; a: bigint; b: bigint; Gx: bigint; Gy: bigint } = {
  p: P, n: N, a: _0, b: _b, Gx, Gy };                   // exported variables incl. a, b
/** Alias to Uint8Array. */
export type Bytes = Uint8Array;
/** Signature instance, which allows recovering pubkey from it. */
export type SignatureWithRecovery = Signature & { recovery: number }
const curve = (x: bigint) => M(M(x * x) * x + _b); // x³+b secp256k1 formula
// lift_x from BIP340 calculates square root.
const lift_x = (x: bigint) => {
  // check 1<=x<P
  const c = curve(afield(x)); // Let c = x³ + 7 mod p. Fail if x ≥ p.
  // y = c^(p+1)/4 mod p.
  // √n = n^((p+1)/4) for fields p = 3 mod 4 -- a special, fast case.
  let r = _1; // Paper: "Square Roots from 1;24,51,10 to Dan Shanks".
  for (let num = c, e = (P + _1) / 4n; e > _0; e >>= _1) { // powMod: modular exponentiation.
    if (e & _1) r = (r * num) % P;                      // Uses exponentiation by squaring.
    num = (num * num) % P;                              // Not constant-time.
  }
  return M(r * r) === c ? r : err('sqrt invalid');      // check if result is valid
};
const err = (m = ''): never => { throw new Error(m); }; // error helper, messes-up stack trace
const isB = (n: unknown): n is bigint => typeof n === 'bigint'; // is big integer
const arange = (n: bigint, min: bigint, max: bigint, msg = 'bad number: out of range') =>
  isB(n) && min <= n && n < max ? n : err(msg);
const afield0 = (n: bigint) => arange(n, _0, P);        // assert field element or 0
const afield = (n: bigint) => arange(n, _1, P);         // assert field element
const agroup = (n: bigint) => arange(n, _1, N);         // assert group elem
const isBytes = (a: unknown): a is Uint8Array => (
  a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array')
);
const abytes = (a: unknown, l?: number): Bytes =>       // assert is Uint8Array (of specific length)
  !isBytes(a) || (typeof l === 'number' && l > 0 && a.length !== l) ?
    err('Uint8Array expected') : a;
const u8n = (len: number) => new Uint8Array(len);       // creates Uint8Array
const u8of = (n: number) => Uint8Array.of(n);
const big = BigInt;
const M = (a: bigint, b: bigint = P) => {               // mod division
  const r = a % b;
  return r >= _0 ? r : b + r;
};
const modN = (a: bigint) => M(a, N);
const isEven = (y: bigint) => (y & _1) === _0;
const getPrefix = (y: bigint) => u8of(isEven(y) ? 0x02 : 0x03);
const freeze = (a: object) => Object.freeze(a);
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
    this.py = afield(py);                               // y can't be 0 in Projective
    this.pz = afield0(pz);
    freeze(this);
  }
  static fromBytes(bytes: Bytes): Point {
    abytes(bytes);
    let p: Point | undefined = undefined;
    const head = bytes[0], tail = bytes.subarray(1);    // first byte is prefix, rest is data
    const x = sliceBytesNum(tail, 0, L), len = bytes.length; // next 32 bytes are x coordinate
    if (len === (L+1) && [0x02, 0x03].includes(head)) { // Compressed 33-byte point
      let y = lift_x(x);                                // x³+b is right side of equation
      const evenY = isEven(y);                          // y² is equivalent left-side
      const evenH = isEven(big(head));                  // y = √y²; there are two solutions: y, -y
      if (evenH !== evenY) y = M(-y);                   // determine proper solution
      p = new Point(x, y, _1);                          // create point
    }
    if (len === (L2+1) && head === 0x04)                // Uncompressed 65-byte point, 0x04 prefix
      p = new Point(x, sliceBytesNum(tail, L, L2), _1);
    return p ? p.ok() : err('bad Point: not on curve'); // Verify the result
  }
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
    const a = _0;
    const b = _b;
    let X3 = _0, Y3 = _0, Z3 = _0;
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
    if (!safe && n === _0) return I;                    // in unsafe mode, allow zero
    agroup(n);                                          // must be 1 <= n < CURVE.n
    if (this.equals(G)) return wNAF(n).p;               // use precomputes for base point
    let p = I, f = G;                                   // init result point & fake point
    for (let d: Point = this; n > _0; d = d.double(), n >>= _1) { // double-and-add ladder
      if (n & _1) p = p.add(d);                         // if bit is present, add to point
      else if (safe) f = f.add(d);                      // if not, add to fake for timing safety
    }
    return p;
  }
  /** Convert point to 2d xy affine point. (x, y, z) ∋ (x=x/z, y=y/z) */
  aff(): AffinePoint {
    const { px: x, py: y, pz: z } = this;
    if (this.equals(I)) return { x: _0, y: _0 };        // fast-path for zero point
    if (z === _1) return { x, y };                      // if z is 1, pass affine coordinates as-is
    const iz = invert(z, P);                            // z^-1: invert z
    if (M(z * iz) !== _1) err('inverse invalid');       // (z * z^-1) must be 1, otherwise bad math
    return { x: M(x * iz), y: M(y * iz) };              // x = x*z^-1; y = y*z^-1
  }
  /** Checks if the point is valid and on-curve. */
  ok(): Point {
    const { x, y } = this.aff();                        // convert to 2d xy affine point.
    afield(x);
    afield(y);                                          // must be in range 1 <= x,y < P
    return M(y * y) === curve(x) ?                      // y² = x³ + ax + b, must be equal
      this : err('bad point: not on curve');
  }
  toBytes(isCompressed = true): Bytes {                 // Encode point to Uint8Array.
    const { x, y } = this.ok().aff();                   // convert to 2d xy affine point
    const x32b = numTo32b(x);
    if (isCompressed) return concatBytes(getPrefix(y), x32b);
    return concatBytes(u8of(0x04), x32b, numTo32b(y));
  }

  // Can be commented-out:
  is0(): boolean { return this.equals(I); }
  // 0.4kb
  toHex(c=true): string { return bytesToHex(this.toBytes(c)); }
  multiply(n: bigint): Point { return this.mul(n); }
  static fromPrivateKey(k: Bytes): Point { return G.mul(toPrivScalar(k)); }
  // 0.02kb
  get x(): bigint { return this.aff().x; }
  get y(): bigint { return this.aff().y; }
  // 0.03kb
  static fromAffine(ap: AffinePoint): Point {
    const { x, y } = ap;
    if (x === 0n && y === 0n) return I;
    return new Point(x, y, 1n);
  }
}
/** Generator / base point */
const G: Point = new Point(Gx, Gy, _1);
/** Identity / zero point */
const I: Point = new Point(_0, _1, _0);
// Unsafe multiplication Q = u1⋅G + u2⋅R.
const mulG2uns = (R: Point, u1: bigint, u2: bigint): Point => {
  return G.mul(u1, false).add(R.mul(u2, false)).ok();
}
const padh = (n: number | bigint, pad: number) => n.toString(16).padStart(pad, '0');
const bytesToHex = (b: Bytes): string => Array.from(abytes(b)).map(e => padh(e, 2)).join('');
const C = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 } as const; // ASCII characters
const _ch = (ch: number): number | undefined => {
  if (ch >= C._0 && ch <= C._9) return ch - C._0;       // '2' => 50-48
  if (ch >= C.A && ch <= C.F) return ch - (C.A - 10);   // 'B' => 66-(65-10)
  if (ch >= C.a && ch <= C.f) return ch - (C.a - 10);   // 'b' => 98-(97-10)
  return;
};
const hexToBytes = (hex: string): Bytes => {
  const e = 'hex invalid';
  if (typeof hex !== 'string') return err(e);
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
const bytesToNum = (b: Bytes): bigint => big('0x' + (bytesToHex(b) || '0'));
const sliceBytesNum = (b: Bytes, from: number, to: number) => bytesToNum(b.subarray(from, to));
// Number to 32b. Must be 0 <= num < B256. validate, pad, to bytes
const numTo32b = (num: bigint): Bytes => hexToBytes(padh(arange(num, _0, B256), L2));
const concatBytes = (...arrs: Bytes[]): Bytes => {          // concatenate Uint8Array-s
  const r = u8n(arrs.reduce((sum, a) => sum + abytes(a).length, 0)); // create u8a of summed length
  let pad = 0;                                          // walk through each array,
  arrs.forEach(a => {r.set(a, pad); pad += a.length});  // ensure they have proper type
  return r;
};
const invert = (num: bigint, md: bigint): bigint => {   // modular inversion
  if (num === _0 || md <= _0) err('no inverse n=' + num + ' mod=' + md); // no neg exponent for now
  let a = M(num, md), b = md, x = _0, y = _1, u = _1, v = _0;
  while (a !== _0) {                                    // uses euclidean gcd algorithm
    const q = b / a, r = b % a;                         // not constant-time
    const m = x - u * q, n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  return b === _1 ? M(x, md) : err('no inverse');       // b is gcd at this point
};
const toPrivScalar = (pr: Bytes): bigint => {           // normalize private key to bigint
  let num = bytesToNum(abytes(pr, L));                         // convert to bigint when bytes
  return arange(num, _1, N, 'private key invalid 3');   // check if bigint is in range
};
const highS = (n: bigint): boolean => n > (N >> _1);    // if a number is bigger than CURVE.n/2
/** Creates 33/65-byte public key from 32-byte private key. */
const getPublicKey = (privKey: Bytes, isCompressed = true): Bytes => {
  return G.mul(toPrivScalar(privKey)).toBytes(isCompressed);
}

// UNUSED for now
/** ECDSA Signature class. Supports only compact 64-byte representation, not DER. */
class Signature {
  readonly r: bigint;
  readonly s: bigint;
  readonly recovery?: number;
  constructor(r: bigint, s: bigint, recovery?: number) {
    this.r = agroup(r);                                 // 1 <= r < N
    this.s = agroup(s);                                 // 1 <= s < N
    if (recovery != null) this.recovery = recovery;
    freeze(this);
  }
  static fromBytes(b: Bytes): Signature {
    abytes(b, L2);
    const r = sliceBytesNum(b, 0, L);
    const s = sliceBytesNum(b, L, L2);
    return new Signature(r, s);
  }
  toBytes(): Bytes {
    const { r, s } = this;
    return concatBytes(numTo32b(r), numTo32b(s));
  }
  // Can be commented-out:
  // 0.04kb
  hasHighS(): boolean { return highS(this.s); }
  toCompactRawBytes(): Bytes {
    return this.toBytes();
  }
  toCompactHex(): string {
    return bytesToHex(this.toBytes());
  }
  addRecoveryBit(bit: number): SignatureWithRecovery {
    return (new Signature(this.r, this.s, bit)) as SignatureWithRecovery;
  }
  // 0.11kb
  recoverPublicKey(msg: Bytes): Point {
    return recoverPublicKey(this as unknown as SignatureWithRecovery, msg);
  }
}
const bits2int = (bytes: Bytes): bigint => {            // RFC6979: ensure ECDSA msg is X bytes.
  const delta = bytes.length * 8 - 256; // RFC suggests optional truncating via bits2octets
  if (delta > 1024) err('msg invalid'); // our CUSTOM check, "just-in-case"
  const num = bytesToNum(bytes); // FIPS 186-4 4.6 suggests the leftmost min(nBitLen, outLen) bits, which
  return delta > 0 ? num >> big(delta) : num; // matches bits2int. bits2int can produce res>N.
};
const bits2int_modN = (bytes: Bytes): bigint => {       // int2octets can't be used; pads small msgs
  return modN(bits2int(abytes(bytes)));                 // with 0: BAD for trunc as per RFC vectors
};
declare const globalThis: Record<string, any> | undefined; // Typescript symbol present in browsers
const cr = () => globalThis?.crypto; // WebCrypto is available in all modern environments
const subtle = () => {
  const c = cr();
  return c?.subtle || err('crypto.subtle must be defined');
};
const callEtcFn = (name: string) => {
  // @ts-ignore
  const fn = etc[name];
  if (typeof fn !== 'function') err('err.' + name + ' not set');
  return fn;
};
const randomBytes = (len = L): Bytes => {               // CSPRNG (random number generator)
  const c = cr();    // Must be shimmed in node.js <= 18 to prevent error. See README.
  return c.getRandomValues(u8n(len));
};
type HmacFnSync = undefined | ((key: Bytes, ...msgs: Bytes[]) => Bytes);
type OptS = { lowS?: boolean; extraEntropy?: boolean | Bytes; };
type OptV = { lowS?: boolean };
const optS: OptS = { lowS: true }; // opts for sign()
const optV: OptV = { lowS: true }; // standard opts for verify()
type BC = { seed: Bytes, k2sig : (kb: Bytes) => SignatureWithRecovery | undefined }; // Bytes+predicate checker
const prepSig = (msgh: Bytes, priv: Bytes, opts: OptS = optS): BC => {// prepare for RFC6979 sig generation
  let { lowS, extraEntropy } = opts;                                  // generates low-s sigs by default
  if (lowS == null) lowS = true;                        // RFC6979 3.2: we skip step A
  const i2o = numTo32b;                                 // int to octets
  const h1i = bits2int_modN(msgh);                      // msg bigint
  const h1o = i2o(h1i);                                 // msg octets
  const d = toPrivScalar(priv);                         // validate private key, convert to bigint
  const seed = [i2o(d), h1o];                           // Step D of RFC6979 3.2
  // RFC6979 3.6: additional k' (optional)
  // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1) || k')
  if (extraEntropy) // true means fetch from CSPRNG
    seed.push(extraEntropy === true ? randomBytes(L) : abytes(extraEntropy));
  const m = h1i;                                        // convert msg to bigint
  const k2sig = (kBytes: Bytes): SignatureWithRecovery | undefined => { // Transform k => Signature.
    const k = bits2int(kBytes);                         // RFC6979 method.
    if (!(_1 <= k && k < N)) return;                    // Check 0 < k < CURVE.n
    const q = G.mul(k).aff();                           // q = Gk
    const r = modN(q.x);                                // r = q.x mod n
    if (r === _0) return;                               // r=0 invalid
    const ik = invert(k, N);                            // k^-1 mod n, NOT mod P
    const s = modN(ik * modN(m + modN(d * r)));         // s = k^-1(m + rd) mod n
    if (s === _0) return;                               // s=0 invalid
    let normS = s;                                      // normalized S
    let rec = (q.x === r ? 0 : 2) | Number(q.y & _1);   // recovery bit
    if (lowS && highS(s)) {                             // if lowS was passed, ensure s is always
      normS = modN(-s);                                 // in the bottom half of CURVE.n
      rec ^= 1;
    }
    // return newsig(r, normS, rec) as SignatureWithRecovery;
    return new Signature(r, normS, rec) as SignatureWithRecovery;       // use normS, not s
  };
  return { seed: concatBytes(...seed), k2sig }
}
type Pred<T> = (v: Uint8Array) => T | undefined;
const hmacDrbg = <T>(asynchronous: boolean) => { // HMAC-DRBG async
  let v = u8n(L);  // Minimal non-full-spec HMAC-DRBG from NIST 800-90 for RFC6979 sigs.
  let k = u8n(L);  // Steps B, C of RFC6979 3.2: set hashLen, in our case always same
  let i = 0;       // Iterations counter, will throw when over 1000
  const reset = () => { v.fill(1); k.fill(0); i = 0; };
  const max = 1000;
  const _e = 'drbg: tried 1000 values';
  if (asynchronous) {                                   // asynchronous=true
    const h = (...b: Bytes[]) => etc.hmacSha256Async(k, v, ...b); // hmac(k)(v, ...values)
    const reseed = async (seed = u8n(0)) => {           // HMAC-DRBG reseed() function. Steps D-G
      k = await h(u8of(0x00), seed);                    // k = hmac(K || V || 0x00 || seed)
      v = await h();                                    // v = hmac(K || V)
      if (seed.length === 0) return;
      k = await h(u8of(0x01), seed);                    // k = hmac(K || V || 0x01 || seed)
      v = await h();                                    // v = hmac(K || V)
    };
    const gen = async () => {                           // HMAC-DRBG generate() function
      if (i++ >= max) err(_e);
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
      return callEtcFn('hmacSha256')(k, v, ...b);       // hmac(k)(v, ...values)
    };
    const reseed = (seed = u8n(0)) => {                 // HMAC-DRBG reseed() function. Steps D-G
      k = h(u8of(0x00), seed);                          // k = hmac(k || v || 0x00 || seed)
      v = h();                                          // v = hmac(k || v)
      if (seed.length === 0) return;
      k = h(u8of(0x01), seed);                          // k = hmac(k || v || 0x01 || seed)
      v = h();                                          // v = hmac(k || v)
    };
    const gen = () => {                                 // HMAC-DRBG generate() function
      if (i++ >= max) err(_e);
      v = h();                                          // v = hmac(k || v)
      return v; // this diverges from noble-curves: we don't allow arbitrary output len!
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
const signAsync = async (msgh: Bytes, priv: Bytes, opts: OptS = optS): Promise<SignatureWithRecovery> => {
  const { seed, k2sig } = prepSig(msgh, priv, opts);    // Extract arguments for hmac-drbg
  const sig = await hmacDrbg<SignatureWithRecovery>(true)(seed, k2sig);  // Re-run drbg until k2sig returns ok
  return sig;
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
 * const sig = sign(sha256('hello'), privKey, { extraEntropy: true });
 */
const sign = (msgh: Bytes, priv: Bytes, opts: OptS = optS): SignatureWithRecovery => {
  const { seed, k2sig } = prepSig(msgh, priv, opts);    // Extract arguments for hmac-drbg
  // Re-run drbg until k2sig returns ok
  const sig = hmacDrbg<SignatureWithRecovery>(false)(seed, k2sig) as unknown as SignatureWithRecovery;
  return sig;
};
/**
 * Verify a signature using secp256k1.
 * @param sig - signature, 64-byte or Signature instance
 * @param msgh - message HASH, not message itself e.g. sha256(message)
 * @param pub - public key
 * @param opts - { lowS: true } is default, prohibits s >= CURVE.n/2 to prevent malleability
 */
const verify = (sig: Bytes | Signature, msgh: Bytes, pub: Bytes, opts: OptV = optV): boolean => {
  let { lowS } = opts;                                  // ECDSA signature verification
  if (lowS == null) lowS = true;                        // Default lowS=true
  if (sig instanceof Signature) sig = new Signature(sig.r, sig.s).toBytes();
  abytes(sig, L2); abytes(msgh); abytes(pub);           // Validate options, throw
  try { // Actual verification code begins here
    const sigg = Signature.fromBytes(sig); // throw error when DER is suspected now.
    const h = bits2int_modN(msgh);                            // Truncate hash
    const P = Point.fromBytes(pub);                           // Validate public key
    const { r, s } = sigg;
    if (lowS && highS(s)) return false;                 // lowS bans sig.s >= CURVE.n/2
    const is = invert(s, N);                            // s^-1
    const u1 = modN(h * is);                            // u1 = hs^-1 mod n
    const u2 = modN(r * is);                            // u2 = rs^-1 mod n
    const R = mulG2uns(P, u1, u2).aff();                      // R = u1⋅G + u2⋅P
    if (!R) return false;                               // stop if R is identity / zero point
    const v = modN(R.x);                                // R.x must be in N's field, not P's
    return v === r;                                     // mod(R.x, n) == r
  } catch (error) { return false; }
};
/** ECDSA public key recovery. Requires msg hash and recovery id. */
const recoverPublicKey = (sig: SignatureWithRecovery, msgh: Bytes): Point => {
  const { r, s, recovery } = sig;              // secg.org/sec1-v2.pdf 4.1.6
  if (![0, 1, 2, 3].includes(recovery!)) err('recovery id invalid'); // check recovery id
  const h = bits2int_modN(abytes(msgh, L));             // Truncate hash
  const radj = recovery === 2 || recovery === 3 ? r + N : r; // q.x > n when rec was 2 or 3,
  afield(radj);                                       // ensure q.x is still a field element
  const head = getPrefix(big(recovery));           // head is 0x02 or 0x03
  const Rb = concatBytes(head, numTo32b(radj));
  const R = Point.fromBytes(Rb);                      // concat head + hex repr of r
  const ir = invert(radj, N);                         // r^-1
  const u1 = modN(-h * ir);                           // -hr^-1
  const u2 = modN(s * ir);                            // sr^-1
  return mulG2uns(R, u1, u2);                         // (sr^-1)R-(hr^-1)G = -(hr^-1)G + (sr^-1)
}

/**
 * Elliptic Curve Diffie-Hellman (ECDH) on secp256k1.
 * Result is **NOT hashed**. Use hash on it if you need.
 * @param privA private key A
 * @param pubB public key B
 * @param isCompressed 33-byte or 65-byte output
 * @returns public key C
 */
const getSharedSecret = (privA: Bytes, pubB: Bytes, isCompressed = true): Bytes => {
  return Point.fromBytes(pubB).mul(toPrivScalar(privA)).toBytes(isCompressed); // ECDH
};
const _sha = 'SHA-256';
/** Math, hex, byte helpers. Not in `utils` because utils share API with noble-curves. */
const etc = {
  hmacSha256Async: async (key: Bytes, ...msgs: Bytes[]): Promise<Bytes> => {
    const s = subtle();
    const name = 'HMAC';
    const k = await s.importKey('raw', key, {name,hash:{name:_sha}}, false, ['sign']);
    return u8n(await s.sign(name, k, concatBytes(...msgs)));
  },
  hmacSha256: undefined as HmacFnSync,              // For TypeScript. Actual logic is below
  sha256Async: async (msg: Bytes): Promise<Bytes> => u8n(await subtle().digest(_sha, msg)),
  sha256: undefined as Sha256FnSync,
};
const etc2 = {
  hexToBytes: hexToBytes as (hex: string) => Bytes,
  bytesToHex: bytesToHex as (bytes: Bytes) => string,
  concatBytes: concatBytes as (...arrs: Bytes[]) => Bytes,
  bytesToNumberBE: bytesToNum as (a: Bytes) => bigint,
  numberToBytesBE: numTo32b as (n: bigint) => Bytes,
  mod: M as (a: bigint, md?: bigint) => bigint,
  invert: invert as (num: bigint, md?: bigint) => bigint,  // math utilities
  randomBytes: randomBytes as (len?: number) => Bytes,
}
const randomPrivateKey = (): Bytes => {
  const num = M(bytesToNum(randomBytes(L + L / 2)), N - _1); // takes n+8 bytes
  return numTo32b(num + _1);                         // returns (hash mod n-1)+1
}; // FIPS 186 B.4.1.
/** Curve-specific utilities for private keys. */
const utils = {                                         // utilities
  isValidPrivateKey: (key: Bytes): boolean => {
    try { return !!toPrivScalar(key); } catch (e) { return false; }
  },
  randomPrivateKey: randomPrivateKey as () => Bytes,
  // precompute: (w=8, p: Point = G): Point => { p.multiply(3n); w; return p; }, // no-op
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
  const mask = big(pow_2_w - 1);                     // W=8 255 == mask 0b11111111
  const shiftBy = big(W);                            // W=8 8
  for (let w = 0; w < pwindows; w++) {
    let wbits = Number(n & mask);                       // extract W bits.
    n >>= shiftBy;                                      // shift number by W bits.
    if (wbits > pwindowSize) {wbits -= maxNum; n += _1;}// split if bits > max: +224 => 256-32
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

// Schnorr signatures are superior to ECDSA from above. Below is Schnorr-specific BIP0340 code.
// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
export type Sha256FnSync = undefined | ((msg: Bytes) => Bytes);
const getTag = (tag: string) => Uint8Array.from('BIP0340/' + tag, (c) => c.charCodeAt(0));
const T_AUX = 'aux';
const T_NONCE = 'nonce';
const T_CHALLENGE = 'challenge';
const taggedHash = (tag: string, ...messages: Bytes[]): Bytes => {
  const fn = callEtcFn('sha256');
  const tagH = fn(getTag(tag));
  return fn(concatBytes(tagH, tagH, ...messages));
};
const taggedHashAsync = async (tag: string, ...messages: Bytes[]): Promise<Bytes> => {
  const fn = etc.sha256Async;
  const tagH = await fn(getTag(tag));
  return await fn(concatBytes(tagH, tagH, ...messages));
};

// ECDSA compact points are 33-byte. Schnorr is 32: we strip first byte 0x02 or 0x03
const pointToBytes = (point: Point): Uint8Array<ArrayBuffer> => point.toBytes(true).subarray(1);
// Calculate point, scalar and bytes
const extpubSchnorr = (priv: Bytes) => {
  const d_ = toPrivScalar(priv); // same method executed in fromPrivateKey
  const p = G.mul(d_); // P = d'⋅G; 0 < d' < n check is done inside
  const d = isEven(p.aff().y) ? d_ : modN(-d_);
  const px = pointToBytes(p);
  return { d, px };
}
const challenge = (...args: Bytes[]): bigint =>
  modN(bytesToNum(taggedHash(T_CHALLENGE, ...args)));
const challengeAsync = async (...args: Bytes[]): Promise<bigint> =>
  modN(bytesToNum(await taggedHashAsync(T_CHALLENGE, ...args)));

/**
 * Schnorr public key is just `x` coordinate of Point as per BIP340.
 */
const pubSchnorr = (privateKey: Bytes): Bytes => {
  return extpubSchnorr(privateKey).px; // d'=int(sk). Fail if d'=0 or d'≥n. Ret bytes(d'⋅G)
}

// Common preparation fn for both sync and async signing
const prepSigSchnorr = (message: Bytes, privateKey: Bytes, auxRand: Bytes) => {
  const { px, d } = extpubSchnorr(privateKey);
  return { m: abytes(message), px, d, a: abytes(auxRand, L) };
}

const extractK = (rand: Bytes) => {
  const k_ = modN(bytesToNum(rand)); // Let k' = int(rand) mod n
  if (k_ === _0) err('sign failed: k is zero'); // Fail if k' = 0.
  const { px, d } = extpubSchnorr(numTo32b(k_)); // Let R = k'⋅G.
  return { rx: px, k: d }
}

// Common signature creation helper
const createSigSchnorr = (k: bigint, px: Bytes, e: bigint, d: bigint): Bytes => {
  return concatBytes(px, numTo32b(modN(k + e * d)));
}

const E_INVSIG = 'invalid signature produced';
/**
 * Creates Schnorr signature as per BIP340. Verifies itself before returning anything.
 * auxRand is optional and is not the sole source of k generation: bad CSPRNG won't be dangerous.
 */
const signSchnorr = (
  message: Bytes,
  privateKey: Bytes,
  auxRand: Bytes = randomBytes(L)
): Bytes => {
  const { m, px, d, a } = prepSigSchnorr(message, privateKey, auxRand);
  const aux = taggedHash(T_AUX, a);
  const t = numTo32b(d ^ bytesToNum(aux)); // Let t be the byte-wise xor of bytes(d) and hash/aux(a)
  const rand = taggedHash(T_NONCE, t, px, m); // Let rand = hash/nonce(t || bytes(P) || m)
  const { rx, k } = extractK(rand);
  const e = challenge(rx, px, m); // Let e = int(hash/challenge(bytes(R) || bytes(P) || m)) mod n.
  const sig = createSigSchnorr(k, rx, e, d);
  if (!verifySchnorr(sig, m, px)) err(E_INVSIG);
  return sig;
}
const signAsyncSchnorr = async (message: Bytes, privateKey: Bytes, auxRand: Bytes = randomBytes(L)): Promise<Bytes> => {
  const { m, px, d, a } = prepSigSchnorr(message, privateKey, auxRand);
  const aux = await taggedHashAsync(T_AUX, a);
  const t = numTo32b(d ^ bytesToNum(aux)); // Let t be the byte-wise xor of bytes(d) and hash/aux(a)
  const rand = await taggedHashAsync(T_NONCE, t, px, m); // Let rand = hash/nonce(t || bytes(P) || m)
  const { rx, k } = extractK(rand);
  const e = await challengeAsync(rx, px, m); // Let e = int(hash/challenge(bytes(R) || bytes(P) || m)) mod n.
  const sig = createSigSchnorr(k, rx, e, d);
  // If Verify(bytes(P), m, sig) (see below) returns failure, abort
  if (!(await verifyAsyncSchnorr(sig, m, px))) err(E_INVSIG);
  return sig;
}

const finishVerif = (P: Point, r: bigint, s: bigint, e: bigint) => {
  const { x, y } = mulG2uns(P, s, modN(-e)).aff(); // R = s⋅G - e⋅P
  if (!isEven(y) || x !== r) return false; // -eP == (n-e)P
  return true; // Fail if is_infinite(R) / not has_even_y(R) / x(R) ≠ r.
}

const verifSchnorr = (signature: Bytes, message: Bytes, publicKey: Bytes, sync = true): boolean | Promise<boolean> => {
  try {
    const sig = abytes(signature, L2);
    const msg = abytes(message);
    const pub = abytes(publicKey, L);
    // lift_x from BIP340. Convert 32-byte x coordinate to elliptic curve point.
    // Fail if x ≥ p. Let c = x³ + 7 mod p.
    const x = bytesToNum(pub);
    const y = lift_x(x); // Let y = c^(p+1)/4 mod p.
    // Return the unique point P such that x(P) = x and
    const P_ = new Point(x, isEven(y) ? y : M(-y), _1).ok(); // y(P) = y if y mod 2 = 0 or y(P) = p-y otherwise.
    // P = lift_x(int(pk)); fail if that fails
    const r = sliceBytesNum(sig, 0, L); // Let r = int(sig[0:32]); fail if r ≥ p.
    arange(r, _1, P);
    const s = sliceBytesNum(sig, L, L2); // Let s = int(sig[32:64]); fail if s ≥ n.
    arange(s, _1, N);
    const i = concatBytes(numTo32b(r), pointToBytes(P_), msg);
    if (sync) return finishVerif(P_, r, s, challenge(i)); // int(challenge(bytes(r)||bytes(P)||m))%n
    return challengeAsync(i).then(e => finishVerif(P_, r, s, e));
  } catch (error) {
    return false;
  }
}
// type VerifFn = typeof verifSchnorr;

/**
 * Verifies Schnorr signature.
 * Will swallow errors & return false except for initial type validation of arguments.
 */
const verifySchnorr = (s: Bytes, m: Bytes, p: Bytes): boolean =>
  verifSchnorr(s, m, p, true) as unknown as boolean;
const verifyAsyncSchnorr = async (s: Bytes, m: Bytes, p: Bytes): Promise<boolean> =>
  verifSchnorr(s, m, p, false) as unknown as Promise<boolean>;

const schnorr: {
  getPublicKey: typeof pubSchnorr;
  sign: typeof signSchnorr;
  verify: typeof verifySchnorr;
  signAsync: typeof signAsyncSchnorr;
  verifyAsync: typeof verifyAsyncSchnorr;
} = {
  getPublicKey: pubSchnorr,
  sign: signSchnorr,
  verify: verifySchnorr,
  signAsync: signAsyncSchnorr,
  verifyAsync: verifyAsyncSchnorr,
}

export {
  CURVE, etc, etc2,
  getPublicKey,
  getSharedSecret, Point, randomPrivateKey, recoverPublicKey,
  schnorr, sign, signAsync, Signature, utils, verify
};
