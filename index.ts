/*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
const B256 = 2n ** 256n;                                // secp256k1 is short weierstrass curve
const P = B256 - 2n ** 32n - 977n;                      // curve's field
const N = B256 - 0x14551231950b75fc4402da1732fc9bebfn;  // curve (group) order
const a = 0n;                                           // a equation's param
const b = 7n;                                           // b equation's param
const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n; // base point x
const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n; // base point y
const CURVE = { P, n: N, a, b, Gx, Gy };                // Variables
const fLen = 32;                                        // field / group byte length
const stdo: { lowS?: boolean; der?: boolean; extraEntropy?: any; recovered?: any } = { lowS: true };
type Bytes = Uint8Array; type Hex = Bytes | string;     // accepted inputs: bytes/hex
const big = (n: any): n is bigint => typeof n === 'bigint'; // is big integer
const str = (s: any): s is string => typeof s === 'string'; // is string
const fe = (n: bigint) => big(n) && 0n < n && n < P;    // is field element
const ge = (n: bigint) => big(n) && 0n < n && n < N;    // is group element
const u8a = (content?: any) => new Uint8Array(content); // creates Uint8Array
const u8fr = (arr: any) => Uint8Array.from(arr);        // another shortcut
const crv = (x: bigint) => mod(mod(x * mod(x * x)) + a * x + b); // x³ + ax + b weierstrass formula
const err = (m = ''): never => { throw new Error(m); }; // throws error, slightly messes stack trace
const isU8 = (a: any, len?: number): Bytes => {         // is Uint8Array (of specific length)
  if (!(a instanceof Uint8Array) || (typeof len === 'number' && len > 0 && a.length !== len)) err();
  return a;
};
const toU8 = (a: any, len?: number) => isU8(str(a) ? h2b(a) : a, len);  // (hex or ui8a) to ui8a
const toPriv = (p: Hex | bigint): bigint => {           // normalize private key
  if (!big(p)) p = b2n(toU8(p, fLen));                  // convert to bigint when bytes
  return ge(p) ? p : err();                             // check if bigint is in range
};
const isPoint = (p: any) => (p instanceof Point ? p : err()); // is 3d point
let Gprec: Point[] | undefined = undefined;             // Precomputes for base point G
class Point {                                           // Point in 3d xyz projective coords
  static readonly G = new Point(Gx, Gy, 1n);            // generator / base point
  static readonly I = new Point(0n, 1n, 0n);            // identity / zero point
  constructor(readonly x: bigint, readonly y: bigint, readonly z = 1n) {} // z is optional
  eql(other: Point): boolean {                          // equality check
    const { x: X1, y: Y1, z: Z1 } = this;
    const { x: X2, y: Y2, z: Z2 } = isPoint(other);     // isPoint() checks class equality
    return mod(X1 * Z2) === mod(X2 * Z1) && mod(Y1 * Z2) === mod(Y2 * Z1);
  }
  neg() { return new Point(this.x, mod(-this.y), this.z); } // negate, flips point over y coord
  dbl() { return this.add(this); }                      // point doubling
  add(other: Point) {                                   // point addition: complete, exception-free
    const { x: X1, y: Y1, z: Z1 } = this;               // formula from Renes-Costello-Batina
    const { x: X2, y: Y2, z: Z2 } = isPoint(other);     // https://eprint.iacr.org/2015/1060, algo 1
    let X3 = 0n, Y3 = 0n, Z3 = 0n;                      // Cost: 12M + 0S + 3*a + 3*b3 + 23add
    const b3 = mod(b * 3n);
    let t0 = mod(X1 * X2), t1 = mod(Y1 * Y2), t2 = mod(Z1 * Z2), t3 = mod(X1 + Y1); // step 1
    let t4 = mod(X2 + Y2);                              // step 5
    t3 = mod(t3 * t4); t4 = mod(t0 + t1); t3 = mod(t3 - t4); t4 = mod(X1 + Z1);
    let t5 = mod(X2 + Z2);                              // step 10
    t4 = mod(t4 * t5); t5 = mod(t0 + t2); t4 = mod(t4 - t5); t5 = mod(Y1 + Z1);
    X3 = mod(Y2 + Z2);                                  // step 15
    t5 = mod(t5 * X3); X3 = mod(t1 + t2); t5 = mod(t5 - X3); Z3 = mod(a * t4);
    X3 = mod(b3 * t2);                                  // step 20
    Z3 = mod(X3 + Z3); X3 = mod(t1 - Z3); Z3 = mod(t1 + Z3); Y3 = mod(X3 * Z3);
    t1 = mod(t0 + t0);                                  // step 25
    t1 = mod(t1 + t0); t2 = mod(a * t2); t4 = mod(b3 * t4); t1 = mod(t1 + t2);
    t2 = mod(t0 - t2);                                  // step 30
    t2 = mod(a * t2); t4 = mod(t4 + t2); t0 = mod(t1 * t4); Y3 = mod(Y3 + t0);
    t0 = mod(t5 * t4);                                  // step 35
    X3 = mod(t3 * X3); X3 = mod(X3 - t0); t0 = mod(t3 * t1); Z3 = mod(t5 * Z3);
    Z3 = mod(Z3 + t0);                                  // step 40
    return new Point(X3, Y3, Z3);
  }
  mul(n: bigint, safe = true) {                         // multiply point by scalar n
    if (!safe && n === 0n) return I;                    // In unsafe mode, allow zero
    if (!ge(n)) err();                                  // must be 0 < n < CURVE.n
    if (Gprec && this.eql(G)) return wNAF(n).p;         // if base point, use precomputes
    let p = I, f = G;                                   // init result point & fake point
    for (let d: Point = this; n > 0n; d = d.dbl(), n >>= 1n) { // double-and-add ladder
      if (n & 1n) p = p.add(d);                         // if bit is present, add to point
      else if (safe) f = f.add(d);                      // if not, add to fake for timing safety
    }
    return p;
  }
  mulAddQUns(R: Point, u1: bigint, u2: bigint) {        // Q = u1⋅G + u2⋅R: double scalar mult.
    return this.mul(u1, false).add(R.mul(u2, false)).ok(); // Unsafe: do NOT use for stuff related
  }                                                     // to private keys. Doesn't use Shamir trick
  aff(): { x: bigint; y: bigint } {                     // converts point to 2d xy affine point
    const { x, y, z } = this;
    if (this.eql(I)) return { x: 0n, y: 0n };           // fast-path for zero point
    if (z === 1n) return { x, y };                      // if z is 1, pass affine coordinates as-is
    const iz = inv(z);                                  // z^-1: invert z
    if (mod(z * iz) !== 1n) err();                      // (z * z^-1) must be 1, otherwise bad math
    return { x: mod(x * iz), y: mod(y * iz) };          // x = x*z^-1; y = y*z^-1
  }
  ok(): Point {                                         // checks if the point is valid and on-curve
    const { x, y } = this.aff();                        // convert to 2d xy affine point
    if (!fe(x) || !fe(y)) err();                        // x and y must be in range 0 < n < P
    const l = mod(y * y);                               // y²
    const r = crv(x);                                   // x³ + ax + b
    return mod(l - r) === 0n ? this : err();            // y² = x³ + ax + b, must be equal
  }
  static fromHex(hex: Hex): Point {                     // convert Uint8Array or hex string to Point
    hex = toU8(hex);                                    // converts hex string to Uint8Array
    let p: Point | undefined = undefined;
    const head = hex[0], tail = hex.subarray(1);        // first byte is prefix, rest is data
    const x = slcNum(tail, 0, fLen), len = hex.length;  // next 32 bytes are x coordinate
    if (len === 33 && [2, 3].includes(head)) {          // Compressed points: 33b, start
      if (!fe(x)) err();                                // with byte 0x02 or 0x03. Check if 0<x<P
      let y = sqrt(crv(x));                             // x³ + ax + b is right side of equation
      const isYOdd = (y & 1n) === 1n;                   // y² is equivalent left-side. Calculate y²:
      const headOdd = (head & 1) === 1;                 // y = √y²; there are two solutions: y, -y
      if (headOdd !== isYOdd) y = mod(-y);              // determine proper solution
      p = new Point(x, y);                              // create 3d point
    }                                                   // Uncompressed points: 65b, start with 0x04
    if (len === 65 && head === 4) p = new Point(x, slcNum(tail, fLen, 2 * fLen));
    return p ? p.ok() : err();                          // Check if the result is valid / on-curve
  }
  toHex(isCompressed = false) {                         // Converts point to hex string
    const { x, y } = this.aff();                        // Convert to 2d xy affine point
    const head = isCompressed ? ((y & 1n) === 0n ? '02' : '03') : '04'; // 0x02, 0x03, 0x04 prefix
    return `${head}${n2h(x)}${isCompressed ? '' : n2h(y)}`; // prefix||x and ||y
  }
  toRawBytes(isCompressed = false) {                    // Converts point to Uint8Array
    return h2b(this.toHex(isCompressed));               // Re-use toHex(), convert hex to bytes
  }
  static fromPrivateKey(n: bigint | Hex) {              // Create point from a private key. Multiply
    return G.mul(toPriv(n));                            // base point by bigint(n)
  }
}
const { G, I } = Point;                                 // Generator, identity points
const mod = (a: bigint, b = P) => { let r = a % b; return r >= 0n ? r : b + r; }; // mod division
const inv = (num: bigint, md = P): bigint => {          // modular inversion
  if (num === 0n || md <= 0n) err(`n=${num} mod=${md}`);// can be invalid
  let a = mod(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
  while (a !== 0n) {                                    // uses euclidean gcd algorithm
    const q = b / a, r = b % a;                         // not constant-time
    const m = x - u * q, n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  return b === 1n ? mod(x, md) : err('invert does not exist'); // b is gcd at this point
};
const pow = (num: bigint, e: bigint, md = P): bigint => { // modular exponentiation num^e
  if (md <= 0n || e < 0n) err();                        // exponentiation by squaring
  if (md === 1n) return 0n;                             // the ladder can leak exponent bits
  let res = 1n;                                         // and is vulnerable to timing attacks
  for (; e > 0n; e >>= 1n) {
    if (e & 1n) res = (res * num) % md;
    num = (num * num) % md;
  }
  return res;
};
const sqrt = (n: bigint) => {                           // √(n) = n^((p+1)/4) for fields P = 3 mod 4
  const r = pow(n, (P + 1n) / 4n, P);                   // So, a special, fast case. Paper: "Square
  return mod(r * r) === n ? r : err();                  // Roots from 1;24,51,10 to Dan Shanks"
}
const padh = (num: number | bigint, pad: number) => num.toString(16).padStart(pad, '0')
const b2h = (b: Bytes): string => Array.from(b).map(e => padh(e, 2)).join(''); // bytes to hex
const h2n = (hex: string): bigint => (str(hex) ? BigInt(`0x${hex}`) : err());  // hex to number
const h2b = (hex: string): Bytes => {                   // hex to bytes
  const l = hex.length;                                 // error if not string,
  if (!str(hex) || l % 2) err();                        // or has odd length like 3, 5.
  const arr = u8a(l / 2);                               // create result array
  for (let i = 0; i < arr.length; i++) {
    const j = i * 2;
    const h = hex.slice(j, j + 2);                      // hexByte. slice is faster than substr
    const b = Number.parseInt(h, 16);                   // byte, created from string part
    if (Number.isNaN(b) || b < 0) err();                // byte must be valid 0 <= byte < 256
    arr[i] = b;
  }
  return arr;
};
const b2n = (b: Bytes): bigint => h2n(b2h(b));          // bytes to number
const slcNum = (b: Bytes, from: number, to: number) => b2n(b.slice(from, to)); // slice bytes
const n2b = (num: bigint): Bytes => {                   // number to bytes. must be 0 <= num < B256
  return big(num) && num >= 0n && num < B256 ? h2b(padh(num, 2 * fLen)) : err();
};
const n2h = (num: bigint): string => b2h(n2b(num));     // number to hex
const concat = (...list: Bytes[]) => {                  // concatenate Uint8Array-s
  let pad = 0;
  const res = u8a(list.reduce((sum, arr) => sum + arr.length, 0));
  list.forEach(arr => { res.set(isU8(arr), pad); pad += arr.length; });
  return res;
};

const bits2int_2 = (bytes: Bytes) => {                  // bytes to bigint
  const delta = bytes.length * 8 - 256;                 // truncates bits
  const num = b2n(bytes);
  return delta > 0 ? num >> BigInt(delta) : num;
};
const truncH = (hash: Bytes): bigint => {               // truncate hash
  const h = bits2int_2(hash);
  return h >= N ? h - N : h;
};
const moreThanHalf = (n: bigint) => {                   // if a number is bigger than CURVE.n/2
  const h = N >> 1n;
  return n > h;
};

const getPublicKey = (privKey: Hex | bigint, isCompressed = false) => { // calculate public
  return Point.fromPrivateKey(privKey).toRawBytes(isCompressed);        // key from private
};
class Signature {                                       // calculates signature
  constructor(readonly r: bigint, readonly s: bigint, readonly rec?: number) { this.ok(); }
  ok(): Signature { return ge(this.r) && ge(this.s) ? this : err(); } // 0 < r or s < CURVE.n
  static fromCompact(hex: Hex) {                        // create signature from 64b compact repr
    hex = toU8(hex, 64);                                // compact repr is (32b r)||(32b s)
    return new Signature(slcNum(hex, 0, fLen), slcNum(hex, fLen, 2 * fLen));
  }
  static fromKMD(kBytes: Bytes, m: bigint, d: bigint, lowS?: boolean): Signature | undefined {
    const k = bits2int_2(kBytes);                       // Utility method for RFC6979 k generation
    if (!ge(k)) return;                                 // Check 0 < k < CURVE.n
    const ik = inv(k, N);                               // k^-1 mod n, NOT mod P
    const q = G.mul(k).aff();                           // q = Gk
    const r = mod(q.x, N);                              // r = q.x mod n
    if (r === 0n) return;                               // invalid
    const s = mod(ik * mod(m + mod(d * r, N), N), N);   // s = k^-1 * m + dr mod n
    if (s === 0n) return;                               // invalid
    let normS = s;                                      // normalized s
    let rec = (q.x === r ? 0 : 2) | Number(q.y & 1n);   // recovery bit
    if (lowS && moreThanHalf(s)) {                      // if option lowS was passed,
      normS = mod(-s, N);                               // ensure s is always in the bottom half
      rec ^= 1;                                         // of CURVE.n
    }
    return new Signature(r, normS, rec);
  }
  recoverPublicKey(msgHash: Hex): Point {
    const { r, s, rec } = this;
    if (rec == null || ![0, 1, 2, 3].includes(rec)) err();
    const h = truncH(toU8(msgHash));
    const radj = rec === 2 || rec === 3 ? r + N : r;
    if (radj >= P) err();
    const ir = inv(radj, N);
    const R = Point.fromHex(`${(rec! & 1) === 0 ? '02' : '03'}${n2h(radj)}`);
    const u1 = mod(-h * ir, N);
    const u2 = mod(s * ir, N);
    return G.mulAddQUns(R, u1, u2); // Q = u1⋅G + u2⋅R
  }
  toCompactRawBytes() { return h2b(this.toCompactHex()); } // Uint8Array 64b compact repr
  toCompactHex() { return n2h(this.r) + n2h(this.s); }  // hex 64b compact repr
}
const b2i = (b: Bytes): bigint => {                     // RFC6979 bytes to int
  isU8(b);
  const sl = b.length > fLen ? b.slice(0, fLen) : b;    // slice
  return b2n(sl);                                       // call our own method
};
const b2o = (bytes: Bytes): Bytes => {                  // RFC6979 bits to octets
  const z1 = b2i(bytes);
  const z2 = mod(z1, N);
  return i2o(z2 < 0n ? z1 : z2);
};
const i2o = (num: bigint): Bytes => n2b(num);           // int to octets
declare const self: Record<string, any> | undefined;    // Typescript global symbol available in
const cr: { node?: any; web?: any } = {     // browsers only. Ensure no dependence on @types/dom
  node: typeof require === 'function' && require('crypto'), // node.js require('crypto')
  web: typeof self === 'object' && 'crypto' in self ? self.crypto : undefined, // browser-only var
};
const hmac = async (key: Bytes, ...messages: Bytes[]): Promise<Bytes> => {
  const msgs = concat(...messages);                     // HMAC-SHA256
  if (cr.web) {                                         // browser built-in version
    const s = cr.web.subtle;
    const k = await s.importKey('raw', key, {name:'HMAC',hash:{name:'SHA-256'}}, false, ['sign']);
    return u8a(await s.sign('HMAC', k, msgs));
  } else if (cr.node) {                                 // node.js built-in version
    return u8fr(cr.node.createHmac('sha256', key).update(msgs).digest());
  } else {
    throw new Error('crypto required');
  }
};
const randomBytes = (len: number): Bytes => {   // CSPRNG: secure generator
  return cr.web ? cr.web.getRandomValues(u8a(len)) :
    cr.node ? u8fr(cr.node.randomBytes(len)) : err('crypto required');
};
class HmacDrbg {                                        // Minimal HMAC-DRBG (NIST 800-90)
  private k: Bytes;                                     // used only for RFC6979 signatures.
  private v: Bytes;                                     // Does not implement full spec.
  private i: number;                                    // counter variable
  constructor() {                                       // Step B, Step C: set hashLen
    this.v = u8a(fLen).fill(1); this.k = u8a(fLen).fill(0); // to 8*ceil(hlen/8)
    this.i = 0;
  }
  async seed(seed = u8a()) {                            // DRBG reseed() function
    const h = (...vs: Bytes[]) => hmac(this.k, this.v, ...vs); // hmac(k)(v, ...values)
    this.k = await h(u8fr([0x00]), seed); this.v = await h();
    if (seed.length === 0) return;
    this.k = await h(u8fr([0x01]), seed); this.v = await h();
  }
  async gen(): Promise<Bytes> {                         // DRBG generate() function
    if (this.i >= 1000) err();                          // Something is wrong if counter is 1k
    this.i += 1;
    this.v = await hmac(this.k, this.v);
    return this.v;
  }
}
const sign = async (msgh: Hex, priv: Hex, opts = stdo): Promise<Signature> => {  // RFC6979 ECDSA
  if (opts?.der === true || opts?.extraEntropy || opts?.recovered) err(); // signature generation
  if (opts?.lowS == null) opts.lowS = true;             // generates low-s sigs by default
  const h1 = n2b(truncH(toU8(msgh)));                   // Steps A, D of RFC6979 3.2.
  const d = toPriv(priv);                               // d = normalize(privatekey)
  const seed = concat(i2o(d), b2o(h1));                 // seed args for drbg
  const m = b2i(h1);                                    // convert msg to bigint
  const drbg = new HmacDrbg();                          // Steps B,C,D,E,F,G of RFC6979 3.2.
  await drbg.seed(seed);                                // Reseed DRBG. Then Step H3:
  let sig: Signature | undefined;                       // reseed until k is in range [1, n-1]
  while (!(sig = Signature.fromKMD(await drbg.gen(), m, d, !!opts?.lowS))) await drbg.seed();
  return sig;
}

type Sig = Hex | Signature;                             // ECDSA signature verification
const verify = (sig: Sig, msgh: Hex, pub: Hex, opts = stdo): boolean => {
  if (opts?.lowS == null) opts.lowS = true;             // lowS=true default
  let sig_: Signature;             // Implements section 4.1.4 from https://www.secg.org/sec1-v2.pdf
  try {                            // verify(r, s, h, P) where u1 = hs^-1 mod n, u2 = rs^-1 mod n,
    sig_ = sig instanceof Signature ? sig.ok() : Signature.fromCompact(sig);
  } catch (error) { return false; } // R = U1⋅G - U2⋅P, mod(R.x, n) == r
  if (!sig_) return false;
  const { r, s } = sig_;
  if (opts?.lowS && moreThanHalf(s)) return false;      // lowS=true bans sig.s >= CURVE.n/2
  const h = truncH(toU8(msgh, fLen));                     // truncate hash
  let P: Point;
  try {                                                 // Validate public key
    P = pub instanceof Point ? pub.ok() : Point.fromHex(pub);
  } catch (error) { return false; }
  let R: { x: bigint, y: bigint } | undefined = undefined;
  try {
    const is = inv(s, N);                               // s^-1
    const u1 = mod(h * is, N);                          // u1 = hs^-1 mod n
    const u2 = mod(r * is, N);                          // u2 = rs^-1 mod n
    R = G.mulAddQUns(P, u1, u2).aff();                  // R = u1⋅G + u2⋅P
  } catch (error) { return false; }
  if (!R) return false;                                 // stop if R is identity / zero point
  const v = mod(R.x, N);
  return v === r;                                       // mod(R.x, n) == r
}
const getSharedSecret = (privA: Hex, pubB: Hex, isCompressed?: boolean) => {
  return Point.fromHex(pubB).mul(toPriv(privA)).toRawBytes(isCompressed);
};
const hashToPrivateKey = (hash: Hex): Bytes => {        // FIPS 186 B.4.1 compliant key generation
  hash = toU8(hash);                                    // produces private keys with modulo bias
  const minLen = fLen + 8;                              // being neglible.
  if (hash.length < minLen || hash.length > 1024) err();
  const num = mod(b2n(hash), N - 1n) + 1n;              // takes at least n+8 bytes
  return n2b(num);
};
const utils = {                                         // utilities
  mod, invert: inv,                                     // math utilities
  concatBytes: concat, hexToBytes: h2b, bytesToHex: b2h, bytesToNumber: b2n, numToField: n2b,
  randomBytes, hashToPrivateKey,                        // CSPRNG etc.
  randomPrivateKey: (): Bytes => hashToPrivateKey(randomBytes(fLen + 8)), // FIPS 186 B.4.1.
  isValidPrivateKey: (key: Hex) => {                    // checks if private key is valid
    try {
      return !!toPriv(key);
    } catch (e) {
      return false;
    }
  },
};
const W = 8;                                            // Precomputes-related code. W = window size
const precompute = () => {                              // They give 12x faster getPublicKey(),
  const points: Point[] = [], wins = 256 / W + 1;       // 10x sign(), 2x verify(). To achieve this,
  let p = G, b = p;                                     // app needs to spend 40ms+ to calculate
  for (let w = 0; w < wins; w++) {                      // 65536 points related to base point G
    b = p;                                              // Points are stored in array and used
    points.push(b);                                     // any time Gx multiplication is done.
    for (let i = 1; i < 2 ** (W - 1); i++) { b = b.add(p); points.push(b); }
    p = b.dbl();                                        // Precomputes do not speed-up getSharedKey,
  }                                                     // which multiplies user point by scalar,
  return points;                                        // when precomputes are using base point
}
const wNAF = (n: bigint): { p: Point; f: Point } => {   // w-ary non-adjacent form (wNAF) method
  if (256 % W) err();                                   // Compared to other point mult methods,
  let comp = Gprec;                                     // allows to store 2x less points by
  if (!comp) err();                                     // using subtraction.
  comp = comp!;
  let p = I, f = G;                                     // f must be G, or could become I in the end
  const wins = 1 + 256 / W;                             // W=8 17 windows
  const wsize = 2 ** (W - 1);                           // W=8 128 window size
  const mask = BigInt(2 ** W - 1);                      // W=8 will create mask 0b11111111
  const maxNum = 2 ** W;                                // W=8 256
  const shiftBy = BigInt(W);                            // W=8 8
  for (let w = 0; w < wins; w++) {
    const off = w * wsize;
    let wbits = Number(n & mask);                       // extract W bits.
    n >>= shiftBy;                                      // shift number by W bits.
    if (wbits > wsize) { wbits -= maxNum; n += 1n; }    // split if bits>max: +224 => 256-32
    const off1 = off, off2 = off + Math.abs(wbits) - 1; // offsets
    const cond1 = w % 2 !== 0, cond2 = wbits < 0;       // conditions
    const neg = (bool: boolean, item: Point) => bool ? item.neg() : item; // negate
    if (wbits === 0) {
      f = f.add(neg(cond1, comp[off1]));                // bit is 0: add garbage to fake point
    } else {
      p = p.add(neg(cond2, comp[off2]));                // bit is 1: add to result point
    }
  }
  return { p, f }                                       // return both real and fake points for JIT
};
Gprec = precompute();                  // <= you can disable precomputes by commenting-out the line
export { getPublicKey, sign, verify, getSharedSecret, CURVE, Point, Signature, utils };
