/*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
const B256 = 2n ** 256n;                                // secp256k1 is short weierstrass curve
const P = B256 - 2n ** 32n - 977n;                      // curve's field
const N = B256 - 0x14551231950b75fc4402da1732fc9bebfn;  // curve (group) order
const a = 0n;                                           // a equation's param
const b = 7n;                                           // b equation's param
const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n; // base point x
const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n; // base point y
export const CURVE = { P, n: N, a, b, Gx, Gy };
const fLen = 32;                                        // field/group byte length
const stdOpts: { lowS?: boolean; der?: boolean; extraEntropy?: any } = { lowS: true };
type Hex = Uint8Array | string;                         // accepted: bytes/hex
const bg = (n: any): n is bigint => typeof n === 'bigint'; // is big integer
const str = (s: any): s is string => typeof s === 'string';
const u8a = (content?: any) => new Uint8Array(content)  // creates Uint8Array byte arrays
const u8fr = (arr: any) => Uint8Array.from(arr);        // another shortcut
const fe = (n: bigint) => bg(n) && 0n < n && n < P;     // is field element
const ge = (n: bigint) => bg(n) && 0n < n && n < N;     // is group element
const crv = (x: bigint) => mod(mod(x * mod(x * x)) + a * x + b); // x³ + ax + b weierstrass formula
const err = (m = ''): never => { throw new Error(m); }; // throws error
const isBytes = (a: any, len?: number): Uint8Array => { // asserts Uint8Array
  if (!(a instanceof Uint8Array) || (typeof len === 'number' && len > 0 && a.length !== len)) err();
  return a;
};
const ensureBytes = (a: any, len?: number) => isBytes(str(a) ? h2b(a) : a, len);
const normPriv = (p: Hex | bigint): bigint => {         // normalize private key
  if (!bg(p)) p = b2n(ensureBytes(p, fLen));            // convert to bigint when bytes
  if (!ge(p)) err();                                    // check if bigint is in range
  return p;
};
const isPoint = (p: any) => (p instanceof Point ? p : err()); // is projective point
export class Point {                                    // Point in 3d xyz projective coords
  static readonly G = new Point(Gx, Gy, 1n);            // generator / base point
  static readonly I = new Point(0n, 1n, 0n);            // identity / zero point
  constructor(readonly x: bigint, readonly y: bigint, readonly z = 1n) {} // z is optional
  eql(other: Point): boolean {                          // equality check
    const { x: X1, y: Y1, z: Z1 } = this;
    const { x: X2, y: Y2, z: Z2 } = isPoint(other);     // isPoint() checks class equality
    return mod(X1 * Z2) === mod(X2 * Z1) && mod(Y1 * Z2) === mod(Y2 * Z1);
  }
  neg() { return new Point(this.x, mod(-this.y), this.z); } // creates negative version of the point
  dbl() { return this.add(this); }                      // point doubling
  add(other: Point) {                                   // addition, exception-free formula
    const { x: X1, y: Y1, z: Z1 } = this;               // from Renes-Costello-Batina
    const { x: X2, y: Y2, z: Z2 } = isPoint(other);
    let X3 = 0n, Y3 = 0n, Z3 = 0n;
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
  mul(n: bigint) {                                      // multiplies point by scalar n
    if (!ge(n)) err();                                  // n must be 0 < n < CURVE.n
    let p = Point.I; let f = Point.G                    // init identity / zero point & fake point
    for (let d: Point = this; n > 0n; d = d.dbl(), n >>= 1n) { // double-and-add ladder
      if (n & 1n) p = p.add(d); else; f = f.add(d);     // add to fake point when bit is not present
    }
    return p;
  }
  aff(): { x: bigint; y: bigint } {                     // converts point to 2d xy affine point
    const { x, y, z } = this;
    if (this.eql(Point.I)) return { x: 0n, y: 0n };     // fast-path for zero point
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
    if (mod(l - r) !== 0n) err();                       // y² = x³ + ax + b, must be equal
    return this;
  }
  static fromHex(hex: Hex): Point {                     // convert Uint8Array or hex string to Point
    hex = ensureBytes(hex);                             // converts hex string to Uint8Array
    let p: Point | undefined = undefined;
    const head = hex[0];                                // first byte serves as prefix
    const tail = hex.subarray(1);                       // the actual data
    const x = sliceNum(tail, 0, fLen);                  // next 32 bytes are x coordinate
    if (hex.length === 33 && [2, 3].includes(head)) {   // compressed points are 33 bytes & start
      if (!fe(x)) err();                                // with byte 0x02 or 0x03. Check if 0<x<P
      let y = sqrt(crv(x));                             // x³ + ax + b is right side of equation
      const isYOdd = (y & 1n) === 1n;                   // y² is equivalent left-side. Calculate y²:
      const isFirstByteOdd = (head & 1) === 1;          // y = √y²; there are two solutions: y, -y
      if (isFirstByteOdd !== isYOdd) y = mod(-y);       // determine proper solution
      p = new Point(x, y);                              // create 3d point
    }                                                   // Uncompressed points are 65 bytes & start
    if (hex.length === 65 && head === 4) p = new Point(x, sliceNum(tail, fLen, 2 * fLen));
    if (!p) err();                                      // with byte 0x04. Everything else: invalid
    return p!.ok();                                     // Check if the result is valid / on-curve
  }
  toHex(isCompressed = false) {                         // Converts point to hex string
    const { x, y } = this.aff();                        // Convert to 2d xy affine point
    const head = isCompressed ? ((y & 1n) === 0n ? '02' : '03') : '04'; // 0x02, 0x03, 0x04 prefix
    return `${head}${numToFieldStr(x)}${isCompressed ? '' : numToFieldStr(y)}`; // prefix||x and ||y
  }
  toRawBytes(isCompressed = false) {                    // Converts point to Uint8Array
    return h2b(this.toHex(isCompressed));               // Re-use toHex(), convert hex to bytes
  }
  static fromPrivateKey(n: bigint | Hex) {              // Create point from a private key. Multiply
    return Point.G.mul(normPriv(n));                    // base generator point by bigint(n)
  }
}
const G = Point.G;                                      // Generator point
const mod = (a: bigint, b = P) => { let r = a % b; return r >= 0n ? r : b + r; }; // mod division
const inv = (number: bigint, md = P): bigint => {       // modular inversion, euclidean gcd algo
  if (number === 0n || md <= 0n) err(`n=${number} mod=${md}`); // can be invalid
  let a = mod(number, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
  while (a !== 0n) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  if (b !== 1n) err('invert: does not exist');          // b is gcd at this point
  return mod(x, md);
};
const pow = (num: bigint, p: bigint, md: bigint): bigint => { // modular exponentiation num^p
  if (md <= 0n || p < 0n) err();                        // exponentiation by squaring
  if (md === 1n) return 0n;                             // the ladder can leak exponent bits
  let res = 1n;                                         // and is vulnerable to timing attacks
  for (; p > 0n; p >>= 1n) {
    if (p & 1n) res = (res * num) % md;
    num = (num * num) % md;
  }
  return res;
};
const sqrt = (n: bigint) => {                           // √(y) = y^((p+1)/4) for fields P = 3 mod 4
  const r = pow(n, (P + 1n) / 4n, P);                   // So, a special, fast case. Paper: "Square
  return mod(r * r) === n ? r : err();                  // Roots from 1;24,51,10 to Dan Shanks"
}
const b2h = (uint8a: Uint8Array): string => {           // bytes to hex string. Every uint8array
  isBytes(uint8a);                                      // item is number [0, 255]
  let hex = '';                                         // convert number to hex string & pad with 0
  for (let i = 0; i < uint8a.length; i++) hex += uint8a[i].toString(16).padStart(2, '0');
  return hex;                                           // byte 2 will become 02, etc
};                                                      // hex to number
const h2n = (hex: string): bigint => (str(hex) ? BigInt(`0x${hex}`) : err());
const h2b = (hex: string): Uint8Array => {              // hex to bytes. error if not string,
  if (!str(hex) || hex.length % 2) err();               // or has odd length like 3, 5
  const array = u8a(hex.length / 2);                    // create result array
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    const hexByte = hex.slice(j, j + 2);                // substr seems slower
    const byte = Number.parseInt(hexByte, 16);          // parse every string part, convert to
    if (Number.isNaN(byte) || byte < 0) err();          // Number. Error if NaN or < 0
    array[i] = byte;
  }
  return array;
};
const b2n = (b: Uint8Array): bigint => h2n(b2h(b));     // bytes to number
const sliceNum = (b: Uint8Array, from: number, to: number) => b2n(b.slice(from, to)); // slice bytes
const n2b = (num: bigint): Uint8Array => {              // number to bytes
  if (!bg(num) || num < 0n || num >= B256) err();       // must be 0 <= num < B256
  return h2b(num.toString(16).padStart(2 * fLen, '0'));
};
const numToFieldStr = (num: bigint): string => b2h(n2b(num));
const catBytes = (...arrays: Uint8Array[]) => {         // concatenate Uint8Array-s
  arrays.every((b) => isBytes(b));
  if (arrays.length === 1) return arrays[0];
  const length = arrays.reduce((a, arr) => a + arr.length, 0);
  const result = u8a(length);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const arr = arrays[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
};

const bits2int_2 = (bytes: Uint8Array) => {             // bytes to bigint
  const delta = bytes.length * 8 - 256;                 // truncates bits
  const num = b2n(bytes);
  return delta > 0 ? num >> BigInt(delta) : num;
};
const truncH = (hash: Uint8Array): bigint => {          // truncate hash
  const h = bits2int_2(hash);
  return h >= N ? h - N : h;
};
const moreThanHalf = (n: bigint) => {                   // if a number is bigger than CURVE.n/2
  const h = N >> 1n;
  return n > h;
};

export const getPublicKey = (privKey: Hex | bigint, isCompressed = false) => { // calculate public
  return Point.fromPrivateKey(privKey).toRawBytes(isCompressed);               // key from private
};
export class Signature {                                // calculates signature
  constructor(readonly r: bigint, readonly s: bigint, readonly rec?: number) {
    this.ok();
  }
  ok(): Signature {                                     // validates signature
    if (!ge(this.r)) err();                             // 0 < r < CURVE.n
    if (!ge(this.s)) err();                             // 0 < s < CURVE.n
    return this;
  }
  static fromCompact(hex: Hex) {                        // create signature from 64b compact repr
    hex = ensureBytes(hex, 64);                         // compact repr is (32-byte r)+(32-byte s)
    return new Signature(sliceNum(hex, 0, fLen), sliceNum(hex, fLen, 2 * fLen));
  }
  static fromKMD(kBytes: Uint8Array, m: bigint, d: bigint, lowS?: boolean): Signature | undefined {
    const k = bits2int_2(kBytes);                       // Utility method for RFC6979 k generation
    if (!ge(k)) return;                                 // Check 0 < k < CURVE.n
    const ik = inv(k, N);                               // k^-1 over CURVE.n, NOT CURVE.P
    const q = G.mul(k).aff();                           // q = Gk
    const r = mod(q.x, N);                              // r = q.x mod CURVE.n
    if (r === 0n) return;                               // invalid
    const s = mod(ik * mod(m + mod(d * r, N), N), N);   // s = k^-1 * m + dr mod CURVE.n
    if (s === 0n) return;                               // invalid
    let normS = s;                                      // normalized s
    let rec = (q.x === r ? 0 : 2) | Number(q.y & 1n);   // recovery bit
    if (lowS && moreThanHalf(s)) {                      // if option lowS was passed,
      normS = mod(-s, N);                               // ensure s is always in the bottom half
      rec ^= 1;                                         // of CURVE.n
    }
    return new Signature(r, normS, rec);
  }
  toCompactRawBytes() { return h2b(this.toCompactHex()); } // Uint8Array 64b compact repr
  toCompactHex() { return numToFieldStr(this.r) + numToFieldStr(this.s); } // hex 64b compact repr
}
const b2i = (b: Uint8Array): bigint => {                // RFC6979 methods: bytes to int
  isBytes(b);
  const sl = b.length > fLen ? b.slice(0, fLen) : b;    // slice
  return b2n(sl);                                       // call our own method
};
const b2o = (bytes: Uint8Array): Uint8Array => {        // bits to octets
  const z1 = b2i(bytes);
  const z2 = mod(z1, N);
  return i2o(z2 < 0n ? z1 : z2);
};
const i2o = (num: bigint): Uint8Array => n2b(num);      // int to octets
declare const self: Record<string, any> | undefined; // Typescript global symbol available in
const cr: { node?: any; web?: any } = { // browsers only. Ensure no dependence on @types/dom
  node: typeof require === 'function' && require('crypto'), // node.js require('crypto')
  web: typeof self === 'object' && 'crypto' in self ? self.crypto : undefined, // browser-only var
};
const hmac = async (key: Uint8Array, ...messages: Uint8Array[]): Promise<Uint8Array> => {
  const msgs = catBytes(...messages);                   // HMAC-SHA256
  if (cr.web) {                                         // browser built-in version
    // prettier-ignore
    const ckey = await cr.web.subtle.importKey(
      'raw', key, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign']
    );
    return u8a(await cr.web.subtle.sign('HMAC', ckey, msgs));
  } else if (cr.node) {                                 // node.js built-in version
    return u8fr(cr.node.createHmac('sha256', key).update(msgs).digest());
  } else {
    throw new Error('crypto required');
  }
};
const randomBytes = (bytesLength: number): Uint8Array => { // CSPRNG: secure generator
  if (cr.web) {                                         // browser built-in version
    return cr.web.getRandomValues(u8a(bytesLength));
  } else if (cr.node) {                                 // node.js built-in version
    return u8fr(cr.node.randomBytes(bytesLength));
  } else {
    throw new Error('crypto required');                 // error when no CSPRNG
  }
};
class HmacDrbg {                                        // Minimal HMAC-DRBG (NIST 800-90)
  k: Uint8Array;                                        // used only for RFC6979 signatures.
  v: Uint8Array;
  counter: number;
  constructor() {                                       // Step B, Step C: set hashLen
    this.v = u8a(fLen).fill(1);                         // to 8*ceil(hlen/8)
    this.k = u8a(fLen).fill(0);
    this.counter = 0;
  }
  async seed(seed = u8a()) {                            // DRBG reseed() function
    const hk = (...vs: Uint8Array[]) => hmac(this.k, ...vs); // hmac(k)(...values)
    const hv = (...vs: Uint8Array[]) => hk(this.v, ...vs);  // hmac(k)(v, ...values)
    this.k = await hv(u8fr([0x00]), seed);
    this.v = await hv();
    if (seed.length === 0) return;
    this.k = await hv(u8fr([0x01]), seed);
    this.v = await hv();
  }
  async gen(): Promise<Uint8Array> {                    // DRBG generate() function
    if (this.counter >= 1000) err();                    // Something is wrong if counter is 1k
    this.counter += 1;
    this.v = await hmac(this.k, this.v);
    return this.v;
  }
}
export const sign = async (msgHash: Hex, privKey: Hex, opts = stdOpts): Promise<Signature> => {
  if (opts?.der === true) err();                        // RFC6979 ECDSA signature generation
  if (opts?.extraEntropy) err();                        // extraEntropy is not supported
  if (opts?.lowS == null) opts.lowS = true;             // generates low-s sigs by default
  const _h1 = n2b(truncH(ensureBytes(msgHash)));        // Steps A, D of RFC6979 3.2.
  const d = normPriv(privKey);                          // d = normalize(privatekey)
  if (!ge(d)) err();                                    // redundant check
  const seedArgs = [i2o(d), b2o(_h1)];                  // seed args for drbg
  const seed = catBytes(...seedArgs);
  const m = b2i(_h1);                                   // convert msg to bigint
  const drbg = new HmacDrbg();                          // Steps B,C,D,E,F,G of RFC6979 3.2.
  await drbg.seed(seed);                                // Reseed DRBG. Then Step H3:
  let sig: Signature | undefined;                       // reseed until k is in range [1, n-1]
  while (!(sig = Signature.fromKMD(await drbg.gen(), m, d, !!opts?.lowS))) await drbg.seed();
  return sig;
}

type Sig = Hex | Signature;                             // signature verification
export const verify = (sig: Sig, msgHash: Hex, pubKey: Hex, opts = stdOpts): boolean => {
  if (opts?.lowS == null) opts.lowS = true;             // lowS=true default
  let sig_: Signature;             // Implements section 4.1.4 from https://www.secg.org/sec1-v2.pdf
  try {                            // verify(r, s, h, P) where u1 = hs^-1 mod n, u2 = rs^-1 mod n,
    sig_ = sig instanceof Signature ? sig.ok() : Signature.fromCompact(sig);
  } catch (error) { return false; } // R = U1⋅G - U2⋅P, mod(R.x, n) == r
  if (!sig_) return false;
  const { r, s } = sig_;
  if (opts?.lowS && moreThanHalf(s)) return false;      // lowS=true bans sig.s >= CURVE.n/2
  const h = truncH(ensureBytes(msgHash, fLen));         // truncate hash
  let P: Point;
  try {                                                 // Validate public key
    P = pubKey instanceof Point ? pubKey.ok() : Point.fromHex(pubKey);
  } catch (error) { return false; }
  let R: { x: bigint; y: bigint } | undefined = undefined;
  try {
    const is = inv(s, N);                               // s^-1
    const u1 = mod(h * is, N);                          // u1 = hs^-1 mod n
    const u2 = mod(r * is, N);                          // u2 = rs^-1 mod n
    R = G.mul(u1).add(P.mul(u2))?.aff();                // R = u1⋅G + u2⋅P
  } catch (error) { return false; }
  if (!R || R.x === 0n || R.y === 0n) return false;     // stop if R is identity / zero point
  const v = mod(R.x, N);
  return v === r;                                       // mod(R.x, n) == r
}
export const getSharedSecret = (privA: Hex, pubB: Hex, isCompressed?: boolean) => {
  return Point.fromHex(pubB).mul(normPriv(privA)).toRawBytes(isCompressed);
};
const hashToPrivateKey = (hash: Hex): Uint8Array => {   // FIPS 186 B.4.1 compliant key generation
  hash = ensureBytes(hash);                             // produces private keys with modulo bias
  const minLen = fLen + 8;                              // being neglible.
  if (hash.length < minLen || hash.length > 1024) err();
  const num = mod(b2n(hash), N - 1n) + 1n;              // takes at least n+8 bytes
  return n2b(num);
};
export const utils = {                                  // utilities
  mod, invert: inv,                                     // math utilities
  concatBytes: catBytes, hexToBytes: h2b, bytesToHex: b2h, bytesToNumber: b2n, numToField: n2b,
  hashToPrivateKey, randomBytes,                        // CSPRNG etc.
  randomPrivateKey: (): Uint8Array => hashToPrivateKey(randomBytes(fLen + 8)), // FIPS 186 B.4.1.
  isValidPrivateKey: (key: Hex) => {                    // checks if private key is valid
    try {
      return !!normPriv(key);
    } catch (e) {
      return false;
    }
  },
};
