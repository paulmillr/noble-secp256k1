/*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
/**
 * 5KB JS implementation of secp256k1 ECDSA / Schnorr signatures & ECDH.
 * Compliant with RFC6979 & BIP340.
 * @module
 */
/**
 * Curve params. secp256k1 is short weierstrass / koblitz curve. Equation is y² == x³ + ax + b.
 * * P = `2n**256n-2n**32n-2n**977n` // field over which calculations are done
 * * N = `2n**256n - 0x14551231950b75fc4402da1732fc9bebfn` // group order, amount of curve points
 * * h = `1n` // cofactor
 * * a = `0n` // equation param
 * * b = `7n` // equation param
 * * Gx, Gy are coordinates of Generator / base point
 */
const secp256k1_CURVE: WeierstrassOpts<bigint> = {
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  h: 1n,
  a: 0n,
  b: 7n,
  Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  Gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
};
const { p: P, n: N, Gx, Gy, b: _b } = secp256k1_CURVE;

const L = 32; // field / group byte length
const L2 = 64;
const lengths = {
  publicKey: L + 1,
  publicKeyUncompressed: L2 + 1,
  signature: L2,
  seed: L + L / 2,
};
/** Alias to Uint8Array. */
export type Bytes = Uint8Array;
/** Signature instance, which allows recovering pubkey from it. */
export type RecoveredSignature = Signature & { recovery: number };
/** Weierstrass elliptic curve options. */
export type WeierstrassOpts<T> = Readonly<{
  p: bigint;
  n: bigint;
  h: bigint;
  a: T;
  b: T;
  Gx: T;
  Gy: T;
}>;

// Helpers and Precomputes sections are reused between libraries

// ## Helpers
// ----------
const captureTrace = (...args: Parameters<typeof Error.captureStackTrace>): void => {
  if ('captureStackTrace' in Error && typeof Error.captureStackTrace === 'function') {
    Error.captureStackTrace(...args);
  }
};
const err = (message = ''): never => {
  const e = new Error(message);
  captureTrace(e, err);
  throw e;
};
const isBig = (n: unknown): n is bigint => typeof n === 'bigint'; // is big integer
const isStr = (s: unknown): s is string => typeof s === 'string'; // is string
const isBytes = (a: unknown): a is Uint8Array =>
  a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
/** Asserts something is Uint8Array. */
const abytes = (value: Bytes, length?: number, title: string = ''): Bytes => {
  const bytes = isBytes(value);
  const len = value?.length;
  const needsLen = length !== undefined;
  if (!bytes || (needsLen && len !== length)) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : '';
    const got = bytes ? `length=${len}` : `type=${typeof value}`;
    err(prefix + 'expected Uint8Array' + ofLen + ', got ' + got);
  }
  return value;
};
/** create Uint8Array */
const u8n = (len: number): Bytes => new Uint8Array(len);
const padh = (n: number | bigint, pad: number) => n.toString(16).padStart(pad, '0');
const bytesToHex = (b: Bytes): string =>
  Array.from(abytes(b))
    .map((e) => padh(e, 2))
    .join('');
const C = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 } as const; // ASCII characters
const _ch = (ch: number): number | undefined => {
  if (ch >= C._0 && ch <= C._9) return ch - C._0; // '2' => 50-48
  if (ch >= C.A && ch <= C.F) return ch - (C.A - 10); // 'B' => 66-(65-10)
  if (ch >= C.a && ch <= C.f) return ch - (C.a - 10); // 'b' => 98-(97-10)
  return;
};
const hexToBytes = (hex: string): Bytes => {
  const e = 'hex invalid';
  if (!isStr(hex)) return err(e);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2) return err(e);
  const array = u8n(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    // treat each char as ASCII
    const n1 = _ch(hex.charCodeAt(hi)); // parse first char, multiply it by 16
    const n2 = _ch(hex.charCodeAt(hi + 1)); // parse second char
    if (n1 === undefined || n2 === undefined) return err(e);
    array[ai] = n1 * 16 + n2; // example: 'A9' => 10*16 + 9
  }
  return array;
};
declare const globalThis: Record<string, any> | undefined; // Typescript symbol present in browsers
const cr = () => globalThis?.crypto; // WebCrypto is available in all modern environments
const subtle = () => cr()?.subtle ?? err('crypto.subtle must be defined, consider polyfill');
// prettier-ignore
const concatBytes = (...arrs: Bytes[]): Bytes => {
  const r = u8n(arrs.reduce((sum, a) => sum + abytes(a).length, 0)); // create u8a of summed length
  let pad = 0; // walk through each array,
  arrs.forEach(a => { r.set(a, pad); pad += a.length; }); // ensure they have proper type
  return r;
};
/** WebCrypto OS-level CSPRNG (random number generator). Will throw when not available. */
const randomBytes = (len: number = L): Bytes => {
  const c = cr();
  return c.getRandomValues(u8n(len));
};
const big = BigInt;
const arange = (n: bigint, min: bigint, max: bigint, msg = 'bad number: out of range'): bigint =>
  isBig(n) && min <= n && n < max ? n : err(msg);
/** modular division */
const M = (a: bigint, b: bigint = P) => {
  const r = a % b;
  return r >= 0n ? r : b + r;
};
const modN = (a: bigint) => M(a, N);
/** Modular inversion using eucledian GCD (non-CT). No negative exponent for now. */
// prettier-ignore
const invert = (num: bigint, md: bigint): bigint => {
  if (num === 0n || md <= 0n) err('no inverse n=' + num + ' mod=' + md);
  let a = M(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
  while (a !== 0n) {
    const q = b / a, r = b % a;
    const m = x - u * q, n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  return b === 1n ? M(x, md) : err('no inverse'); // b is gcd at this point
};
const callHash = (name: string) => {
  // @ts-ignore
  const fn = hashes[name];
  if (typeof fn !== 'function') err('hashes.' + name + ' not set');
  return fn;
};
const hash = (msg: Bytes): Bytes => callHash('sha256')(msg);
const apoint = (p: unknown) => (p instanceof Point ? p : err('Point expected'));
/** Point in 2d xy affine coordinates. */
export type AffinePoint = {
  x: bigint;
  y: bigint;
};
// ## End of Helpers
// -----------------

/** secp256k1 formula. Koblitz curves are subclass of weierstrass curves with a=0, making it x³+b */
const koblitz = (x: bigint) => M(M(x * x) * x + _b);
/** assert is element of field mod P (incl. 0) */
const FpIsValid = (n: bigint) => arange(n, 0n, P);
/** assert is element of field mod P (excl. 0) */
const FpIsValidNot0 = (n: bigint) => arange(n, 1n, P);
/** assert is element of field mod N (excl. 0) */
const FnIsValidNot0 = (n: bigint) => arange(n, 1n, N);
const isEven = (y: bigint) => (y & 1n) === 0n;
/** create Uint8Array of byte n */
const u8of = (n: number): Bytes => Uint8Array.of(n);
const getPrefix = (y: bigint) => u8of(isEven(y) ? 0x02 : 0x03);
/** lift_x from BIP340 calculates square root. Validates x, then validates root*root. */
const lift_x = (x: bigint) => {
  // Let c = x³ + 7 mod p. Fail if x ≥ p. (also fail if x < 1)
  const c = koblitz(FpIsValidNot0(x));
  // c = √y
  // y = c^((p+1)/4) mod p
  // This formula works for fields p = 3 mod 4 -- a special, fast case.
  // Paper: "Square Roots from 1;24,51,10 to Dan Shanks".
  let r = 1n;
  for (let num = c, e = (P + 1n) / 4n; e > 0n; e >>= 1n) {
    // powMod: modular exponentiation.
    if (e & 1n) r = (r * num) % P; // Uses exponentiation by squaring.
    num = (num * num) % P; // Not constant-time.
  }
  return M(r * r) === c ? r : err('sqrt invalid'); // check if result is valid
};

/** Point in 3d xyz projective coordinates. 3d takes less inversions than 2d. */
class Point {
  static BASE: Point;
  static ZERO: Point;
  readonly X: bigint;
  readonly Y: bigint;
  readonly Z: bigint;
  constructor(X: bigint, Y: bigint, Z: bigint) {
    this.X = FpIsValid(X);
    this.Y = FpIsValidNot0(Y); // Y can't be 0 in Projective
    this.Z = FpIsValid(Z);
    Object.freeze(this);
  }
  static CURVE(): WeierstrassOpts<bigint> {
    return secp256k1_CURVE;
  }
  /** Create 3d xyz point from 2d xy. (0, 0) => (0, 1, 0), not (0, 0, 1) */
  static fromAffine(ap: AffinePoint): Point {
    const { x, y } = ap;
    return x === 0n && y === 0n ? I : new Point(x, y, 1n);
  }
  /** Convert Uint8Array or hex string to Point. */
  static fromBytes(bytes: Bytes): Point {
    abytes(bytes);
    const { publicKey: comp, publicKeyUncompressed: uncomp } = lengths; // e.g. for 32-byte: 33, 65
    let p: Point | undefined = undefined;
    const length = bytes.length;
    const head = bytes[0];
    const tail = bytes.subarray(1);
    const x = sliceBytesNumBE(tail, 0, L);
    // No actual validation is done here: use .assertValidity()
    if (length === comp && (head === 0x02 || head === 0x03)) {
      // Equation is y² == x³ + ax + b. We calculate y from x.
      // y = √y²; there are two solutions: y, -y. Determine proper solution based on prefix
      let y = lift_x(x);
      const evenY = isEven(y);
      const evenH = isEven(big(head));
      if (evenH !== evenY) y = M(-y);
      p = new Point(x, y, 1n);
    }
    // Uncompressed 65-byte point, 0x04 prefix
    if (length === uncomp && head === 0x04) p = new Point(x, sliceBytesNumBE(tail, L, L2), 1n);
    // Validate point
    return p ? p.assertValidity() : err('bad point: not on curve');
  }
  static fromHex(hex: string): Point {
    return Point.fromBytes(hexToBytes(hex));
  }
  get x(): bigint {
    return this.toAffine().x;
  }
  get y(): bigint {
    return this.toAffine().y;
  }
  /** Equality check: compare points P&Q. */
  equals(other: Point): boolean {
    const { X: X1, Y: Y1, Z: Z1 } = this;
    const { X: X2, Y: Y2, Z: Z2 } = apoint(other); // checks class equality
    const X1Z2 = M(X1 * Z2);
    const X2Z1 = M(X2 * Z1);
    const Y1Z2 = M(Y1 * Z2);
    const Y2Z1 = M(Y2 * Z1);
    return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
  }
  is0(): boolean {
    return this.equals(I);
  }
  /** Flip point over y coordinate. */
  negate(): Point {
    return new Point(this.X, M(-this.Y), this.Z);
  }
  /** Point doubling: P+P, complete formula. */
  double(): Point {
    return this.add(this);
  }
  /**
   * Point addition: P+Q, complete, exception-free formula
   * (Renes-Costello-Batina, algo 1 of [2015/1060](https://eprint.iacr.org/2015/1060)).
   * Cost: `12M + 0S + 3*a + 3*b3 + 23add`.
   */
  // prettier-ignore
  add(other: Point): Point {
    const { X: X1, Y: Y1, Z: Z1 } = this;
    const { X: X2, Y: Y2, Z: Z2 } = apoint(other);
    const a = 0n;
    const b = _b;
    let X3 = 0n, Y3 = 0n, Z3 = 0n;
    const b3 = M(b * 3n);
    let t0 = M(X1 * X2), t1 = M(Y1 * Y2), t2 = M(Z1 * Z2), t3 = M(X1 + Y1); // step 1
    let t4 = M(X2 + Y2); // step 5
    t3 = M(t3 * t4); t4 = M(t0 + t1); t3 = M(t3 - t4); t4 = M(X1 + Z1);
    let t5 = M(X2 + Z2); // step 10
    t4 = M(t4 * t5); t5 = M(t0 + t2); t4 = M(t4 - t5); t5 = M(Y1 + Z1);
    X3 = M(Y2 + Z2); // step 15
    t5 = M(t5 * X3); X3 = M(t1 + t2); t5 = M(t5 - X3); Z3 = M(a * t4);
    X3 = M(b3 * t2); // step 20
    Z3 = M(X3 + Z3); X3 = M(t1 - Z3); Z3 = M(t1 + Z3); Y3 = M(X3 * Z3);
    t1 = M(t0 + t0); // step 25
    t1 = M(t1 + t0); t2 = M(a * t2); t4 = M(b3 * t4); t1 = M(t1 + t2);
    t2 = M(t0 - t2); // step 30
    t2 = M(a * t2); t4 = M(t4 + t2); t0 = M(t1 * t4); Y3 = M(Y3 + t0);
    t0 = M(t5 * t4); // step 35
    X3 = M(t3 * X3); X3 = M(X3 - t0); t0 = M(t3 * t1); Z3 = M(t5 * Z3);
    Z3 = M(Z3 + t0); // step 40
    return new Point(X3, Y3, Z3);
  }
  subtract(other: Point): Point {
    return this.add(apoint(other).negate());
  }
  /**
   * Point-by-scalar multiplication. Scalar must be in range 1 <= n < CURVE.n.
   * Uses {@link wNAF} for base point.
   * Uses fake point to mitigate side-channel leakage.
   * @param n scalar by which point is multiplied
   * @param safe safe mode guards against timing attacks; unsafe mode is faster
   */
  multiply(n: bigint, safe = true): Point {
    if (!safe && n === 0n) return I;
    FnIsValidNot0(n);
    if (n === 1n) return this;
    if (this.equals(G)) return wNAF(n).p;
    // init result point & fake point
    let p = I;
    let f = G;
    for (let d: Point = this; n > 0n; d = d.double(), n >>= 1n) {
      // if bit is present, add to point
      // if not present, add to fake, for timing safety
      if (n & 1n) p = p.add(d);
      else if (safe) f = f.add(d);
    }
    return p;
  }
  multiplyUnsafe(scalar: bigint): Point {
    return this.multiply(scalar, false);
  }
  /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
  toAffine(): AffinePoint {
    const { X: x, Y: y, Z: z } = this;
    // fast-paths for ZERO point OR Z=1
    if (this.equals(I)) return { x: 0n, y: 0n };
    if (z === 1n) return { x, y };
    const iz = invert(z, P);
    // (Z * Z^-1) must be 1, otherwise bad math
    if (M(z * iz) !== 1n) err('inverse invalid');
    // x = X*Z^-1; y = Y*Z^-1
    return { x: M(x * iz), y: M(y * iz) };
  }
  /** Checks if the point is valid and on-curve. */
  assertValidity(): Point {
    const { x, y } = this.toAffine(); // convert to 2d xy affine point.
    FpIsValidNot0(x); // must be in range 1 <= x,y < P
    FpIsValidNot0(y);
    // y² == x³ + ax + b, equation sides must be equal
    return M(y * y) === koblitz(x) ? this : err('bad point: not on curve');
  }
  /** Converts point to 33/65-byte Uint8Array. */
  toBytes(isCompressed = true): Bytes {
    const { x, y } = this.assertValidity().toAffine();
    const x32b = numTo32b(x);
    if (isCompressed) return concatBytes(getPrefix(y), x32b);
    return concatBytes(u8of(0x04), x32b, numTo32b(y));
  }

  toHex(isCompressed?: boolean): string {
    return bytesToHex(this.toBytes(isCompressed));
  }
}
/** Generator / base point */
const G: Point = new Point(Gx, Gy, 1n);
/** Identity / zero point */
const I: Point = new Point(0n, 1n, 0n);
// Static aliases
Point.BASE = G;
Point.ZERO = I;
/** `Q = u1⋅G + u2⋅R`. Verifies Q is not ZERO. Unsafe: non-CT. */
const doubleScalarMulUns = (R: Point, u1: bigint, u2: bigint): Point => {
  return G.multiply(u1, false).add(R.multiply(u2, false)).assertValidity();
};
const bytesToNumBE = (b: Bytes): bigint => big('0x' + (bytesToHex(b) || '0'));
const sliceBytesNumBE = (b: Bytes, from: number, to: number) => bytesToNumBE(b.subarray(from, to));
const B256 = 2n ** 256n; // secp256k1 is weierstrass curve. Equation is x³ + ax + b.
/** Number to 32b. Must be 0 <= num < B256. validate, pad, to bytes. */
const numTo32b = (num: bigint): Bytes => hexToBytes(padh(arange(num, 0n, B256), L2));
/** Normalize private key to scalar (bigint). Verifies scalar is in range 1<s<N */
const secretKeyToScalar = (secretKey: Bytes): bigint => {
  const num = bytesToNumBE(abytes(secretKey, L, 'secret key'));
  return arange(num, 1n, N, 'invalid secret key: outside of range');
};
/** For Signature malleability, validates sig.s is bigger than N/2. */
const highS = (n: bigint): boolean => n > N >> 1n;
/** Creates 33/65-byte public key from 32-byte private key. */
const getPublicKey = (privKey: Bytes, isCompressed = true): Bytes => {
  return G.multiply(secretKeyToScalar(privKey)).toBytes(isCompressed);
};

const isValidSecretKey = (secretKey: Bytes): boolean => {
  try {
    return !!secretKeyToScalar(secretKey);
  } catch (error) {
    return false;
  }
};
const isValidPublicKey = (publicKey: Bytes, isCompressed?: boolean): boolean => {
  const { publicKey: comp, publicKeyUncompressed } = lengths;
  try {
    const l = publicKey.length;
    if (isCompressed === true && l !== comp) return false;
    if (isCompressed === false && l !== publicKeyUncompressed) return false;
    return !!Point.fromBytes(publicKey);
  } catch (error) {
    return false;
  }
};

const assertRecoveryBit = (recovery?: number) => {
  if (![0, 1, 2, 3].includes(recovery!)) err('recovery id must be valid and present');
};
const assertSigFormat = (format?: ECDSASignatureFormat) => {
  if (format != null && !ALL_SIG.includes(format))
    err(`Signature format must be one of: ${ALL_SIG.join(', ')}`);
  if (format === SIG_DER) err('Signature format "der" is not supported: switch to noble-curves');
};
const assertSigLength = (sig: Bytes, format: ECDSASignatureFormat = SIG_COMPACT) => {
  assertSigFormat(format);
  const SL = lengths.signature;
  const RL = SL + 1;
  let msg = `Signature format "${format}" expects Uint8Array with length `;
  if (format === SIG_COMPACT && sig.length !== SL) err(msg + SL);
  if (format === SIG_RECOVERED && sig.length !== RL) err(msg + RL);
};
/** ECDSA Signature class. Supports only compact 64-byte representation, not DER. */
class Signature {
  readonly r: bigint;
  readonly s: bigint;
  readonly recovery?: number;
  constructor(r: bigint, s: bigint, recovery?: number) {
    this.r = FnIsValidNot0(r); // 1 <= r < N
    this.s = FnIsValidNot0(s); // 1 <= s < N
    if (recovery != null) this.recovery = recovery;
    Object.freeze(this);
  }
  static fromBytes(b: Bytes, format: ECDSASignatureFormat = SIG_COMPACT): Signature {
    assertSigLength(b, format);
    let rec: number | undefined;
    if (format === SIG_RECOVERED) {
      rec = b[0];
      b = b.subarray(1);
    }
    const r = sliceBytesNumBE(b, 0, L);
    const s = sliceBytesNumBE(b, L, L2);
    return new Signature(r, s, rec);
  }
  addRecoveryBit(bit: number): RecoveredSignature {
    return new Signature(this.r, this.s, bit) as RecoveredSignature;
  }
  hasHighS(): boolean {
    return highS(this.s);
  }
  toBytes(format: ECDSASignatureFormat = SIG_COMPACT): Bytes {
    const { r, s, recovery } = this;
    const res = concatBytes(numTo32b(r), numTo32b(s));
    if (format === SIG_RECOVERED) {
      assertRecoveryBit(recovery);
      return concatBytes(Uint8Array.of(recovery!), res);
    }
    return res;
  }
}

/**
 * RFC6979: ensure ECDSA msg is X bytes, convert to BigInt.
 * RFC suggests optional truncating via bits2octets.
 * FIPS 186-4 4.6 suggests the leftmost min(nBitLen, outLen) bits,
 * which matches bits2int. bits2int can produce res>N.
 */
const bits2int = (bytes: Bytes): bigint => {
  const delta = bytes.length * 8 - 256;
  if (delta > 1024) err('msg invalid'); // our CUSTOM check, "just-in-case": prohibit long inputs
  const num = bytesToNumBE(bytes);
  return delta > 0 ? num >> big(delta) : num;
};
/** int2octets can't be used; pads small msgs with 0: BAD for truncation as per RFC vectors */
const bits2int_modN = (bytes: Bytes): bigint => modN(bits2int(abytes(bytes)));
/**
 * Option to enable hedged signatures with improved security.
 *
 * * Randomly generated k is bad, because broken CSPRNG would leak private keys.
 * * Deterministic k (RFC6979) is better; but is suspectible to fault attacks.
 *
 * We allow using technique described in RFC6979 3.6: additional k', a.k.a. adding randomness
 * to deterministic sig. If CSPRNG is broken & randomness is weak, it would STILL be as secure
 * as ordinary sig without ExtraEntropy.
 *
 * * `true` means "fetch data, from CSPRNG, incorporate it into k generation"
 * * `false` means "disable extra entropy, use purely deterministic k"
 * * `Uint8Array` passed means "incorporate following data into k generation"
 *
 * https://paulmillr.com/posts/deterministic-signatures/
 */
export type ECDSAExtraEntropy = boolean | Bytes;
// todo: better name
const SIG_COMPACT = 'compact';
const SIG_RECOVERED = 'recovered';
const SIG_DER = 'der';
const ALL_SIG = [SIG_COMPACT, SIG_RECOVERED, SIG_DER] as const;
/**
 * - `compact` is the default format
 * - `recovered` is the same as compact, but with an extra byte indicating recovery byte
 * - `der` is not supported; and provided for consistency.
 *   Switch to noble-curves if you need der.
 */
export type ECDSASignatureFormat = 'compact' | 'recovered' | 'der';
/**
 * - `prehash`: (default: true) indicates whether to do sha256(message).
 *   When a custom hash is used, it must be set to `false`.
 */
export type ECDSARecoverOpts = {
  prehash?: boolean;
};
/**
 * - `prehash`: (default: true) indicates whether to do sha256(message).
 *   When a custom hash is used, it must be set to `false`.
 * - `lowS`: (default: true) prohibits signatures which have (sig.s >= CURVE.n/2n).
 *   Compatible with BTC/ETH. Setting `lowS: false` allows to create malleable signatures,
 *   which is default openssl behavior.
 *   Non-malleable signatures can still be successfully verified in openssl.
 * - `format`: (default: 'compact') 'compact' or 'recovered' with recovery byte
 */
export type ECDSAVerifyOpts = {
  prehash?: boolean;
  lowS?: boolean;
  format?: ECDSASignatureFormat;
};
/**
 * - `prehash`: (default: true) indicates whether to do sha256(message).
 *   When a custom hash is used, it must be set to `false`.
 * - `lowS`: (default: true) prohibits signatures which have (sig.s >= CURVE.n/2n).
 *   Compatible with BTC/ETH. Setting `lowS: false` allows to create malleable signatures,
 *   which is default openssl behavior.
 *   Non-malleable signatures can still be successfully verified in openssl.
 * - `format`: (default: 'compact') 'compact' or 'recovered' with recovery byte
 * - `extraEntropy`: (default: false) creates sigs with increased security, see {@link ECDSAExtraEntropy}
 */
export type ECDSASignOpts = {
  prehash?: boolean;
  lowS?: boolean;
  format?: ECDSASignatureFormat;
  extraEntropy?: ECDSAExtraEntropy;
};

const defaultSignOpts: ECDSASignOpts = {
  lowS: true,
  prehash: true,
  format: SIG_COMPACT,
  extraEntropy: false,
};

const _sha = 'SHA-256';
const hashes = {
  hmacSha256Async: async (key: Bytes, message: Bytes): Promise<Bytes> => {
    const s = subtle();
    const name = 'HMAC';
    const k = await s.importKey('raw', key, { name, hash: { name: _sha } }, false, ['sign']);
    return u8n(await s.sign(name, k, message));
  },
  hmacSha256: undefined as undefined | ((key: Bytes, message: Bytes) => Bytes),
  sha256Async: async (msg: Bytes): Promise<Bytes> => u8n(await subtle().digest(_sha, msg)),
  sha256: undefined as undefined | ((message: Bytes) => Bytes),
};

const prepMsg = (msg: Bytes, opts: ECDSARecoverOpts, async_: boolean): Bytes | Promise<Bytes> => {
  abytes(msg, undefined, 'message');
  if (!opts.prehash) return msg;
  return async_ ? hashes.sha256Async(msg) : callHash('sha256')(msg);
};

type Pred<T> = (v: Bytes) => T | undefined;
const NULL = u8n(0);
const byte0 = u8of(0x00);
const byte1 = u8of(0x01);
const _maxDrbgIters = 1000;
const _drbgErr = 'drbg: tried max amount of iterations';
// HMAC-DRBG from NIST 800-90. Minimal, non-full-spec - used for RFC6979 signatures.
const hmacDrbg = (seed: Bytes, pred: Pred<Bytes>): Bytes => {
  let v = u8n(L); // Steps B, C of RFC6979 3.2: set hashLen
  let k = u8n(L); // In our case, it's always equal to L
  let i = 0; // Iterations counter, will throw when over max
  const reset = () => {
    v.fill(1);
    k.fill(0);
  };
  // h = hmac(K || V || ...)
  const h = (...b: Bytes[]) => callHash('hmacSha256')(k, concatBytes(v, ...b));
  const reseed = (seed = NULL) => {
    // HMAC-DRBG reseed() function. Steps D-G
    k = h(byte0, seed); // k = hmac(k || v || 0x00 || seed)
    v = h(); // v = hmac(k || v)
    if (seed.length === 0) return;
    k = h(byte1, seed); // k = hmac(k || v || 0x01 || seed)
    v = h(); // v = hmac(k || v)
  };
  // HMAC-DRBG generate() function
  const gen = () => {
    if (i++ >= _maxDrbgIters) err(_drbgErr);
    v = h(); // v = hmac(k || v)
    return v; // this diverges from noble-curves: we don't allow arbitrary output len!
  };
  reset();
  reseed(seed); // Steps D-G
  let res: Bytes | undefined = undefined; // Step H: grind until k is in [1..n-1]
  while (!(res = pred(gen()))) reseed(); // test predicate until it returns ok
  reset();
  return res!;
};

// Identical to hmacDrbg, but async: uses built-in WebCrypto
const hmacDrbgAsync = async (seed: Bytes, pred: Pred<Bytes>): Promise<Bytes> => {
  let v = u8n(L); // Steps B, C of RFC6979 3.2: set hashLen
  let k = u8n(L); // In our case, it's always equal to L
  let i = 0; // Iterations counter, will throw when over max
  const reset = () => {
    v.fill(1);
    k.fill(0);
  };
  // h = hmac(K || V || ...)
  const h = (...b: Bytes[]) => hashes.hmacSha256Async(k, concatBytes(v, ...b));
  const reseed = async (seed = NULL) => {
    // HMAC-DRBG reseed() function. Steps D-G
    k = await h(byte0, seed); // k = hmac(K || V || 0x00 || seed)
    v = await h(); // v = hmac(K || V)
    if (seed.length === 0) return;
    k = await h(byte1, seed); // k = hmac(K || V || 0x01 || seed)
    v = await h(); // v = hmac(K || V)
  };
  // HMAC-DRBG generate() function
  const gen = async () => {
    if (i++ >= _maxDrbgIters) err(_drbgErr);
    v = await h(); // v = hmac(K || V)
    return v; // this diverges from noble-curves: we don't allow arbitrary output len!
  };
  reset();
  await reseed(seed); // Steps D-G
  let res: Bytes | undefined = undefined; // Step H: grind until k is in [1..n-1]
  while (!(res = pred(await gen()))) await reseed(); // test predicate until it returns ok
  reset();
  return res!;
};

// RFC6979 signature generation, preparation step.
// Follows [SEC1](https://secg.org/sec1-v2.pdf) 4.1.2 & RFC6979.
const _sign = <T>(
  messageHash: Bytes,
  secretKey: Bytes,
  opts: ECDSASignOpts,
  hmacDrbg: (seed: Bytes, pred: Pred<Bytes>) => T
): T => {
  let { lowS, extraEntropy } = opts; // generates low-s sigs by default
  // RFC6979 3.2: we skip step A
  const int2octets = numTo32b; // int to octets
  const h1i = bits2int_modN(messageHash); // msg bigint
  const h1o = int2octets(h1i); // msg octets
  const d = secretKeyToScalar(secretKey); // validate private key, convert to bigint
  const seedArgs = [int2octets(d), h1o]; // Step D of RFC6979 3.2
  /** RFC6979 3.6: additional k' (optional). See {@link ECDSAExtraEntropy}. */
  if (extraEntropy != null && extraEntropy !== false) {
    // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1) || k')
    // gen random bytes OR pass as-is
    const e = extraEntropy === true ? randomBytes(L) : extraEntropy;
    seedArgs.push(abytes(e, undefined, 'extraEntropy')); // check for being bytes
  }
  const seed = concatBytes(...seedArgs);
  const m = h1i; // convert msg to bigint
  // Converts signature params into point w r/s, checks result for validity.
  // To transform k => Signature:
  // q = k⋅G
  // r = q.x mod n
  // s = k^-1(m + rd) mod n
  // Can use scalar blinding b^-1(bm + bdr) where b ∈ [1,q−1] according to
  // https://tches.iacr.org/index.php/TCHES/article/view/7337/6509. We've decided against it:
  // a) dependency on CSPRNG b) 15% slowdown c) doesn't really help since bigints are not CT
  const k2sig = (kBytes: Bytes): Bytes | undefined => {
    // RFC 6979 Section 3.2, step 3: k = bits2int(T)
    // Important: all mod() calls here must be done over N
    const k = bits2int(kBytes);
    if (!(1n <= k && k < N)) return; // Valid scalars (including k) must be in 1..N-1
    const ik = invert(k, N); // k^-1 mod n
    const q = G.multiply(k).toAffine(); // q = k⋅G
    const r = modN(q.x); // r = q.x mod n
    if (r === 0n) return;
    const s = modN(ik * modN(m + r * d)); // s = k^-1(m + rd) mod n
    if (s === 0n) return;
    let recovery = (q.x === r ? 0 : 2) | Number(q.y & 1n); // recovery bit (2 or 3, when q.x > n)
    let normS = s; // normalized S
    if (lowS && highS(s)) {
      // if lowS was passed, ensure s is always
      normS = modN(-s); // in the bottom half of CURVE.n
      recovery ^= 1;
    }
    const sig = new Signature(r, normS, recovery) as RecoveredSignature; // use normS, not s
    return sig.toBytes(opts.format);
  };
  return hmacDrbg(seed, k2sig);
};

// Follows [SEC1](https://secg.org/sec1-v2.pdf) 4.1.4.
const _verify = (sig: Bytes, messageHash: Bytes, publicKey: Bytes, opts: ECDSAVerifyOpts = {}) => {
  const { lowS, format } = opts;
  if (sig instanceof Signature) err('Signature must be in Uint8Array, use .toBytes()');
  assertSigLength(sig, format);
  abytes(publicKey, undefined, 'publicKey');
  try {
    const { r, s } = Signature.fromBytes(sig, format);
    const h = bits2int_modN(messageHash); // Truncate hash
    const P = Point.fromBytes(publicKey); // Validate public key
    if (lowS && highS(s)) return false; // lowS bans sig.s >= CURVE.n/2
    const is = invert(s, N); // s^-1
    const u1 = modN(h * is); // u1 = hs^-1 mod n
    const u2 = modN(r * is); // u2 = rs^-1 mod n
    const R = doubleScalarMulUns(P, u1, u2).toAffine(); // R = u1⋅G + u2⋅P
    // Stop if R is identity / zero point. Check is done inside `doubleScalarMulUns`
    const v = modN(R.x); // R.x must be in N's field, not P's
    return v === r; // mod(R.x, n) == r
  } catch (error) {
    return false;
  }
};

const setDefaults = (opts: ECDSASignOpts): Required<ECDSASignOpts> => {
  const res: ECDSASignOpts = {};
  Object.keys(defaultSignOpts).forEach((k: string) => {
    // @ts-ignore
    res[k] = opts[k] ?? defaultSignOpts[k];
  });
  return res as Required<ECDSASignOpts>;
};

/**
 * Sign a message using secp256k1. Sync: uses `hashes.sha256` and `hashes.hmacSha256`.
 * Prehashes message with sha256, disable using `prehash: false`.
 * @param opts - see {@link ECDSASignOpts} for details. Enabling {@link ECDSAExtraEntropy} will improve security.
 * @example
 * ```js
 * const msg = new TextEncoder().encode('hello noble');
 * sign(msg, secretKey);
 * sign(keccak256(msg), secretKey, { prehash: false });
 * sign(msg, secretKey, { extraEntropy: true });
 * sign(msg, secretKey, { format: 'recovered' });
 * ```
 */
const sign = (message: Bytes, secretKey: Bytes, opts: ECDSASignOpts = {}): Bytes => {
  opts = setDefaults(opts);
  message = prepMsg(message, opts, false) as Bytes;
  return _sign(message, secretKey, opts, hmacDrbg);
};

/**
 * Sign a message using secp256k1. Async: uses built-in WebCrypto hashes.
 * Prehashes message with sha256, disable using `prehash: false`.
 * @param opts - see {@link ECDSASignOpts} for details. Enabling {@link ECDSAExtraEntropy} will improve security.
 * @example
 * ```js
 * const msg = new TextEncoder().encode('hello noble');
 * await signAsync(msg, secretKey);
 * await signAsync(keccak256(msg), secretKey, { prehash: false });
 * await signAsync(msg, secretKey, { extraEntropy: true });
 * await signAsync(msg, secretKey, { format: 'recovered' });
 * ```
 */
const signAsync = async (
  message: Bytes,
  secretKey: Bytes,
  opts: ECDSASignOpts = {}
): Promise<Bytes> => {
  opts = setDefaults(opts);
  message = await prepMsg(message, opts, true);
  return _sign(message, secretKey, opts, hmacDrbgAsync);
};

/**
 * Verify a signature using secp256k1. Sync: uses `hashes.sha256` and `hashes.hmacSha256`.
 * @param signature - default is 64-byte 'compact' format, also see {@link ECDSASignatureFormat}
 * @param message - message which was signed. Keep in mind `prehash` from opts.
 * @param publicKey - public key which
 * @param opts - see {@link ECDSAVerifyOpts} for details.
 * @example
 * ```js
 * const msg = new TextEncoder().encode('hello noble');
 * verify(sig, msg, publicKey);
 * verify(sig, keccak256(msg), publicKey, { prehash: false });
 * verify(sig, msg, publicKey, { lowS: false });
 * verify(sigr, msg, publicKey, { format: 'recovered' });
 * ```
 */
const verify = (
  signature: Bytes,
  message: Bytes,
  publicKey: Bytes,
  opts: ECDSAVerifyOpts = {}
): boolean => {
  opts = setDefaults(opts);
  message = prepMsg(message, opts, false) as Bytes;
  return _verify(signature, message, publicKey, opts);
};

/**
 * Verify a signature using secp256k1. Async: uses built-in WebCrypto hashes.
 * @param signature - default is 64-byte 'compact' format, also see {@link ECDSASignatureFormat}
 * @param message - message which was signed. Keep in mind `prehash` from opts.
 * @param publicKey - public key which
 * @param opts - see {@link ECDSAVerifyOpts} for details.
 * @example
 * ```js
 * const msg = new TextEncoder().encode('hello noble');
 * verify(sig, msg, publicKey);
 * verify(sig, keccak256(msg), publicKey, { prehash: false });
 * verify(sig, msg, publicKey, { lowS: false });
 * verify(sigr, msg, publicKey, { format: 'recovered' });
 * ```
 */
const verifyAsync = async (
  sig: Bytes,
  message: Bytes,
  publicKey: Bytes,
  opts: ECDSAVerifyOpts = {}
): Promise<boolean> => {
  opts = setDefaults(opts);
  message = await prepMsg(message, opts, true);
  return _verify(sig, message, publicKey, opts);
};

const _recover = (signature: Bytes, messageHash: Bytes) => {
  const sig = Signature.fromBytes(signature, 'recovered');
  const { r, s, recovery } = sig;
  // 0 or 1 recovery id determines sign of "y" coordinate.
  // 2 or 3 means q.x was >N.
  assertRecoveryBit(recovery);
  const h = bits2int_modN(abytes(messageHash, L)); // Truncate hash
  const radj = recovery === 2 || recovery === 3 ? r + N : r;
  FpIsValidNot0(radj); // ensure q.x is still a field element
  const head = getPrefix(big(recovery!)); // head is 0x02 or 0x03
  const Rb = concatBytes(head, numTo32b(radj)); // concat head + r
  const R = Point.fromBytes(Rb);
  const ir = invert(radj, N); // r^-1
  const u1 = modN(-h * ir); // -hr^-1
  const u2 = modN(s * ir); // sr^-1
  const point = doubleScalarMulUns(R, u1, u2); // (sr^-1)R-(hr^-1)G = -(hr^-1)G + (sr^-1)
  return point.toBytes();
};

/**
 * ECDSA public key recovery. Requires msg hash and recovery id.
 * Follows [SEC1](https://secg.org/sec1-v2.pdf) 4.1.6.
 */
const recoverPublicKey = (signature: Bytes, message: Bytes, opts: ECDSARecoverOpts = {}): Bytes => {
  message = prepMsg(message, setDefaults(opts), false) as Bytes;
  return _recover(signature, message);
};

const recoverPublicKeyAsync = async (
  signature: Bytes,
  message: Bytes,
  opts: ECDSARecoverOpts = {}
): Promise<Bytes> => {
  message = await prepMsg(message, setDefaults(opts), true);
  return _recover(signature, message);
};

/**
 * Elliptic Curve Diffie-Hellman (ECDH) on secp256k1.
 * Result is **NOT hashed**. Use hash or KDF on it if you need.
 * @param isCompressed 33-byte (true) or 65-byte (false) output
 * @returns public key C
 */
const getSharedSecret = (secretKeyA: Bytes, publicKeyB: Bytes, isCompressed = true): Bytes => {
  return Point.fromBytes(publicKeyB).multiply(secretKeyToScalar(secretKeyA)).toBytes(isCompressed);
};

// FIPS 186 B.4.1 compliant key generation produces private keys
// with modulo bias being neglible. takes >N+16 bytes, returns (hash mod n-1)+1
const randomSecretKey = (seed = randomBytes(lengths.seed)) => {
  abytes(seed);
  if (seed.length < lengths.seed || seed.length > 1024) err('expected 40-1024b');
  const num = M(bytesToNumBE(seed), N - 1n);
  return numTo32b(num + 1n);
};

type KeysSecPub = { secretKey: Bytes; publicKey: Bytes };
type KeygenFn = (seed?: Bytes) => KeysSecPub;
const createKeygen = (getPublicKey: (secretKey: Bytes) => Bytes) => (seed?: Bytes): KeysSecPub => {
  const secretKey = randomSecretKey(seed);
  return { secretKey, publicKey: getPublicKey(secretKey) };
}
const keygen: KeygenFn = createKeygen(getPublicKey);

/** Math, hex, byte helpers. Not in `utils` because utils share API with noble-curves. */
const etc = {
  hexToBytes: hexToBytes as (hex: string) => Bytes,
  bytesToHex: bytesToHex as (bytes: Bytes) => string,
  concatBytes: concatBytes as (...arrs: Bytes[]) => Bytes,
  bytesToNumberBE: bytesToNumBE as (a: Bytes) => bigint,
  numberToBytesBE: numTo32b as (n: bigint) => Bytes,
  mod: M as (a: bigint, md?: bigint) => bigint,
  invert: invert as (num: bigint, md?: bigint) => bigint, // math utilities
  randomBytes: randomBytes as (len?: number) => Bytes,
  secretKeyToScalar: secretKeyToScalar as typeof secretKeyToScalar,
  abytes: abytes as typeof abytes,
};

/** Curve-specific utilities for private keys. */
const utils = {
  isValidSecretKey: isValidSecretKey as typeof isValidSecretKey,
  isValidPublicKey: isValidPublicKey as typeof isValidPublicKey,
  randomSecretKey: randomSecretKey as () => Bytes,
};

// Schnorr signatures are superior to ECDSA from above. Below is Schnorr-specific BIP0340 code.
// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
const getTag = (tag: string) => Uint8Array.from('BIP0340/' + tag, (c) => c.charCodeAt(0));
const T_AUX = 'aux';
const T_NONCE = 'nonce';
const T_CHALLENGE = 'challenge';
const taggedHash = (tag: string, ...messages: Bytes[]): Bytes => {
  const fn = callHash('sha256');
  const tagH = fn(getTag(tag));
  return fn(concatBytes(tagH, tagH, ...messages));
};
const taggedHashAsync = async (tag: string, ...messages: Bytes[]): Promise<Bytes> => {
  const fn = hashes.sha256Async;
  const tagH = await fn(getTag(tag));
  return await fn(concatBytes(tagH, tagH, ...messages));
};

// ECDSA compact points are 33-byte. Schnorr is 32: we strip first byte 0x02 or 0x03
// Calculate point, scalar and bytes
const extpubSchnorr = (priv: Bytes) => {
  const d_ = secretKeyToScalar(priv);
  const p = G.multiply(d_); // P = d'⋅G; 0 < d' < n check is done inside
  const { x, y } = p.assertValidity().toAffine(); // validate Point is not at infinity
  const d = isEven(y) ? d_ : modN(-d_);
  const px = numTo32b(x);
  return { d, px };
};

const bytesModN = (bytes: Bytes) => modN(bytesToNumBE(bytes));
const challenge = (...args: Bytes[]): bigint => bytesModN(taggedHash(T_CHALLENGE, ...args));
const challengeAsync = async (...args: Bytes[]): Promise<bigint> =>
  bytesModN(await taggedHashAsync(T_CHALLENGE, ...args));

/**
 * Schnorr public key is just `x` coordinate of Point as per BIP340.
 */
const pubSchnorr = (secretKey: Bytes): Bytes => {
  return extpubSchnorr(secretKey).px; // d'=int(sk). Fail if d'=0 or d'≥n. Ret bytes(d'⋅G)
};

const keygenSchnorr: KeygenFn = createKeygen(pubSchnorr);

// Common preparation fn for both sync and async signing
const prepSigSchnorr = (message: Bytes, secretKey: Bytes, auxRand: Bytes) => {
  const { px, d } = extpubSchnorr(secretKey);
  return { m: abytes(message), px, d, a: abytes(auxRand, L) };
};

const extractK = (rand: Bytes) => {
  const k_ = bytesModN(rand); // Let k' = int(rand) mod n
  if (k_ === 0n) err('sign failed: k is zero'); // Fail if k' = 0.
  const { px, d } = extpubSchnorr(numTo32b(k_)); // Let R = k'⋅G.
  return { rx: px, k: d };
};

// Common signature creation helper
const createSigSchnorr = (k: bigint, px: Bytes, e: bigint, d: bigint): Bytes => {
  return concatBytes(px, numTo32b(modN(k + e * d)));
};

const E_INVSIG = 'invalid signature produced';
/**
 * Creates Schnorr signature as per BIP340. Verifies itself before returning anything.
 * auxRand is optional and is not the sole source of k generation: bad CSPRNG won't be dangerous.
 */
const signSchnorr = (message: Bytes, secretKey: Bytes, auxRand: Bytes = randomBytes(L)): Bytes => {
  const { m, px, d, a } = prepSigSchnorr(message, secretKey, auxRand);
  const aux = taggedHash(T_AUX, a);
  // Let t be the byte-wise xor of bytes(d) and hash/aux(a)
  const t = numTo32b(d ^ bytesToNumBE(aux));
  // Let rand = hash/nonce(t || bytes(P) || m)
  const rand = taggedHash(T_NONCE, t, px, m);
  const { rx, k } = extractK(rand);
  // Let e = int(hash/challenge(bytes(R) || bytes(P) || m)) mod n.
  const e = challenge(rx, px, m);
  const sig = createSigSchnorr(k, rx, e, d);
  // If Verify(bytes(P), m, sig) (see below) returns failure, abort
  if (!verifySchnorr(sig, m, px)) err(E_INVSIG);
  return sig;
};

const signSchnorrAsync = async (
  message: Bytes,
  secretKey: Bytes,
  auxRand: Bytes = randomBytes(L)
): Promise<Bytes> => {
  const { m, px, d, a } = prepSigSchnorr(message, secretKey, auxRand);
  const aux = await taggedHashAsync(T_AUX, a);
  // Let t be the byte-wise xor of bytes(d) and hash/aux(a)
  const t = numTo32b(d ^ bytesToNumBE(aux));
  // Let rand = hash/nonce(t || bytes(P) || m)
  const rand = await taggedHashAsync(T_NONCE, t, px, m);
  const { rx, k } = extractK(rand);
  // Let e = int(hash/challenge(bytes(R) || bytes(P) || m)) mod n.
  const e = await challengeAsync(rx, px, m);
  const sig = createSigSchnorr(k, rx, e, d);
  // If Verify(bytes(P), m, sig) (see below) returns failure, abort
  if (!(await verifySchnorrAsync(sig, m, px))) err(E_INVSIG);
  return sig;
};

// const finishVerif = (P_: Point, r: bigint, s: bigint, e: bigint) => {};

type MaybePromise<T> = T | Promise<T>;
const callSyncAsyncFn = <T, O>(res: MaybePromise<T>, later: (res2: T) => O) => {
  return res instanceof Promise ? res.then(later) : later(res);
};

const _verifSchnorr = (
  signature: Bytes,
  message: Bytes,
  publicKey: Bytes,
  challengeFn: (...args: Bytes[]) => bigint | Promise<bigint>
): boolean | Promise<boolean> => {
  const sig = abytes(signature, L2, 'signature');
  const msg = abytes(message, undefined, 'message');
  const pub = abytes(publicKey, L, 'publicKey');
  try {
    // lift_x from BIP340. Convert 32-byte x coordinate to elliptic curve point.
    // Fail if x ≥ p. Let c = x³ + 7 mod p.
    const x = bytesToNumBE(pub);
    const y = lift_x(x); // Let y = c^(p+1)/4 mod p.
    const y_ = isEven(y) ? y : M(-y);
    // Return the unique point P such that x(P) = x and
    // y(P) = y if y mod 2 = 0 or y(P) = p-y otherwise.
    const P_ = new Point(x, y_, 1n).assertValidity();
    const px = numTo32b(P_.toAffine().x);
    // P = lift_x(int(pk)); fail if that fails
    const r = sliceBytesNumBE(sig, 0, L); // Let r = int(sig[0:32]); fail if r ≥ p.
    arange(r, 1n, P);
    const s = sliceBytesNumBE(sig, L, L2); // Let s = int(sig[32:64]); fail if s ≥ n.
    arange(s, 1n, N);
    const i = concatBytes(numTo32b(r), px, msg);
    // int(challenge(bytes(r)||bytes(P)||m))%n
    return callSyncAsyncFn(challengeFn(i), (e) => {
      const { x, y } = doubleScalarMulUns(P_, s, modN(-e)).toAffine(); // R = s⋅G - e⋅P
      if (!isEven(y) || x !== r) return false; // -eP == (n-e)P
      return true; // Fail if is_infinite(R) / not has_even_y(R) / x(R) ≠ r.
    });
  } catch (error) {
    return false;
  }
};

/**
 * Verifies Schnorr signature.
 * Will swallow errors & return false except for initial type validation of arguments.
 */
const verifySchnorr = (s: Bytes, m: Bytes, p: Bytes): boolean =>
  _verifSchnorr(s, m, p, challenge) as boolean;
const verifySchnorrAsync = async (s: Bytes, m: Bytes, p: Bytes): Promise<boolean> =>
  _verifSchnorr(s, m, p, challengeAsync) as Promise<boolean>;

const schnorr: {
  keygen: typeof keygenSchnorr,
  getPublicKey: typeof pubSchnorr;
  sign: typeof signSchnorr;
  verify: typeof verifySchnorr;
  signAsync: typeof signSchnorrAsync,
  verifyAsync: typeof verifySchnorrAsync
} = {
  keygen: keygenSchnorr,
  getPublicKey: pubSchnorr,
  sign: signSchnorr,
  verify: verifySchnorr,
  signAsync: signSchnorrAsync,
  verifyAsync: verifySchnorrAsync,
};

// ## Precomputes
// --------------

const W = 8; // W is window size
const scalarBits = 256;
const pwindows = Math.ceil(scalarBits / W) + 1; // 33 for W=8, NOT 32 - see wNAF loop
const pwindowSize = 2 ** (W - 1); // 128 for W=8
const precompute = () => {
  const points: Point[] = [];
  let p = G;
  let b = p;
  for (let w = 0; w < pwindows; w++) {
    b = p;
    points.push(b);
    for (let i = 1; i < pwindowSize; i++) {
      b = b.add(p);
      points.push(b);
    } // i=1, bc we skip 0
    p = b.double();
  }
  return points;
};
let Gpows: Point[] | undefined = undefined; // precomputes for base point G
// const-time negate
const ctneg = (cnd: boolean, p: Point) => {
  const n = p.negate();
  return cnd ? n : p;
};

/**
 * Precomputes give 12x faster getPublicKey(), 10x sign(), 2x verify() by
 * caching multiples of G (base point). Cache is stored in 32MB of RAM.
 * Any time `G.multiply` is done, precomputes are used.
 * Not used for getSharedSecret, which instead multiplies random pubkey `P.multiply`.
 *
 * w-ary non-adjacent form (wNAF) precomputation method is 10% slower than windowed method,
 * but takes 2x less RAM. RAM reduction is possible by utilizing `.subtract`.
 *
 * !! Precomputes can be disabled by commenting-out call of the wNAF() inside Point#multiply().
 */
const wNAF = (n: bigint): { p: Point; f: Point } => {
  const comp = Gpows || (Gpows = precompute());
  let p = I;
  let f = G; // f must be G, or could become I in the end
  const pow_2_w = 2 ** W; // 256 for W=8
  const maxNum = pow_2_w; // 256 for W=8
  const mask = big(pow_2_w - 1); // 255 for W=8 == mask 0b11111111
  const shiftBy = big(W); // 8 for W=8
  for (let w = 0; w < pwindows; w++) {
    let wbits = Number(n & mask); // extract W bits.
    n >>= shiftBy; // shift number by W bits.
    // We use negative indexes to reduce size of precomputed table by 2x.
    // Instead of needing precomputes 0..256, we only calculate them for 0..128.
    // If an index > 128 is found, we do (256-index) - where 256 is next window.
    // Naive: index +127 => 127, +224 => 224
    // Optimized: index +127 => 127, +224 => 256-32
    if (wbits > pwindowSize) {
      wbits -= maxNum;
      n += 1n;
    }
    const off = w * pwindowSize;
    const offF = off; // offsets, evaluate both
    const offP = off + Math.abs(wbits) - 1;
    const isEven = w % 2 !== 0; // conditions, evaluate both
    const isNeg = wbits < 0;
    if (wbits === 0) {
      // off == I: can't add it. Adding random offF instead.
      f = f.add(ctneg(isEven, comp[offF])); // bits are 0: add garbage to fake point
    } else {
      p = p.add(ctneg(isNeg, comp[offP])); // bits are 1: add to result point
    }
  }
  if (n !== 0n) err('invalid wnaf');
  return { p, f }; // return both real and fake points for JIT
};

// !! Remove the export below to easily use in REPL / browser console
export {
  etc,
  getPublicKey, getSharedSecret,
  hash, hashes,
  keygen,
  Point, recoverPublicKey, recoverPublicKeyAsync, schnorr, sign, signAsync,

  Signature, utils, verify, verifyAsync
};

