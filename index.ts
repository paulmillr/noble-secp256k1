/*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
/**
 * 5KB JS implementation of secp256k1 ECDSA / Schnorr signatures & ECDH.
 * Compliant with RFC6979 & BIP340.
 * @module
 */
/**
 * Curve params from SEC 2 v2 §2.4.1.
 * secp256k1 is a short Weierstrass / Koblitz curve with equation
 * `y² == x³ + ax + b`.
 * * P = `2n**256n - 2n**32n - 977n` // field over which calculations are done
 * * N = `2n**256n - 0x14551231950b75fc4402da1732fc9bebfn` // group order, amount of curve points
 * * h = `1n` // cofactor
 * * a = `0n` // equation param
 * * b = `7n` // equation param
 * * Gx, Gy are coordinates of Generator / base point
 *
 * Mirror noble-curves: Point.CURVE() returns shared params,
 * but those params must stay frozen so callers cannot mutate
 * them out from under the arithmetic constants captured below.
 */
const secp256k1_CURVE: WeierstrassOpts<bigint> = Object.freeze({
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  h: 1n,
  a: 0n,
  b: 7n,
  Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  Gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
});
const { p: P, n: N, Gx, Gy, b: _b } = secp256k1_CURVE;

// 32-byte field / scalar width, and the SHA-256 / HMAC-DRBG output width used
// by the RFC6979 paths here.
const L = 32;
const L2 = 64; // 64-byte compact signatures, and 64 hex chars for zero-padded 32-byte scalars
const lengths = {
  publicKey: L + 1,
  publicKeyUncompressed: L2 + 1,
  signature: L2,
  // 48-byte keygen seed floor: 384 bits exceeds FIPS 186-5 Table A.2's
  // 352-bit recommendation for 256-bit prime curves.
  seed: L + L / 2,
};
/** Alias to Uint8Array. */
export type Bytes = Uint8Array;
/**
 * Bytes API type helpers for old + new TypeScript.
 *
 * TS 5.6 has `Uint8Array`, while TS 5.9+ made it generic `Uint8Array<ArrayBuffer>`.
 * We can't use specific return type, because TS 5.6 will error.
 * We can't use generic return type, because most TS 5.9 software will expect specific type.
 *
 * Maps typed-array input leaves to broad forms.
 * These are compatibility adapters, not ownership guarantees.
 *
 * - `TArg` keeps byte inputs broad.
 * - `TRet` marks byte outputs for TS 5.6 and TS 5.9+ compatibility.
 */
export type TypedArg<T> = T extends BigInt64Array
  ? BigInt64Array
  : T extends BigUint64Array
    ? BigUint64Array
    : T extends Float32Array
      ? Float32Array
      : T extends Float64Array
        ? Float64Array
        : T extends Int16Array
          ? Int16Array
          : T extends Int32Array
            ? Int32Array
            : T extends Int8Array
              ? Int8Array
              : T extends Uint16Array
                ? Uint16Array
                : T extends Uint32Array
                  ? Uint32Array
                  : T extends Uint8ClampedArray
                    ? Uint8ClampedArray
                    : T extends Uint8Array
                      ? Uint8Array
                      : never;
/** Maps typed-array output leaves to narrow TS-compatible forms. */
export type TypedRet<T> = T extends BigInt64Array
  ? ReturnType<typeof BigInt64Array.of>
  : T extends BigUint64Array
    ? ReturnType<typeof BigUint64Array.of>
    : T extends Float32Array
      ? ReturnType<typeof Float32Array.of>
      : T extends Float64Array
        ? ReturnType<typeof Float64Array.of>
        : T extends Int16Array
          ? ReturnType<typeof Int16Array.of>
          : T extends Int32Array
            ? ReturnType<typeof Int32Array.of>
            : T extends Int8Array
              ? ReturnType<typeof Int8Array.of>
              : T extends Uint16Array
                ? ReturnType<typeof Uint16Array.of>
                : T extends Uint32Array
                  ? ReturnType<typeof Uint32Array.of>
                  : T extends Uint8ClampedArray
                    ? ReturnType<typeof Uint8ClampedArray.of>
                    : T extends Uint8Array
                      ? ReturnType<typeof Uint8Array.of>
                      : never;
/** Recursively adapts byte-carrying API input types. See {@link TypedArg}. */
export type TArg<T> =
  | T
  | ([TypedArg<T>] extends [never]
      ? T extends (...args: infer A) => infer R
        ? ((...args: { [K in keyof A]: TRet<A[K]> }) => TArg<R>) & {
            [K in keyof T]: T[K] extends (...args: any) => any ? T[K] : TArg<T[K]>;
          }
        : T extends [infer A, ...infer R]
          ? [TArg<A>, ...{ [K in keyof R]: TArg<R[K]> }]
          : T extends readonly [infer A, ...infer R]
            ? readonly [TArg<A>, ...{ [K in keyof R]: TArg<R[K]> }]
            : T extends (infer A)[]
              ? TArg<A>[]
              : T extends readonly (infer A)[]
                ? readonly TArg<A>[]
                : T extends Promise<infer A>
                  ? Promise<TArg<A>>
                  : T extends object
                    ? { [K in keyof T]: TArg<T[K]> }
                    : T
      : TypedArg<T>);
/** Recursively adapts byte-carrying API output types. See {@link TypedArg}. */
export type TRet<T> = T extends unknown
  ? T &
      ([TypedRet<T>] extends [never]
        ? T extends (...args: infer A) => infer R
          ? ((...args: { [K in keyof A]: TArg<A[K]> }) => TRet<R>) & {
              [K in keyof T]: T[K] extends (...args: any) => any ? T[K] : TRet<T[K]>;
            }
          : T extends [infer A, ...infer R]
            ? [TRet<A>, ...{ [K in keyof R]: TRet<R[K]> }]
            : T extends readonly [infer A, ...infer R]
              ? readonly [TRet<A>, ...{ [K in keyof R]: TRet<R[K]> }]
              : T extends (infer A)[]
                ? TRet<A>[]
                : T extends readonly (infer A)[]
                  ? readonly TRet<A>[]
                  : T extends Promise<infer A>
                    ? Promise<TRet<A>>
                    : T extends object
                      ? { [K in keyof T]: TRet<T[K]> }
                      : T
        : TypedRet<T>)
  : never;
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
const err = (message = '', E: ErrorConstructor = Error): never => {
  const e = new E(message);
  const { captureStackTrace } = Error as ErrorConstructor & {
    captureStackTrace?: (targetObject: object, constructorOpt?: Function) => void;
  };
  if (typeof captureStackTrace === 'function') captureStackTrace(e, err);
  throw e;
};
// Plain `instanceof Uint8Array` is too strict for some Buffer / proxy / cross-realm cases. The
// fallback still requires a real ArrayBuffer view so plain JSON-deserialized `{ constructor: ... }`
// spoofing is rejected, and `BYTES_PER_ELEMENT === 1` keeps the fallback on byte-oriented views.
const isBytes = (a: unknown): a is Bytes =>
  a instanceof Uint8Array ||
  (ArrayBuffer.isView(a) &&
    a.constructor.name === 'Uint8Array' &&
    (a as Bytes).BYTES_PER_ELEMENT === 1);
/** Asserts something is Bytes. */
const abytes = (value: TArg<Bytes>, length?: number, title: string = ''): TRet<Bytes> => {
  const bytes = isBytes(value);
  const len = value?.length;
  const needsLen = length !== undefined;
  if (!bytes || (needsLen && len !== length)) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : '';
    const got = bytes ? `length=${len}` : `type=${typeof value}`;
    const msg = prefix + 'expected Uint8Array' + ofLen + ', got ' + got;
    return bytes ? err(msg, RangeError) : err(msg, TypeError);
  }
  return value as TRet<Bytes>;
};
/** create Uint8Array */
const u8n = (len: number): TRet<Bytes> => new Uint8Array(len) as TRet<Bytes>;
// Callers keep values non-negative and within the requested width; padStart() won't truncate over-wide inputs.
const padh = (n: number | bigint, pad: number) => n.toString(16).padStart(pad, '0');
/** Render bytes as lowercase hex. */
const bytesToHex = (b: TArg<Bytes>): string => {
  let hex = '';
  for (const e of abytes(b)) hex += padh(e, 2);
  return hex;
};
const C = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 } as const; // ASCII characters
// Strict ASCII nibble parser: non-ASCII hex lookalikes are rejected as undefined.
// prettier-ignore
const _ch = (ch: number): number | undefined =>
  ch >= C._0 && ch <= C._9 ? ch - C._0 // '2' => 50-48
  : ch >= C.A && ch <= C.F ? ch - (C.A - 10) // 'B' => 66-(65-10)
  : ch >= C.a && ch <= C.f ? ch - (C.a - 10) // 'b' => 98-(97-10)
  : undefined;
const hexToBytes = (hex: string): TRet<Bytes> => {
  const e = 'hex invalid'; // Strict ASCII hex only, with one generic error for type and parse failures.
  if (typeof hex !== 'string') return err(e);
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
// WebCrypto is available in all modern environments
const subtle = () =>
  globalThis?.crypto?.subtle ?? err('crypto.subtle must be defined, consider polyfill');
// prettier-ignore
const concatBytes = (...arrs: TArg<Bytes[]>): TRet<Bytes> => {
  let len = 0;
  for (const a of arrs) len += abytes(a).length; // validate every input and sum lengths before copying
  const r = u8n(len);
  let pad = 0; // walk through each array,
  for (const a of arrs) r.set(a, pad), pad += a.length; // ensure they have proper type
  return r as TRet<Bytes>;
};
/**
 * WebCrypto OS-level CSPRNG (random number generator).
 * Will throw when not available; large-request ceilings are delegated to getRandomValues().
 */
const randomBytes = (len: number = L): TRet<Bytes> =>
  (globalThis?.crypto).getRandomValues(u8n(len)) as TRet<Bytes>;
const big = BigInt;
const arange = (n: bigint, min: bigint, max: bigint, msg = 'bad number: out of range'): bigint => {
  if (typeof n !== 'bigint') return err(msg, TypeError);
  if (min <= n && n < max) return n;
  return err(msg, RangeError);
};
/** Canonical modular reduction. Callers must provide a positive modulus. */
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
// All exported provider slots are caller-configurable and may be unset or return arbitrary values,
// so wrapper helpers must enforce the exact 32-byte digest contract instead of trusting providers.
const gh = (name: string, a: TArg<Bytes>, b?: TArg<Bytes>): TRet<Bytes> =>
  abytes(callHash(name)(a, b), L, 'digest');
const gha = (name: string, a: TArg<Bytes>, b?: TArg<Bytes>): Promise<TRet<Bytes>> =>
  Promise.resolve(callHash(name)(a, b)).then((r) => abytes(r, L, 'digest'));
/**
 * SHA-256 helper used by the synchronous API.
 * @param msg - message bytes to hash
 * @returns 32-byte SHA-256 digest.
 * @example
 * Hash message bytes after wiring the synchronous SHA-256 implementation.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * secp.hashes.sha256 = sha256;
 * const digest = secp.hash(new Uint8Array([1, 2, 3]));
 * ```
 */
// Public helper validates the message boundary explicitly; the configured provider is still looked
// up dynamically and its output is checked with `gh(...)`.
const hash = (msg: TArg<Bytes>): TRet<Bytes> => gh('sha256', abytes(msg, undefined, 'message'));
// also rejects structurally similar Point values from other realms / bundled copies
const apoint = (p: unknown) => (p instanceof Point ? p : err('Point expected'));
/** Point in 2d xy affine coordinates. */
export type AffinePoint = {
  /** Affine x coordinate. */
  x: bigint;
  /** Affine y coordinate. */
  y: bigint;
};
// ## End of Helpers
// -----------------

/**
 * secp256k1 formula. Koblitz curves are subclass of weierstrass curves with a=0,
 * making it x³+b; callers validate x first.
 */
const koblitz = (x: bigint) => M(M(x * x) * x + _b);
/** assert is element of field mod P (incl. 0 for projective infinity coordinates) */
const FpIsValid = (n: bigint) => arange(n, 0n, P);
/** assert is element of field mod P (excl. 0 where current callers need a non-zero coordinate) */
const FpIsValidNot0 = (n: bigint) => arange(n, 1n, P);
/** assert is element of field mod N (excl. 0), matching the shared BIP340 scalar-failure rule used here */
const FnIsValidNot0 = (n: bigint) => arange(n, 1n, N);
// Shared parity primitive for BIP340 even-y checks and SEC 1 compressed prefixes.
const isEven = (y: bigint) => !(y & 1n);
/** create Uint8Array of byte n */
const u8of = (n: number): TRet<Bytes> => Uint8Array.of(n) as TRet<Bytes>;
/** SEC 1 compressed-prefix helper. Parity only: callers validate y before asking for the prefix byte. */
const getPrefix = (y: bigint) => u8of(isEven(y) ? 0x02 : 0x03);
/** lift_x from BIP340 returns the unique even square root for x³+7.
 * SEC 1 callers still flip it for the odd-prefix branch. */
const lift_x = (x: bigint) => {
  // Let c = x³ + 7 mod p. Fail if x ≥ p. (also fail if x < 1)
  const c = koblitz(FpIsValidNot0(x));
  // r = √c candidate
  // r = c^((p+1)/4) mod p
  // This formula works for fields p = 3 mod 4 -- a special, fast case.
  // Paper: "Square Roots from 1;24,51,10 to Dan Shanks".
  let r = 1n;
  for (let num = c, e = (P + 1n) / 4n; e > 0n; e >>= 1n) {
    // powMod: modular exponentiation.
    if (e & 1n) r = (r * num) % P; // Uses exponentiation by squaring.
    num = (num * num) % P; // Not constant-time.
  }
  if (M(r * r) !== c) err('sqrt invalid'); // check if result is valid
  return isEven(r) ? r : M(-r);
};
/**
 * Point in 3d xyz projective coordinates. 3d takes less inversions than 2d.
 * @param X - X coordinate.
 * @param Y - Y coordinate.
 * @param Z - projective Z coordinate.
 * @example
 * Do point arithmetic with the base point and encode the result as hex.
 * ```ts
 * import { Point } from '@noble/secp256k1';
 * const hex = Point.BASE.double().toHex();
 * ```
 */
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
  /** Returns the shared curve metadata object by reference.
   * It is readonly only at type level, and mutating it won't retarget arithmetic,
   * which already uses module-load snapshots. */
  static CURVE(): WeierstrassOpts<bigint> {
    return secp256k1_CURVE;
  }
  /** Create 3d xyz point from 2d xy. (0, 0) => (0, 1, 0), not (0, 0, 1) */
  static fromAffine(ap: AffinePoint): Point {
    const { x, y } = ap;
    return x === 0n && y === 0n ? I : new Point(x, y, 1n);
  }
  /** Convert Uint8Array or hex string to Point. */
  static fromBytes(bytes: TArg<Bytes>): Point {
    abytes(bytes);
    const { publicKey: comp, publicKeyUncompressed: uncomp } = lengths; // e.g. for 32-byte: 33, 65
    let p: Point | undefined = undefined;
    const length = bytes.length;
    const head = bytes[0];
    const tail = bytes.subarray(1);
    const x = sliceBytesNumBE(tail, 0, L);
    // SEC 1 defines the rare infinity encoding 0x00, but SEC 1 public-key validation rejects
    // infinity. We keep 0x00 rejected here because this parser is reused by verify(), ECDH,
    // and public-key validation helpers, so strict handling applies to all callers by default.
    // Local secp256k1 crosstests show OpenSSL raw point codecs accept 0x00 too.
    // Parse SEC 1 compressed/uncompressed encodings, then finish with assertValidity() before returning.
    if (length === comp && (head === 0x02 || head === 0x03)) {
      // Equation is y² == x³ + ax + b. We calculate y from x.
      // lift_x() returns the even root; SEC 1 0x03 still needs the odd root.
      let y = lift_x(x);
      if (head === 0x03) y = M(-y);
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
   * Uses fake point to mitigate leakage shape in JS, not as a hard constant-time guarantee.
   * @param n scalar by which point is multiplied
   * @param safe safe mode guards against timing attacks; unsafe mode is faster
   */
  multiply(n: bigint, safe = true): Point {
    // Unsafe internal callers may legitimately need 0*P = O during double-scalar multiplication.
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
  toBytes(isCompressed = true): TRet<Bytes> {
    // Same policy as fromBytes(): SEC 1 has the rare infinity encoding 0x00, but we keep ZERO
    // out of this byte surface because callers treat these encodings as public keys by default.
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
const doubleScalarMulUns = (R: TArg<Point>, u1: bigint, u2: bigint): TRet<Point> => {
  return G.multiply(u1, false)
    .add((R as Point).multiply(u2, false))
    .assertValidity() as TRet<Point>;
};
// Inherits byte validation from bytesToHex(); the || '0' fallback keeps empty input mapped to 0n.
const bytesToNumBE = (b: TArg<Bytes>): bigint => big('0x' + (bytesToHex(b) || '0'));
// Callers provide monotone slice bounds; subarray() would otherwise clamp or reinterpret them silently.
const sliceBytesNumBE = (b: TArg<Bytes>, from: number, to: number) =>
  bytesToNumBE(b.subarray(from, to));
const B256 = 2n ** 256n; // secp256k1 is weierstrass curve. Equation is x³ + ax + b.
/** Generic 32-byte big-endian encoder. Must be 0 <= num < B256; call sites need not be field/scalar elements. */
const numTo32b = (num: bigint): TRet<Bytes> => hexToBytes(padh(arange(num, 0n, B256), L2));
/** Normalize private key to scalar (bigint). Verifies scalar is in range 1 <= d < N. */
const secretKeyToScalar = (secretKey: TArg<Bytes>): bigint => {
  const num = bytesToNumBE(abytes(secretKey, L, 'secret key'));
  return arange(num, 1n, N, 'invalid secret key: outside of range');
};
/** For signature malleability, checks the strict upper-half predicate s > floor(N/2). */
const highS = (n: bigint): boolean => n > N >> 1n;
/**
 * Creates a SEC 1 public key from a 32-byte private key.
 * @param privKey - 32-byte secret key.
 * @param isCompressed - return 33-byte compressed SEC 1 encoding when `true`, otherwise 65-byte uncompressed.
 * @returns serialized secp256k1 public key in SEC 1 encoding.
 * @example
 * Derive the serialized public key for a secp256k1 secret key.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * const secretKey = secp.utils.randomSecretKey();
 * const publicKey = secp.getPublicKey(secretKey);
 * ```
 */
const getPublicKey = (privKey: TArg<Bytes>, isCompressed = true): TRet<Bytes> => {
  return G.multiply(secretKeyToScalar(privKey)).toBytes(isCompressed);
};

const isValidSecretKey = (secretKey: TArg<Bytes>): boolean => {
  try {
    return !!secretKeyToScalar(secretKey);
  } catch (error) {
    return false;
  }
};
const isValidPublicKey = (publicKey: TArg<Bytes>, isCompressed?: boolean): boolean => {
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

const assertRecoveryBit = (recovery?: number): number =>
  [0, 1, 2, 3].includes(recovery!) ? recovery! : err('invalid recovery id');
const assertSigFormat = (format?: ECDSASignatureFormat) => {
  if (format === SIG_DER) err('Signature format "der" is not supported: switch to noble-curves');
  if (format != null && format !== SIG_COMPACT && format !== SIG_RECOVERED)
    err('Signature format must be one of: compact, recovered, der');
};
const assertSigLength = (sig: TArg<Bytes>, format: ECDSASignatureFormat = SIG_COMPACT) => {
  assertSigFormat(format);
  const len = lengths.signature + Number(format === SIG_RECOVERED);
  if (sig.length !== len) err(`Signature format "${format}" expects Uint8Array with length ${len}`);
};
/**
 * ECDSA Signature class. Supports only compact 64-byte representation, not DER.
 * @param r - signature `r` scalar.
 * @param s - signature `s` scalar.
 * @param recovery - optional recovery id.
 * @example
 * Build a recovered-format signature object and serialize it.
 * ```ts
 * import { Signature } from '@noble/secp256k1';
 * const bytes = new Signature(1n, 2n, 0).toBytes('recovered');
 * ```
 */
class Signature {
  readonly r: bigint;
  readonly s: bigint;
  readonly recovery?: number;
  constructor(r: bigint, s: bigint, recovery?: number) {
    this.r = FnIsValidNot0(r); // 1 <= r < N
    this.s = FnIsValidNot0(s); // 1 <= s < N
    // Keep recovered Signature objects internally consistent across all construction paths.
    if (recovery != null) this.recovery = assertRecoveryBit(recovery);
    Object.freeze(this);
  }
  static fromBytes(b: TArg<Bytes>, format: ECDSASignatureFormat = SIG_COMPACT): Signature {
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
  toBytes(format: ECDSASignatureFormat = SIG_COMPACT): TRet<Bytes> {
    // Standalone noble-secp256k1 does not implement DER; reject here so direct Signature users
    // don't silently get compact bytes for an unsupported format.
    assertSigFormat(format);
    const { r, s, recovery } = this;
    const res = concatBytes(numTo32b(r), numTo32b(s));
    if (format === SIG_RECOVERED) {
      return concatBytes(u8of(assertRecoveryBit(recovery)), res);
    }
    return res;
  }
}

/**
 * RFC6979: ensure ECDSA msg is X bytes, convert to BigInt.
 * RFC 6979 §2.3.2 says bits2int keeps the leftmost qlen bits and discards the rest.
 * FIPS 186-4 4.6 gives the same leftmost-bit truncation rule. bits2int can produce res>N.
 */
const bits2int = (bytes: TArg<Bytes>): bigint => {
  // The 8 KiB cap is only a local DoS guard. Longer ordinary prehashes must still follow
  // RFC 6979 §2.3.2 truncation instead of being rejected just because blen > qlen.
  if (bytes.length > 8192) err('input is too large');
  const delta = bytes.length * 8 - 256;
  const num = bytesToNumBE(bytes);
  return delta > 0 ? num >> big(delta) : num;
};
/** int2octets can't be used; pads small msgs with 0: BAD for truncation as per RFC vectors */
const bits2int_modN = (bytes: TArg<Bytes>): bigint => modN(bits2int(abytes(bytes)));
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
 * See {@link https://paulmillr.com/posts/deterministic-signatures/ | Deterministic signatures}.
 */
export type ECDSAExtraEntropy = boolean | Bytes;
// todo: better name
const SIG_COMPACT = 'compact';
const SIG_RECOVERED = 'recovered';
const SIG_DER = 'der';
/**
 * - `compact` is the default format
 * - `recovered` is the same as compact, but with an extra byte indicating recovery byte
 * - `der` is not supported; it is included only so unsupported requests can be rejected consistently.
 *   Switch to noble-curves if you need der.
 */
export type ECDSASignatureFormat = 'compact' | 'recovered' | 'der';
/**
 * - `prehash`: (default: true) indicates whether to do sha256(message).
 *   When a custom hash is used, it must be set to `false`.
 */
export type ECDSARecoverOpts = {
  /** Set to `false` when the message is already hashed with a custom digest. */
  prehash?: boolean;
};
/**
 * - `prehash`: (default: true) indicates whether to do sha256(message).
 *   When a custom hash is used, it must be set to `false`.
 * - `lowS`: (default: true) prohibits signatures in the strict upper half (`sig.s > floor(CURVE.n / 2n)`).
 *   Compatible with BTC/ETH. Setting `lowS: false` allows to create malleable signatures,
 *   which is default openssl behavior.
 *   Non-malleable signatures can still be successfully verified in openssl.
 * - `format`: (default: 'compact') 'compact' or 'recovered' with recovery byte
 */
export type ECDSAVerifyOpts = {
  /** Set to `false` when the message is already hashed with a custom digest. */
  prehash?: boolean;
  /** Set to `false` to accept high-S signatures instead of enforcing canonical low-S ones. */
  lowS?: boolean;
  /** Signature encoding accepted by the verifier. */
  format?: ECDSASignatureFormat;
};
/**
 * - `prehash`: (default: true) indicates whether to do sha256(message).
 *   When a custom hash is used, it must be set to `false`.
 * - `lowS`: (default: true) prohibits signatures in the strict upper half (`sig.s > floor(CURVE.n / 2n)`).
 *   Compatible with BTC/ETH. Setting `lowS: false` allows to create malleable signatures,
 *   which is default openssl behavior.
 *   Non-malleable signatures can still be successfully verified in openssl.
 * - `format`: (default: 'compact') 'compact' or 'recovered' with recovery byte
 * - `extraEntropy`: (default: false) creates sigs with increased security, see {@link ECDSAExtraEntropy}
 */
export type ECDSASignOpts = {
  /** Set to `false` when the message is already hashed with a custom digest. */
  prehash?: boolean;
  /** Set to `false` to allow high-S signatures instead of normalizing to low-S form. */
  lowS?: boolean;
  /** Signature encoding produced by the signer. */
  format?: ECDSASignatureFormat;
  /** Extra entropy mixed into RFC6979 nonce generation for hedged signatures. */
  extraEntropy?: ECDSAExtraEntropy;
};

const _sha = 'SHA-256';
/**
 * Hash implementations used by the synchronous and async ECDSA / Schnorr helpers.
 * All slots are configurable API surface; wrapper helpers revalidate that SHA-256 and HMAC-SHA256
 * providers still return exact 32-byte Uint8Array digests.
 * @example
 * Provide sync hash helpers before calling the synchronous signing API.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * import { hmac } from '@noble/hashes/hmac.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * secp.hashes.sha256 = sha256;
 * secp.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);
 * const secretKey = secp.utils.randomSecretKey();
 * const sig = secp.sign(new Uint8Array([1, 2, 3]), secretKey);
 * ```
 */
const hashes = {
  hmacSha256Async: async (key: TArg<Bytes>, message: TArg<Bytes>): Promise<TRet<Bytes>> => {
    const s = subtle();
    const name = 'HMAC';
    const k = await s.importKey('raw', key, { name, hash: { name: _sha } }, false, ['sign']);
    return u8n(await s.sign(name, k, message)) as TRet<Bytes>;
  },
  hmacSha256: undefined as undefined | ((key: TArg<Bytes>, message: TArg<Bytes>) => TRet<Bytes>),
  sha256Async: async (msg: TArg<Bytes>): Promise<TRet<Bytes>> =>
    u8n(await subtle().digest(_sha, msg)) as TRet<Bytes>,
  sha256: undefined as undefined | ((message: TArg<Bytes>) => TRet<Bytes>),
};

// prehash=false means the caller already supplies the digest bytes
// used by sign/verify/recover, and this helper returns the same reference unchanged.
const prepMsg = (
  msg: TArg<Bytes>,
  opts: TArg<ECDSARecoverOpts>,
  async_: boolean
): TRet<Bytes | Promise<Bytes>> => {
  const message = abytes(msg, undefined, 'message');
  if (!opts.prehash) return message;
  return async_ ? gha('sha256Async', message) : gh('sha256', message);
};

type Pred<T> = (v: Bytes) => T | undefined;
const NULL = /* @__PURE__ */ u8n(0);
const byte0 = /* @__PURE__ */ u8of(0x00);
const byte1 = /* @__PURE__ */ u8of(0x01);
const _maxDrbgIters = 1000;
const _drbgErr = 'drbg: tried max amount of iterations';
// HMAC-DRBG from NIST 800-90. Minimal, non-full-spec - used for RFC6979 signatures.
const hmacDrbg = <T>(seed: TArg<Bytes>, pred: TArg<Pred<T>>): T => {
  let v = u8n(L); // Steps B, C of RFC6979 3.2: set hashLen
  let k = u8n(L); // In our case, it's always equal to L
  let i = 0; // Iterations counter, will throw when over max
  const reset = () => {
    v.fill(1);
    k.fill(0);
  };
  // h = hmac(K || V || ...). The configured provider is still checked on every call because the
  // exported slot can be replaced or unset at runtime.
  const h = (...b: TArg<Bytes[]>) => gh('hmacSha256', k, concatBytes(v, ...b));
  const reseed = (seed: TArg<Bytes> = NULL) => {
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
    return v; // One block is enough here because secp256k1 qlen and SHA-256 hlen are both 32 bytes.
  };
  reset();
  reseed(seed); // Steps D-G
  let res: T | undefined = undefined; // Step H: grind until k is in [1..n-1]
  // `pred` receives the live V buffer from gen(); it must treat that input as read-only and
  // return independent bytes, because reset() scrubs the DRBG state before hmacDrbg returns.
  while (!(res = (pred as Pred<T>)(gen()))) reseed(); // test predicate until it returns ok
  reset();
  return res!;
};

// Identical to hmacDrbg, but async: uses built-in WebCrypto
const hmacDrbgAsync = async <T>(seed: TArg<Bytes>, pred: TArg<Pred<T>>): Promise<T> => {
  let v = u8n(L); // Steps B, C of RFC6979 3.2: set hashLen
  let k = u8n(L); // In our case, it's always equal to L
  let i = 0; // Iterations counter, will throw when over max
  const reset = () => {
    v.fill(1);
    k.fill(0);
  };
  // h = hmac(K || V || ...). Async provider lookup still goes through `callHash(...)` because the
  // exported slot can be replaced or unset at runtime.
  const h = (...b: TArg<Bytes[]>) => gha('hmacSha256Async', k, concatBytes(v, ...b));
  const reseed = async (seed: TArg<Bytes> = NULL) => {
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
    return v; // Same one-block shortcut: secp256k1 qlen and SHA-256 hlen are both 32 bytes here.
  };
  reset();
  await reseed(seed); // Steps D-G
  let res: T | undefined = undefined; // Step H: grind until k is in [1..n-1]
  // Same contract as sync hmacDrbg(): pred sees the live V buffer and must not mutate or return it.
  while (!(res = (pred as Pred<T>)(await gen()))) await reseed(); // test predicate until it returns ok
  reset();
  return res!;
};

// RFC6979 signature generation, preparation step.
// Follows [SEC1](https://secg.org/sec1-v2.pdf) 4.1.3 & RFC6979.
const _sign = <T>(
  messageHash: TArg<Bytes>,
  secretKey: TArg<Bytes>,
  opts: TArg<ECDSASignOpts>,
  hmacDrbg: TArg<(seed: Bytes, pred: Pred<Bytes>) => T>
): T => {
  let { lowS, extraEntropy } = opts; // generates low-s sigs by default
  // RFC6979 3.2: we skip step A
  const int2octets = numTo32b; // int to octets
  const h1i = bits2int_modN(messageHash); // msg bigint
  const h1o = int2octets(h1i); // msg octets
  const d = secretKeyToScalar(secretKey); // validate private key, convert to bigint
  const seedArgs: Bytes[] = [int2octets(d), h1o]; // Step D of RFC6979 3.2
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
  const k2sig = (kBytes: TArg<Bytes>): TRet<Bytes | undefined> => {
    // RFC 6979 Section 3.2, step 3: k = bits2int(T)
    // Important: all mod() calls here must be done over N
    const k = bits2int(kBytes);
    if (!(1n <= k && k < N)) return; // Valid scalars (including k) must be in 1..N-1
    const ik = invert(k, N); // k^-1 mod n
    const q = G.multiply(k).toAffine(); // q = k⋅G
    const r = modN(q.x); // r = q.x mod n
    // RFC 6979 §2.4 step 3 / §3.4 only spell out retry for r = 0.
    // FIPS 186-5 §6.4.1 step 11 says deterministic ECDSA should fail on r = 0 or s = 0, but
    // that restart-from-scratch note does not apply here: hmacDrbg() keeps advancing through one
    // RFC6979 stream until k2sig() accepts a candidate, instead of restarting from the same seed.
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
  return (hmacDrbg as (seed: Bytes, pred: Pred<Bytes>) => T)(seed, k2sig);
};

// Follows [SEC1](https://secg.org/sec1-v2.pdf) 4.1.4.
const _verify = (
  sig: TArg<Bytes>,
  messageHash: TArg<Bytes>,
  publicKey: TArg<Bytes>,
  opts: TArg<ECDSAVerifyOpts> = {}
) => {
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

const setDefaults = (opts: TArg<ECDSASignOpts>) => {
  // Inline defaults keep the same returned keys/values while avoiding the extra defaults object.
  return {
    lowS: opts.lowS ?? true,
    prehash: opts.prehash ?? true,
    format: opts.format ?? SIG_COMPACT,
    extraEntropy: opts.extraEntropy ?? false,
  };
};

/**
 * Sign a message using secp256k1. Sync: uses `hashes.sha256` and `hashes.hmacSha256`.
 * Prehashes message with sha256, disable using `prehash: false`.
 * @param message - message bytes to sign.
 * @param secretKey - 32-byte secret key.
 * @param opts - See {@link ECDSASignOpts} for details. Enabling {@link ECDSAExtraEntropy} improves security.
 * @returns ECDSA signature encoded according to `opts.format`.
 * @example
 * Sign a message using secp256k1.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * import { hmac } from '@noble/hashes/hmac.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * secp.hashes.sha256 = sha256;
 * secp.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);
 * const secretKey = secp.utils.randomSecretKey();
 * const msg = new TextEncoder().encode('hello noble');
 * secp.sign(msg, secretKey);
 * secp.sign(msg, secretKey, { extraEntropy: true });
 * secp.sign(msg, secretKey, { format: 'recovered' });
 * ```
 */
const sign = (
  message: TArg<Bytes>,
  secretKey: TArg<Bytes>,
  opts: TArg<ECDSASignOpts> = {}
): TRet<Bytes> => {
  opts = setDefaults(opts);
  assertSigFormat(opts.format);
  const msg = prepMsg(message, opts, false) as Bytes;
  return _sign<TRet<Bytes>>(msg, secretKey, opts, hmacDrbg);
};

/**
 * Sign a message using secp256k1. Async: uses built-in WebCrypto hashes.
 * Prehashes message with sha256, disable using `prehash: false`.
 * @param message - message bytes to sign.
 * @param secretKey - 32-byte secret key.
 * @param opts - See {@link ECDSASignOpts} for details. Enabling {@link ECDSAExtraEntropy} improves security.
 * @returns ECDSA signature encoded according to `opts.format`.
 * @example
 * Sign a message using secp256k1 with the async WebCrypto path.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * import { keccak_256 } from '@noble/hashes/sha3.js';
 * const secretKey = secp.utils.randomSecretKey();
 * const msg = new TextEncoder().encode('hello noble');
 * await secp.signAsync(msg, secretKey);
 * await secp.signAsync(keccak_256(msg), secretKey, { prehash: false });
 * await secp.signAsync(msg, secretKey, { extraEntropy: true });
 * await secp.signAsync(msg, secretKey, { format: 'recovered' });
 * ```
 */
const signAsync = async (
  message: TArg<Bytes>,
  secretKey: TArg<Bytes>,
  opts: TArg<ECDSASignOpts> = {}
): Promise<TRet<Bytes>> => {
  opts = setDefaults(opts);
  assertSigFormat(opts.format);
  const msg = (await prepMsg(message, opts, true)) as Bytes;
  return _sign<Promise<TRet<Bytes>>>(msg, secretKey, opts, hmacDrbgAsync);
};

/**
 * Verify a signature using secp256k1. Sync: uses `hashes.sha256` and `hashes.hmacSha256`.
 * @param signature - default is 64-byte `compact` format; also see {@link ECDSASignatureFormat}.
 * @param message - message which was signed. Keep in mind `prehash` from opts.
 * @param publicKey - public key that should verify the signature.
 * @param opts - See {@link ECDSAVerifyOpts} for details.
 * @returns `true` when the signature is valid. Unsupported format configuration still
 * throws instead of returning `false`.
 * @example
 * Verify a signature using secp256k1.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * import { hmac } from '@noble/hashes/hmac.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * import { keccak_256 } from '@noble/hashes/sha3.js';
 * secp.hashes.sha256 = sha256;
 * secp.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);
 * const secretKey = secp.utils.randomSecretKey();
 * const msg = new TextEncoder().encode('hello noble');
 * const publicKey = secp.getPublicKey(secretKey);
 * const sig = secp.sign(msg, secretKey);
 * const sigr = secp.sign(msg, secretKey, { format: 'recovered' });
 * secp.verify(sig, msg, publicKey);
 * secp.verify(sig, keccak_256(msg), publicKey, { prehash: false });
 * secp.verify(sig, msg, publicKey, { lowS: false });
 * secp.verify(sigr, msg, publicKey, { format: 'recovered' });
 * ```
 */
const verify = (
  signature: TArg<Bytes>,
  message: TArg<Bytes>,
  publicKey: TArg<Bytes>,
  opts: TArg<ECDSAVerifyOpts> = {}
): boolean => {
  opts = setDefaults(opts);
  const msg = prepMsg(message, opts, false) as Bytes;
  return _verify(signature, msg, publicKey, opts);
};

/**
 * Verify a signature using secp256k1. Async: uses built-in WebCrypto hashes.
 * @param sig - default is 64-byte `compact` format; also see {@link ECDSASignatureFormat}.
 * @param message - message which was signed. Keep in mind `prehash` from opts.
 * @param publicKey - public key that should verify the signature.
 * @param opts - See {@link ECDSAVerifyOpts} for details.
 * @returns `true` when the signature is valid. Unsupported format configuration still
 * throws instead of returning `false`.
 * @example
 * Verify a signature using secp256k1 with the async WebCrypto path.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * import { keccak_256 } from '@noble/hashes/sha3.js';
 * const secretKey = secp.utils.randomSecretKey();
 * const msg = new TextEncoder().encode('hello noble');
 * const publicKey = secp.getPublicKey(secretKey);
 * const sig = await secp.signAsync(msg, secretKey);
 * const sigr = await secp.signAsync(msg, secretKey, { format: 'recovered' });
 * await secp.verifyAsync(sig, msg, publicKey);
 * await secp.verifyAsync(sigr, msg, publicKey, { format: 'recovered' });
 * await secp.verifyAsync(sig, keccak_256(msg), publicKey, { prehash: false });
 * ```
 */
const verifyAsync = async (
  sig: TArg<Bytes>,
  message: TArg<Bytes>,
  publicKey: TArg<Bytes>,
  opts: TArg<ECDSAVerifyOpts> = {}
): Promise<boolean> => {
  opts = setDefaults(opts);
  const msg = (await prepMsg(message, opts, true)) as Bytes;
  return _verify(sig, msg, publicKey, opts);
};

const _recover = (signature: TArg<Bytes>, messageHash: TArg<Bytes>): TRet<Bytes> => {
  const sig = Signature.fromBytes(signature, 'recovered');
  const { r, s, recovery } = sig;
  // 0 or 1 recovery id determines sign of "y" coordinate.
  // 2 or 3 means q.x was >N.
  assertRecoveryBit(recovery);
  // SEC 1 recovery derives e through the same truncation path as verification, so prehash:false
  // must accept long digests here too instead of hard-requiring 32-byte SHA-256 input.
  const h = bits2int_modN(abytes(messageHash, undefined, 'msgHash')); // Truncate hash
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
 * Follows {@link https://secg.org/sec1-v2.pdf | SEC1} 4.1.6.
 * @param signature - recovered-format signature from `sign(..., { format: 'recovered' })`.
 * @param message - signed message bytes.
 * @param opts - See {@link ECDSARecoverOpts} for details.
 * @returns recovered public key bytes.
 * @example
 * Recover a secp256k1 public key from a recovered-format signature.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * import { hmac } from '@noble/hashes/hmac.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * secp.hashes.sha256 = sha256;
 * secp.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);
 * const secretKey = secp.utils.randomSecretKey();
 * const message = new Uint8Array([1, 2, 3]);
 * const sig = secp.sign(message, secretKey, { format: 'recovered' });
 * secp.recoverPublicKey(sig, message);
 * ```
 */
const recoverPublicKey = (
  signature: TArg<Bytes>,
  message: TArg<Bytes>,
  opts: TArg<ECDSARecoverOpts> = {}
): TRet<Bytes> => {
  const msg = prepMsg(message, setDefaults(opts), false) as Bytes;
  return _recover(signature, msg);
};

/**
 * Async ECDSA public key recovery. Requires msg hash and recovery id.
 * @param signature - recovered-format signature from `signAsync(..., { format: 'recovered' })`.
 * @param message - signed message bytes.
 * @param opts - See {@link ECDSARecoverOpts} for details.
 * @returns recovered public key bytes.
 * @example
 * Recover a secp256k1 public key from a recovered-format signature with the async API.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * const secretKey = secp.utils.randomSecretKey();
 * const message = new Uint8Array([1, 2, 3]);
 * const sig = await secp.signAsync(message, secretKey, { format: 'recovered' });
 * await secp.recoverPublicKeyAsync(sig, message);
 * ```
 */
const recoverPublicKeyAsync = async (
  signature: TArg<Bytes>,
  message: TArg<Bytes>,
  opts: TArg<ECDSARecoverOpts> = {}
): Promise<TRet<Bytes>> => {
  const msg = (await prepMsg(message, setDefaults(opts), true)) as Bytes;
  return _recover(signature, msg);
};

/**
 * Elliptic Curve Diffie-Hellman (ECDH) on secp256k1.
 * Result is **NOT hashed** and returns the serialized shared point (compressed by default),
 * not the SEC 1 x-only primitive `z = x_P`.
 * secp256k1 has cofactor `h = 1`, so there is no separate cofactor-ECDH distinction here.
 * @param secretKeyA - local 32-byte secret key.
 * @param publicKeyB - peer public key.
 * @param isCompressed - return 33-byte compressed output when `true`.
 * @returns shared secret point bytes.
 * @example
 * Derive a shared secp256k1 secret with ECDH.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * const alice = secp.utils.randomSecretKey();
 * const bob = secp.utils.randomSecretKey();
 * const shared = secp.getSharedSecret(alice, secp.getPublicKey(bob));
 * ```
 */
const getSharedSecret = (
  secretKeyA: TArg<Bytes>,
  publicKeyB: TArg<Bytes>,
  isCompressed = true
): TRet<Bytes> => {
  return Point.fromBytes(publicKeyB).multiply(secretKeyToScalar(secretKeyA)).toBytes(isCompressed);
};

// FIPS 186-5 Appendix A.4.1 style key generation reduces a wide random integer mod (n - 1) and adds 1.
// The 48-byte minimum keeps the secp256k1 bias bound below the appendix's epsilon <= 2^-64 target.
const randomSecretKey = (seed?: TArg<Bytes>): TRet<Bytes> => {
  seed = seed === undefined ? randomBytes(lengths.seed) : seed;
  abytes(seed);
  // Keep the public range text aligned with the enforced 48-byte FIPS floor.
  if (seed.length < lengths.seed || seed.length > 1024) return err('expected 48-1024b', RangeError);
  const num = M(bytesToNumBE(seed), N - 1n);
  return numTo32b(num + 1n);
};

type KeysSecPub = { secretKey: Bytes; publicKey: Bytes };
type KeygenFn = (seed?: TArg<Bytes>) => TRet<KeysSecPub>;
const createKeygen =
  (getPublicKey: TArg<(secretKey: Bytes) => Bytes>) =>
  (seed?: TArg<Bytes>): TRet<KeysSecPub> => {
    const secretKey = randomSecretKey(seed);
    return {
      secretKey,
      publicKey: (getPublicKey as (secretKey: Bytes) => Bytes)(secretKey),
    } as TRet<KeysSecPub>;
  };
/**
 * Generates a secp256k1 keypair.
 * @param seed - optional entropy seed.
 * @returns keypair with `secretKey` and `publicKey`.
 * @example
 * Generate a secp256k1 keypair for sync signing.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * import { hmac } from '@noble/hashes/hmac.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * secp.hashes.sha256 = sha256;
 * secp.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);
 * const { secretKey, publicKey } = secp.keygen();
 * ```
 */
const keygen: KeygenFn = /* @__PURE__ */ createKeygen(getPublicKey);

/**
 * Math, hex, byte helpers. Not in `utils` because utils share API with noble-curves.
 * @example
 * Convert bytes to a hex string with the low-level helper namespace.
 * ```ts
 * import { etc } from '@noble/secp256k1';
 * const hex = etc.bytesToHex(new Uint8Array([1, 2, 3]));
 * ```
 */
const etc: {
  hexToBytes: (hex: string) => TRet<Bytes>;
  bytesToHex: (bytes: TArg<Bytes>) => string;
  concatBytes: (...arrs: TArg<Bytes[]>) => TRet<Bytes>;
  bytesToNumberBE: (a: TArg<Bytes>) => bigint;
  numberToBytesBE: (n: bigint) => TRet<Bytes>;
  mod: (a: bigint, md?: bigint) => bigint;
  invert: typeof invert;
  randomBytes: (len?: number) => TRet<Bytes>;
  secretKeyToScalar: typeof secretKeyToScalar;
  abytes: typeof abytes;
} = /* @__PURE__ */ Object.freeze({
  hexToBytes,
  bytesToHex,
  concatBytes,
  bytesToNumberBE: bytesToNumBE,
  numberToBytesBE: numTo32b,
  mod: M as (a: bigint, md?: bigint) => bigint,
  invert: invert as typeof invert, // math utilities; keep public alias type aligned with runtime
  randomBytes,
  secretKeyToScalar: secretKeyToScalar as typeof secretKeyToScalar,
  abytes: abytes as typeof abytes,
});

/**
 * Curve-specific key utilities.
 * @example
 * Generate a fresh secret key and derive its public key.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * const secretKey = secp.utils.randomSecretKey();
 * const publicKey = secp.getPublicKey(secretKey);
 * ```
 */
const utils: {
  isValidSecretKey: typeof isValidSecretKey;
  isValidPublicKey: typeof isValidPublicKey;
  randomSecretKey: typeof randomSecretKey;
} = /* @__PURE__ */ Object.freeze({
  isValidSecretKey: isValidSecretKey as typeof isValidSecretKey,
  isValidPublicKey: isValidPublicKey as typeof isValidPublicKey,
  randomSecretKey: randomSecretKey as typeof randomSecretKey, // preserve the optional seeded call
});

// Schnorr signatures are superior to ECDSA from above. Below is Schnorr-specific BIP0340 code.
// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
// Internal BIP340 tag names are ASCII-only here, so charCodeAt() is enough; this is not a general UTF-8 encoder.
const getTag = (tag: string): TRet<Bytes> =>
  Uint8Array.from('BIP0340/' + tag, (c) => c.charCodeAt(0)) as TRet<Bytes>;
const T_AUX = 'aux';
const T_NONCE = 'nonce';
const T_CHALLENGE = 'challenge';
// Both SHA-256 provider slots are configurable, so tag hashing still goes through the checked
// wrappers even though the built-in defaults are deterministic and the tag bytes are ASCII-only.
const taggedHash = (tag: string, ...messages: TArg<Bytes[]>): TRet<Bytes> => {
  const tagH = gh('sha256', getTag(tag));
  return gh('sha256', concatBytes(tagH, tagH, ...messages));
};
// Async twin of taggedHash with the same checked provider boundary.
const taggedHashAsync = (tag: string, ...messages: TArg<Bytes[]>): Promise<TRet<Bytes>> =>
  gha('sha256Async', getTag(tag)).then((tagH) =>
    gha('sha256Async', concatBytes(tagH, tagH, ...messages))
  );

// BIP340 PubKey(sk) = bytes(d'⋅G), where bytes(P) is bytes(x(P)); signing also normalizes
// d to the equivalent scalar whose point has even y so the x-only public key stays canonical.
const extpubSchnorr = (priv: TArg<Bytes>) => {
  const d_ = secretKeyToScalar(priv);
  const p = G.multiply(d_); // P = d'⋅G; 0 < d' < n check is done inside
  const { x, y } = p.assertValidity().toAffine(); // validate Point is not at infinity
  const d = isEven(y) ? d_ : modN(-d_);
  const px = numTo32b(x);
  return { d, px };
};

const bytesModN = (bytes: TArg<Bytes>) => modN(bytesToNumBE(bytes));
const challenge = (...args: TArg<Bytes[]>): bigint => bytesModN(taggedHash(T_CHALLENGE, ...args));
const challengeAsync = async (...args: TArg<Bytes[]>): Promise<bigint> =>
  bytesModN(await taggedHashAsync(T_CHALLENGE, ...args));

/** Schnorr public key is just `x` coordinate of Point as per BIP340. */
const pubSchnorr = (secretKey: TArg<Bytes>): TRet<Bytes> => {
  return extpubSchnorr(secretKey).px; // d'=int(sk). Fail if d'=0 or d'≥n. Ret bytes(d'⋅G)
};

const keygenSchnorr: KeygenFn = /* @__PURE__ */ createKeygen(pubSchnorr);

// Common preparation fn for both sync and async signing
const prepSigSchnorr = (message: TArg<Bytes>, secretKey: TArg<Bytes>, auxRand: TArg<Bytes>) => {
  const { px, d } = extpubSchnorr(secretKey);
  return { m: abytes(message), px, d, a: abytes(auxRand, L) };
};

const extractK = (rand: TArg<Bytes>): TRet<{ rx: Bytes; k: bigint }> => {
  const k_ = bytesModN(rand); // Let k' = int(rand) mod n
  if (k_ === 0n) err('sign failed: k is zero'); // Fail if k' = 0.
  const { px, d } = extpubSchnorr(numTo32b(k_)); // Let R = k'⋅G.
  return { rx: px, k: d } as TRet<{ rx: Bytes; k: bigint }>;
};

// Common signature creation helper
const createSigSchnorr = (k: bigint, px: TArg<Bytes>, e: bigint, d: bigint): TRet<Bytes> => {
  return concatBytes(px, numTo32b(modN(k + e * d)));
};

const E_INVSIG = 'invalid signature produced';
/**
 * Creates Schnorr signature as per BIP340. Verifies itself before returning anything.
 * auxRand is optional and defaults to fresh 32-byte randomness; it is not the sole source of
 * k generation, so bad CSPRNG won't be the only entropy source.
 */
const signSchnorr = (
  message: TArg<Bytes>,
  secretKey: TArg<Bytes>,
  auxRand: TArg<Bytes> = randomBytes(L)
): TRet<Bytes> => {
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
  message: TArg<Bytes>,
  secretKey: TArg<Bytes>,
  auxRand: TArg<Bytes> = randomBytes(L)
): Promise<TRet<Bytes>> => {
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
  signature: TArg<Bytes>,
  message: TArg<Bytes>,
  publicKey: TArg<Bytes>,
  challengeFn: TArg<(...args: Bytes[]) => bigint | Promise<bigint>>
): boolean | Promise<boolean> => {
  const sig = abytes(signature, L2, 'signature');
  const msg = abytes(message, undefined, 'message');
  const pub = abytes(publicKey, L, 'publicKey');
  try {
    // lift_x from BIP340. Convert 32-byte x coordinate to elliptic curve point.
    // Fail if x ≥ p. Let c = x³ + 7 mod p.
    const x = bytesToNumBE(pub);
    const y = lift_x(x); // lift_x already returns the unique even root required by BIP340.
    const P_ = new Point(x, y, 1n).assertValidity();
    const px = numTo32b(P_.toAffine().x);
    // P = lift_x(int(pk)); fail if that fails
    const r = sliceBytesNumBE(sig, 0, L); // Let r = int(sig[0:32]); fail if r ≥ p.
    arange(r, 1n, P);
    const s = sliceBytesNumBE(sig, L, L2); // Let s = int(sig[32:64]); fail if s ≥ n.
    // Stricter than BIP-340/libsecp256k1, which only reject s >= n. Honest signing reaches
    // s = 0 only with negligible probability (k + e*d ≡ 0 mod n), so treat zero-s inputs as
    // crafted edge cases and fail closed instead of carrying that extra verification surface.
    arange(s, 1n, N);
    const i = concatBytes(numTo32b(r), px, msg);
    // int(challenge(bytes(r)||bytes(P)||m))%n
    return callSyncAsyncFn(
      (challengeFn as (...args: Bytes[]) => bigint | Promise<bigint>)(i),
      (e) => {
        const { x, y } = doubleScalarMulUns(P_, s, modN(-e)).toAffine(); // R = s⋅G - e⋅P
        if (!isEven(y) || x !== r) return false; // -eP == (n-e)P
        return true; // Fail if is_infinite(R) / not has_even_y(R) / x(R) ≠ r.
      }
    );
  } catch (error) {
    return false;
  }
};

/** Verifies Schnorr signature. Sync wrapper returns false for post-validation failures
 * after the initial byte checks. */
const verifySchnorr = (s: TArg<Bytes>, m: TArg<Bytes>, p: TArg<Bytes>): boolean =>
  _verifSchnorr(s, m, p, challenge) as boolean;
/** Async Schnorr verification. Curve/encoding failures after the initial byte checks still
 * become false, but async backend failures reject the promise. Missing crypto.subtle is a
 * runtime/backend error, not an "invalid signature" result, so we surface it instead of
 * turning it into false. */
const verifySchnorrAsync = async (
  s: TArg<Bytes>,
  m: TArg<Bytes>,
  p: TArg<Bytes>
): Promise<boolean> => _verifSchnorr(s, m, p, challengeAsync) as Promise<boolean>;

/**
 * BIP340 Schnorr helpers over secp256k1.
 * @example
 * Sign and verify a BIP340 Schnorr signature.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * secp.hashes.sha256 = sha256;
 * const secretKey = secp.utils.randomSecretKey();
 * const message = new Uint8Array([1, 2, 3]);
 * const sig = secp.schnorr.sign(message, secretKey);
 * const publicKey = secp.schnorr.getPublicKey(secretKey);
 * const isValid = secp.schnorr.verify(sig, message, publicKey);
 * ```
 */
const schnorr: {
  keygen: typeof keygenSchnorr;
  getPublicKey: typeof pubSchnorr;
  sign: typeof signSchnorr;
  verify: typeof verifySchnorr;
  signAsync: typeof signSchnorrAsync;
  verifyAsync: typeof verifySchnorrAsync;
} = /* @__PURE__ */ Object.freeze({
  keygen: keygenSchnorr,
  getPublicKey: pubSchnorr,
  sign: signSchnorr,
  verify: verifySchnorr,
  signAsync: signSchnorrAsync,
  verifyAsync: verifySchnorrAsync,
});

const __TEST: TRet<{
  lift_x: (x: bigint) => Point;
  extractK: (rand: TArg<Bytes>) => TRet<{ rx: Bytes; k: bigint }>;
}> = /* @__PURE__ */ (() =>
  Object.freeze({
    // Shared tests expect the BIP340 helper to expose the canonical even-y point, not just the root.
    lift_x: (x: bigint): TRet<Point> => Point.fromAffine({ x, y: lift_x(x) }) as TRet<Point>,
    extractK: (rand: TArg<Bytes>): TRet<{ rx: Bytes; k: bigint }> => extractK(rand),
  }))();

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
// Branch-shaped negate helper for wNAF; not a hard constant-time primitive in JavaScript.
const ctneg = (cnd: boolean, p: TArg<Point>) => {
  const n = (p as Point).negate();
  return cnd ? n : (p as Point);
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
const wNAF = (n: bigint): TRet<{ p: Point; f: Point }> => {
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
  return { p, f } as TRet<{ p: Point; f: Point }>; // return both real and fake points for JIT/leakage-shape symmetry
};

// !! Remove the export below to easily use in REPL / browser console
export {
  etc,
  getPublicKey,
  getSharedSecret,
  hash,
  hashes,
  keygen,
  Point,
  recoverPublicKey,
  recoverPublicKeyAsync,
  schnorr,
  sign,
  signAsync,
  Signature,
  utils,
  verify,
  verifyAsync,
  __TEST,
};
