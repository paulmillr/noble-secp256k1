/*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
// https://www.secg.org/sec2-v2.pdf

// Uses built-in crypto module from node.js to generate randomness / hmac-sha256.
// In browser the line is automatically removed during build time: uses crypto.subtle instead.
import * as nodeCrypto from 'crypto';

// Be friendly to bad ECMAScript parsers by not using bigint literals like 123n
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _3n = BigInt(3);
const _8n = BigInt(8);

// Curve fomula is y² = x³ + ax + b
const CURVE = Object.freeze({
  // Params: a, b
  a: _0n,
  b: BigInt(7),
  // Field over which we'll do calculations. Verify with:
  //   console.log(CURVE.P === (2n**256n - 2n**32n - 2n**9n - 2n**8n-2n**7n-2n**6n-2n**4n - 1n))
  P: BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'),
  // Curve order, total count of valid points in the field. Verify with:
  //   console.log(CURVE.n === (2n**256n - 432420386565659656852420866394968145599n))
  n: BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),
  // Cofactor. It's 1, so other subgroups don't exist, and default subgroup is prime-order
  h: _1n,
  // Base point (x, y) aka generator point
  Gx: BigInt('55066263022277343669578718895168534326250603453777594175500187360389116729240'),
  Gy: BigInt('32670510020758816978083085130507043184471273380659243275938904335757337482424'),
  // For endomorphism, see below
  beta: BigInt('0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee'),
});

// Cleaner js output if that's on a separate line.
export { CURVE };

/**
 * y² = x³ + ax + b: Short weistrass curve formula
 * @returns y²
 */
function weistrass(x: bigint): bigint {
  const { a, b } = CURVE;
  const x2 = mod(x * x);
  const x3 = mod(x2 * x);
  return mod(x3 + a * x + b);
}

// We accept hex strings besides Uint8Array for simplicity
type Hex = Uint8Array | string;
// Very few implementations accept numbers, we do it to ease learning curve
type PrivKey = Hex | bigint | number;
// 33/65-byte ECDSA key, or 32-byte Schnorr key - not interchangeable
type PubKey = Hex | Point;
// ECDSA signature
type Sig = Hex | Signature;

/**
 * Always true for secp256k1.
 * We're including it here if you'll want to reuse code to support
 * different curve (e.g. secp256r1) - just set it to false then.
 * Endomorphism only works for Koblitz curves with a == 0.
 * It improves efficiency:
 * Uses 2x less RAM, speeds up precomputation by 2x and ECDH / sign key recovery by 20%.
 * Should always be used for Jacobian's double-and-add multiplication.
 * For affines cached multiplication, it trades off 1/2 init time & 1/3 ram for 20% perf hit.
 * https://gist.github.com/paulmillr/eb670806793e84df628a7c434a873066
 */
const USE_ENDOMORPHISM = CURVE.a === _0n;

class ShaError extends Error {
  constructor(message: string) {
    super(message);
  }
}

/**
 * Jacobian Point works in 3d / jacobi coordinates: (x, y, z) ∋ (x=x/z², y=y/z³)
 * Default Point works in 2d / affine coordinates: (x, y)
 * We're doing calculations in jacobi, because its operations don't require costly inversion.
 */
class JacobianPoint {
  constructor(readonly x: bigint, readonly y: bigint, readonly z: bigint) {}

  static readonly BASE = new JacobianPoint(CURVE.Gx, CURVE.Gy, _1n);
  static readonly ZERO = new JacobianPoint(_0n, _1n, _0n);
  static fromAffine(p: Point): JacobianPoint {
    if (!(p instanceof Point)) {
      throw new TypeError('JacobianPoint#fromAffine: expected Point');
    }
    return new JacobianPoint(p.x, p.y, _1n);
  }

  /**
   * Takes a bunch of Jacobian Points but executes only one
   * invert on all of them. invert is very slow operation,
   * so this improves performance massively.
   */
  static toAffineBatch(points: JacobianPoint[]): Point[] {
    const toInv = invertBatch(points.map((p) => p.z));
    return points.map((p, i) => p.toAffine(toInv[i]));
  }

  static normalizeZ(points: JacobianPoint[]): JacobianPoint[] {
    return JacobianPoint.toAffineBatch(points).map(JacobianPoint.fromAffine);
  }

  /**
   * Compare one point to another.
   */
  equals(other: JacobianPoint): boolean {
    if (!(other instanceof JacobianPoint)) throw new TypeError('JacobianPoint expected');
    const { x: X1, y: Y1, z: Z1 } = this;
    const { x: X2, y: Y2, z: Z2 } = other;
    const Z1Z1 = mod(Z1 * Z1);
    const Z2Z2 = mod(Z2 * Z2);
    const U1 = mod(X1 * Z2Z2);
    const U2 = mod(X2 * Z1Z1);
    const S1 = mod(mod(Y1 * Z2) * Z2Z2);
    const S2 = mod(mod(Y2 * Z1) * Z1Z1);
    return U1 === U2 && S1 === S2;
  }

  /**
   * Flips point to one corresponding to (x, -y) in Affine coordinates.
   */
  negate(): JacobianPoint {
    return new JacobianPoint(this.x, mod(-this.y), this.z);
  }

  // Fast algo for doubling 2 Jacobian Points when curve's a=0.
  // Note: cannot be reused for other curves when a != 0.
  // From: http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
  // Cost: 2M + 5S + 6add + 3*2 + 1*3 + 1*8.
  double(): JacobianPoint {
    const { x: X1, y: Y1, z: Z1 } = this;
    const A = mod(X1 * X1);
    const B = mod(Y1 * Y1);
    const C = mod(B * B);
    const x1b = X1 + B;
    const D = mod(_2n * (mod(x1b * x1b) - A - C));
    const E = mod(_3n * A);
    const F = mod(E * E);
    const X3 = mod(F - _2n * D);
    const Y3 = mod(E * (D - X3) - _8n * C);
    const Z3 = mod(_2n * Y1 * Z1);
    return new JacobianPoint(X3, Y3, Z3);
  }

  // Fast algo for adding 2 Jacobian Points when curve's a=0.
  // Note: cannot be reused for other curves when a != 0.
  // http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-1998-cmo-2
  // Cost: 12M + 4S + 6add + 1*2.
  // Note: 2007 Bernstein-Lange (11M + 5S + 9add + 4*2) is actually 10% slower.
  add(other: JacobianPoint): JacobianPoint {
    if (!(other instanceof JacobianPoint)) throw new TypeError('JacobianPoint expected');
    const { x: X1, y: Y1, z: Z1 } = this;
    const { x: X2, y: Y2, z: Z2 } = other;
    if (X2 === _0n || Y2 === _0n) return this;
    if (X1 === _0n || Y1 === _0n) return other;
    // We're using same code in equals()
    const Z1Z1 = mod(Z1 * Z1);
    const Z2Z2 = mod(Z2 * Z2);
    const U1 = mod(X1 * Z2Z2);
    const U2 = mod(X2 * Z1Z1);
    const S1 = mod(mod(Y1 * Z2) * Z2Z2);
    const S2 = mod(mod(Y2 * Z1) * Z1Z1);
    const H = mod(U2 - U1);
    const r = mod(S2 - S1);
    // H = 0 meaning it's the same point.
    if (H === _0n) {
      if (r === _0n) {
        return this.double();
      } else {
        return JacobianPoint.ZERO;
      }
    }
    const HH = mod(H * H);
    const HHH = mod(H * HH);
    const V = mod(U1 * HH);
    const X3 = mod(r * r - HHH - _2n * V);
    const Y3 = mod(r * (V - X3) - S1 * HHH);
    const Z3 = mod(Z1 * Z2 * H);
    return new JacobianPoint(X3, Y3, Z3);
  }

  subtract(other: JacobianPoint) {
    return this.add(other.negate());
  }

  /**
   * Non-constant-time multiplication. Uses double-and-add algorithm.
   * It's faster, but should only be used when you don't care about
   * an exposed private key e.g. sig verification, which works over *public* keys.
   */
  multiplyUnsafe(scalar: bigint): JacobianPoint {
    const P0 = JacobianPoint.ZERO;
    if (typeof scalar === 'bigint' && scalar === _0n) return P0;
    // Will throw on 0
    let n = normalizeScalar(scalar);
    if (n === _1n) return this;

    // The condition is not executed unless you change global var
    if (!USE_ENDOMORPHISM) {
      let p = P0;
      let d: JacobianPoint = this;
      while (n > _0n) {
        if (n & _1n) p = p.add(d);
        d = d.double();
        n >>= _1n;
      }
      return p;
    }
    let { k1neg, k1, k2neg, k2 } = splitScalarEndo(n);
    let k1p = P0;
    let k2p = P0;
    let d: JacobianPoint = this;
    while (k1 > _0n || k2 > _0n) {
      if (k1 & _1n) k1p = k1p.add(d);
      if (k2 & _1n) k2p = k2p.add(d);
      d = d.double();
      k1 >>= _1n;
      k2 >>= _1n;
    }
    if (k1neg) k1p = k1p.negate();
    if (k2neg) k2p = k2p.negate();
    k2p = new JacobianPoint(mod(k2p.x * CURVE.beta), k2p.y, k2p.z);
    return k1p.add(k2p);
  }

  /**
   * Creates a wNAF precomputation window. Used for caching.
   * Default window size is set by `utils.precompute()` and is equal to 8.
   * Which means we are caching 65536 points: 256 points for every bit from 0 to 256.
   * @returns 65K precomputed points, depending on W
   */
  private precomputeWindow(W: number): JacobianPoint[] {
    // splitScalarEndo could return 129-bit numbers, so we need at least 128 / W + 1
    const windows = USE_ENDOMORPHISM ? 128 / W + 1 : 256 / W + 1;
    const points: JacobianPoint[] = [];
    let p: JacobianPoint = this;
    let base = p;
    for (let window = 0; window < windows; window++) {
      base = p;
      points.push(base);
      for (let i = 1; i < 2 ** (W - 1); i++) {
        base = base.add(p);
        points.push(base);
      }
      p = base.double();
    }
    return points;
  }

  /**
   * Implements w-ary non-adjacent form for calculating ec multiplication.
   * @param n
   * @param affinePoint optional 2d point to save cached precompute windows on it.
   * @returns real and fake (for const-time) points
   */
  private wNAF(n: bigint, affinePoint?: Point): { p: JacobianPoint; f: JacobianPoint } {
    if (!affinePoint && this.equals(JacobianPoint.BASE)) affinePoint = Point.BASE;
    const W = (affinePoint && affinePoint._WINDOW_SIZE) || 1;
    if (256 % W) {
      throw new Error('Point#wNAF: Invalid precomputation window, must be power of 2');
    }

    // Calculate precomputes on a first run, reuse them after
    let precomputes = affinePoint && pointPrecomputes.get(affinePoint);
    if (!precomputes) {
      precomputes = this.precomputeWindow(W);
      if (affinePoint && W !== 1) {
        precomputes = JacobianPoint.normalizeZ(precomputes);
        pointPrecomputes.set(affinePoint, precomputes);
      }
    }

    // Initialize real and fake points for const-time
    let p = JacobianPoint.ZERO;
    let f = JacobianPoint.ZERO;

    const windows = 1 + (USE_ENDOMORPHISM ? 128 / W : 256 / W); // W=8 17
    const windowSize = 2 ** (W - 1); // W=8 128
    const mask = BigInt(2 ** W - 1); // Create mask with W ones: 0b11111111 for W=8
    const maxNumber = 2 ** W; // W=8 256
    const shiftBy = BigInt(W); // W=8 8

    for (let window = 0; window < windows; window++) {
      const offset = window * windowSize;
      // Extract W bits.
      let wbits = Number(n & mask);

      // Shift number by W bits.
      n >>= shiftBy;

      // If the bits are bigger than max size, we'll split those.
      // +224 => 256 - 32
      if (wbits > windowSize) {
        wbits -= maxNumber;
        n += _1n;
      }

      // Check if we're onto Zero point.
      // Add random point inside current window to f.
      if (wbits === 0) {
        // The most important part for const-time getPublicKey
        let pr = precomputes[offset];
        if (window % 2) pr = pr.negate();
        f = f.add(pr);
      } else {
        let cached = precomputes[offset + Math.abs(wbits) - 1];
        if (wbits < 0) cached = cached.negate();
        p = p.add(cached);
      }
    }
    return { p, f };
  }

  /**
   * Constant time multiplication.
   * Uses wNAF method. Windowed method may be 10% faster,
   * but takes 2x longer to generate and consumes 2x memory.
   * @param scalar by which the point would be multiplied
   * @param affinePoint optional point ot save cached precompute windows on it
   * @returns New point
   */
  multiply(scalar: number | bigint, affinePoint?: Point): JacobianPoint {
    let n = normalizeScalar(scalar);
    // Real point.
    let point: JacobianPoint;
    // Fake point, we use it to achieve constant-time multiplication.
    let fake: JacobianPoint;
    if (USE_ENDOMORPHISM) {
      const { k1neg, k1, k2neg, k2 } = splitScalarEndo(n);
      let { p: k1p, f: f1p } = this.wNAF(k1, affinePoint);
      let { p: k2p, f: f2p } = this.wNAF(k2, affinePoint);
      if (k1neg) k1p = k1p.negate();
      if (k2neg) k2p = k2p.negate();
      k2p = new JacobianPoint(mod(k2p.x * CURVE.beta), k2p.y, k2p.z);
      point = k1p.add(k2p);
      fake = f1p.add(f2p);
    } else {
      const { p, f } = this.wNAF(n, affinePoint);
      point = p;
      fake = f;
    }
    // Normalize `z` for both points, but return only real one
    return JacobianPoint.normalizeZ([point, fake])[0];
  }

  // Converts Jacobian point to affine (x, y) coordinates.
  // Can accept precomputed Z^-1 - for example, from invertBatch.
  // (x, y, z) ∋ (x=x/z², y=y/z³)
  toAffine(invZ: bigint = invert(this.z)): Point {
    const { x, y, z } = this;
    const iz1 = invZ;
    const iz2 = mod(iz1 * iz1);
    const iz3 = mod(iz2 * iz1);
    const ax = mod(x * iz2);
    const ay = mod(y * iz3);
    const zz = mod(z * iz1);
    if (zz !== _1n) throw new Error('invZ was invalid');
    return new Point(ax, ay);
  }
}

// Stores precomputed values for points.
const pointPrecomputes = new WeakMap<Point, JacobianPoint[]>();

/**
 * Default Point works in default aka affine coordinates: (x, y)
 */
export class Point {
  /**
   * Base point aka generator. public_key = Point.BASE * private_key
   */
  static BASE: Point = new Point(CURVE.Gx, CURVE.Gy);
  /**
   * Identity point aka point at infinity. point = point + zero_point
   */
  static ZERO: Point = new Point(_0n, _0n);
  // We calculate precomputes for elliptic curve point multiplication
  // using windowed method. This specifies window size and
  // stores precomputed values. Usually only base point would be precomputed.
  _WINDOW_SIZE?: number;

  constructor(readonly x: bigint, readonly y: bigint) {}

  // "Private method", don't use it directly
  _setWindowSize(windowSize: number) {
    this._WINDOW_SIZE = windowSize;
    pointPrecomputes.delete(this);
  }

  // Checks for y % 2 == 0
  hasEvenY() {
    return this.y % _2n === _0n;
  }

  /**
   * Supports compressed Schnorr (32-byte) and ECDSA (33-byte) points
   * @param bytes 32/33 bytes
   * @returns Point instance
   */
  private static fromCompressedHex(bytes: Uint8Array) {
    const isShort = bytes.length === 32;
    const x = bytesToNumber(isShort ? bytes : bytes.subarray(1));
    if (!isValidFieldElement(x)) throw new Error('Point is not on curve');
    const y2 = weistrass(x); // y² = x³ + ax + b
    let y = sqrtMod(y2); // y = y² ^ (p+1)/4
    const isYOdd = (y & _1n) === _1n;
    if (isShort) {
      // Schnorr
      if (isYOdd) y = mod(-y);
    } else {
      // ECDSA
      const isFirstByteOdd = (bytes[0] & 1) === 1;
      if (isFirstByteOdd !== isYOdd) y = mod(-y);
    }
    const point = new Point(x, y);
    point.assertValidity();
    return point;
  }

  // Schnorr doesn't support uncompressed points, so this is only for ECDSA
  private static fromUncompressedHex(bytes: Uint8Array) {
    const x = bytesToNumber(bytes.subarray(1, 33));
    const y = bytesToNumber(bytes.subarray(33, 65));
    const point = new Point(x, y);
    point.assertValidity();
    return point;
  }

  /**
   * Converts hash string or Uint8Array to Point.
   * @param hex 32-byte (schnorr) or 33/65-byte (ECDSA) hex
   */
  static fromHex(hex: Hex): Point {
    const bytes = ensureBytes(hex);
    const len = bytes.length;
    const header = bytes[0];
    // this.assertValidity() is done inside of those two functions
    if (len === 32 || (len === 33 && (header === 0x02 || header === 0x03))) {
      return this.fromCompressedHex(bytes);
    }
    if (len === 65 && header === 0x04) return this.fromUncompressedHex(bytes);
    throw new Error(
      `Point.fromHex: received invalid point. Expected 32-33 compressed bytes or 65 uncompressed bytes, not ${len}`
    );
  }

  // Multiplies generator point by privateKey.
  static fromPrivateKey(privateKey: PrivKey) {
    return Point.BASE.multiply(normalizePrivateKey(privateKey));
  }

  /**
   * Recovers public key from ECDSA signature.
   * https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Public_key_recovery
   * ```
   * recover(r, s, h) where
   *   u1 = hs^-1 mod n
   *   u2 = sr^-1 mod n
   *   Q = u1⋅G + u2⋅R
   * ```
   */
  static fromSignature(msgHash: Hex, signature: Sig, recovery: number): Point {
    msgHash = ensureBytes(msgHash);
    const h = truncateHash(msgHash);
    const { r, s } = normalizeSignature(signature);
    if (recovery !== 0 && recovery !== 1) {
      throw new Error('Cannot recover signature: invalid recovery bit');
    }
    const prefix = recovery & 1 ? '03' : '02';
    const R = Point.fromHex(prefix + numTo32bStr(r));
    const { n } = CURVE;
    const rinv = invert(r, n);
    // Q = u1⋅G + u2⋅R
    const u1 = mod(-h * rinv, n);
    const u2 = mod(s * rinv, n);
    const Q = Point.BASE.multiplyAndAddUnsafe(R, u1, u2);
    if (!Q) throw new Error('Cannot recover signature: point at infinify');
    Q.assertValidity();
    return Q;
  }

  toRawBytes(isCompressed = false): Uint8Array {
    return hexToBytes(this.toHex(isCompressed));
  }

  toHex(isCompressed = false): string {
    const x = numTo32bStr(this.x);
    if (isCompressed) {
      const prefix = this.hasEvenY() ? '02' : '03';
      return `${prefix}${x}`;
    } else {
      return `04${x}${numTo32bStr(this.y)}`;
    }
  }

  // Schnorr-related function
  toHexX() {
    return this.toHex(true).slice(2);
  }

  toRawX() {
    return this.toRawBytes(true).slice(1);
  }

  // A point on curve is valid if it conforms to equation.
  assertValidity(): void {
    const msg = 'Point is not on elliptic curve';
    const { x, y } = this;
    if (!isValidFieldElement(x) || !isValidFieldElement(y)) throw new Error(msg);
    const left = mod(y * y);
    const right = weistrass(x);
    if (mod(left - right) !== _0n) throw new Error(msg);
  }

  equals(other: Point): boolean {
    return this.x === other.x && this.y === other.y;
  }

  // Returns the same point with inverted `y`
  negate() {
    return new Point(this.x, mod(-this.y));
  }

  // Adds point to itself
  double() {
    return JacobianPoint.fromAffine(this).double().toAffine();
  }

  // Adds point to other point
  add(other: Point) {
    return JacobianPoint.fromAffine(this).add(JacobianPoint.fromAffine(other)).toAffine();
  }

  // Subtracts other point from the point
  subtract(other: Point) {
    return this.add(other.negate());
  }

  multiply(scalar: number | bigint) {
    return JacobianPoint.fromAffine(this).multiply(scalar, this).toAffine();
  }

  /**
   * Efficiently calculate `aP + bQ`.
   * Unsafe, can expose private key, if used incorrectly.
   * TODO: Utilize Shamir's trick
   * @returns non-zero affine point
   */
  multiplyAndAddUnsafe(Q: Point, a: bigint, b: bigint): Point | undefined {
    const P = JacobianPoint.fromAffine(this);
    const aP = a === _0n || a === _1n || this !== Point.BASE ? P.multiplyUnsafe(a) : P.multiply(a);
    const bQ = JacobianPoint.fromAffine(Q).multiplyUnsafe(b);
    const sum = aP.add(bQ);
    return sum.equals(JacobianPoint.ZERO) ? undefined : sum.toAffine();
  }
}

function sliceDER(s: string): string {
  // Proof: any([(i>=0x80) == (int(hex(i).replace('0x', '').zfill(2)[0], 16)>=8)  for i in range(0, 256)])
  // Padding done by numberToHex
  return Number.parseInt(s[0], 16) >= 8 ? '00' + s : s;
}

function parseDERInt(data: Uint8Array) {
  if (data.length < 2 || data[0] !== 0x02) {
    throw new Error(`Invalid signature integer tag: ${bytesToHex(data)}`);
  }
  const len = data[1];
  const res = data.subarray(2, len + 2);
  if (!len || res.length !== len) {
    throw new Error(`Invalid signature integer: wrong length`);
  }
  // Strange condition, its not about length, but about first bytes of number.
  if (res[0] === 0x00 && res[1] <= 0x7f) {
    throw new Error('Invalid signature integer: trailing length');
  }
  return { data: bytesToNumber(res), left: data.subarray(len + 2) };
}

function parseDERSignature(data: Uint8Array) {
  if (data.length < 2 || data[0] != 0x30) {
    throw new Error(`Invalid signature tag: ${bytesToHex(data)}`);
  }
  if (data[1] !== data.length - 2) {
    throw new Error('Invalid signature: incorrect length');
  }
  const { data: r, left: sBytes } = parseDERInt(data.subarray(2));
  const { data: s, left: rBytesLeft } = parseDERInt(sBytes);
  if (rBytesLeft.length) {
    throw new Error(`Invalid signature: left bytes after parsing: ${bytesToHex(rBytesLeft)}`);
  }
  return { r, s };
}

// Represents ECDSA signature with its (r, s) properties
export class Signature {
  constructor(readonly r: bigint, readonly s: bigint) {
    this.assertValidity();
  }

  // pair (32 bytes of r, 32 bytes of s)
  static fromCompact(hex: Hex) {
    const arr = hex instanceof Uint8Array;
    const name = 'Signature.fromCompact';
    if (typeof hex !== 'string' && !arr)
      throw new TypeError(`${name}: Expected string or Uint8Array`);
    const str = arr ? bytesToHex(hex) : hex;
    if (str.length !== 128) throw new Error(`${name}: Expected 64-byte hex`);
    return new Signature(hexToNumber(str.slice(0, 64)), hexToNumber(str.slice(64, 128)));
  }

  // DER encoded ECDSA signature
  // https://bitcoin.stackexchange.com/questions/57644/what-are-the-parts-of-a-bitcoin-transaction-input-script
  static fromDER(hex: Hex) {
    const arr = hex instanceof Uint8Array;
    if (typeof hex !== 'string' && !arr)
      throw new TypeError(`Signature.fromDER: Expected string or Uint8Array`);
    const { r, s } = parseDERSignature(arr ? hex : hexToBytes(hex));
    return new Signature(r, s);
  }

  // Don't use this method
  static fromHex(hex: Hex) {
    return this.fromDER(hex);
  }

  assertValidity(): void {
    const { r, s } = this;
    if (!isWithinCurveOrder(r)) throw new Error('Invalid Signature: r must be 0 < r < n');
    if (!isWithinCurveOrder(s)) throw new Error('Invalid Signature: s must be 0 < s < n');
  }

  // Default signatures are always low-s, to prevent malleability.
  // sign(canonical: true) always produces low-s sigs.
  // verify(strict: true) always fails for high-s.
  // We don't provide `hasHighR` https://github.com/bitcoin/bitcoin/pull/13666
  hasHighS(): boolean {
    const HALF = CURVE.n >> _1n;
    return this.s > HALF;
  }

  normalizeS(): Signature {
    return this.hasHighS() ? new Signature(this.r, CURVE.n - this.s) : this;
  }

  // DER-encoded
  toDERRawBytes(isCompressed = false) {
    return hexToBytes(this.toDERHex(isCompressed));
  }
  toDERHex(isCompressed = false) {
    const sHex = sliceDER(numberToHexUnpadded(this.s));
    if (isCompressed) return sHex;
    const rHex = sliceDER(numberToHexUnpadded(this.r));
    const rLen = numberToHexUnpadded(rHex.length / 2);
    const sLen = numberToHexUnpadded(sHex.length / 2);
    const length = numberToHexUnpadded(rHex.length / 2 + sHex.length / 2 + 4);
    return `30${length}02${rLen}${rHex}02${sLen}${sHex}`;
  }

  // Don't use these methods. Use toDER* or toCompact* for explicitness.
  toRawBytes() {
    return this.toDERRawBytes();
  }
  toHex() {
    return this.toDERHex();
  }

  // 32 bytes of r, then 32 bytes of s
  toCompactRawBytes() {
    return hexToBytes(this.toCompactHex());
  }
  toCompactHex() {
    return numTo32bStr(this.r) + numTo32bStr(this.s);
  }
}

// Concatenates several Uint8Arrays into one.
// TODO: check if we're copying data instead of moving it and if that's ok
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  if (!arrays.every((b) => b instanceof Uint8Array)) throw new Error('Uint8Array list expected');
  if (arrays.length === 1) return arrays[0];
  const length = arrays.reduce((a, arr) => a + arr.length, 0);
  const result = new Uint8Array(length);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const arr = arrays[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
}

// Convert between types
// ---------------------

const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
function bytesToHex(uint8a: Uint8Array): string {
  if (!(uint8a instanceof Uint8Array)) throw new Error('Expected Uint8Array');
  // pre-caching improves the speed 6x
  let hex = '';
  for (let i = 0; i < uint8a.length; i++) {
    hex += hexes[uint8a[i]];
  }
  return hex;
}

const POW_2_256 = BigInt('0x10000000000000000000000000000000000000000000000000000000000000000');
function numTo32bStr(num: bigint): string {
  if (typeof num !== 'bigint') throw new Error('Expected bigint');
  if (!(_0n <= num && num < POW_2_256)) throw new Error('Expected number < 2^256');
  return num.toString(16).padStart(64, '0');
}

function numTo32b(num: bigint): Uint8Array {
  const b = hexToBytes(numTo32bStr(num));
  if (b.length !== 32) throw new Error('Error: expected 32 bytes');
  return b;
}

function numberToHexUnpadded(num: number | bigint): string {
  const hex = num.toString(16);
  return hex.length & 1 ? `0${hex}` : hex;
}

function hexToNumber(hex: string): bigint {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
  }
  // Big Endian
  return BigInt(`0x${hex}`);
}

// Caching slows it down 2-3x
function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
  }
  if (hex.length % 2) throw new Error('hexToBytes: received invalid unpadded hex' + hex.length);
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    const hexByte = hex.slice(j, j + 2);
    const byte = Number.parseInt(hexByte, 16);
    if (Number.isNaN(byte) || byte < 0) throw new Error('Invalid byte sequence');
    array[i] = byte;
  }
  return array;
}

// Big Endian
function bytesToNumber(bytes: Uint8Array): bigint {
  return hexToNumber(bytesToHex(bytes));
}

function ensureBytes(hex: Hex): Uint8Array {
  // Uint8Array.from() instead of hash.slice() because node.js Buffer
  // is instance of Uint8Array, and its slice() creates **mutable** copy
  return hex instanceof Uint8Array ? Uint8Array.from(hex) : hexToBytes(hex);
}

function normalizeScalar(num: number | bigint): bigint {
  if (typeof num === 'number' && Number.isSafeInteger(num) && num > 0) return BigInt(num);
  if (typeof num === 'bigint' && isWithinCurveOrder(num)) return num;
  throw new TypeError('Expected valid private scalar: 0 < scalar < curve.n');
}

// -------------------------

// Calculates a modulo b
function mod(a: bigint, b: bigint = CURVE.P): bigint {
  const result = a % b;
  return result >= _0n ? result : b + result;
}

// Does x ^ (2 ^ power). E.g. 30 ^ (2 ^ 4)
function pow2(x: bigint, power: bigint): bigint {
  const { P } = CURVE;
  let res = x;
  while (power-- > _0n) {
    res *= res;
    res %= P;
  }
  return res;
}

// Used to calculate y - the square root of y².
// Exponentiates it to very big number (P+1)/4.
// We are unwrapping the loop because it's 2x faster.
// (P+1n/4n).toString(2) would produce bits [223x 1, 0, 22x 1, 4x 0, 11, 00]
// We are multiplying it bit-by-bit
function sqrtMod(x: bigint): bigint {
  const { P } = CURVE;
  const _6n = BigInt(6);
  const _11n = BigInt(11);
  const _22n = BigInt(22);
  const _23n = BigInt(23);
  const _44n = BigInt(44);
  const _88n = BigInt(88);
  const b2 = (x * x * x) % P; // x^3, 11
  const b3 = (b2 * b2 * x) % P; // x^7
  const b6 = (pow2(b3, _3n) * b3) % P;
  const b9 = (pow2(b6, _3n) * b3) % P;
  const b11 = (pow2(b9, _2n) * b2) % P;
  const b22 = (pow2(b11, _11n) * b11) % P;
  const b44 = (pow2(b22, _22n) * b22) % P;
  const b88 = (pow2(b44, _44n) * b44) % P;
  const b176 = (pow2(b88, _88n) * b88) % P;
  const b220 = (pow2(b176, _44n) * b44) % P;
  const b223 = (pow2(b220, _3n) * b3) % P;
  const t1 = (pow2(b223, _23n) * b22) % P;
  const t2 = (pow2(t1, _6n) * b2) % P;
  return pow2(t2, _2n);
}

// Inverses number over modulo
function invert(number: bigint, modulo: bigint = CURVE.P): bigint {
  if (number === _0n || modulo <= _0n) {
    throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
  }
  // Eucledian GCD https://brilliant.org/wiki/extended-euclidean-algorithm/
  let a = mod(number, modulo);
  let b = modulo;
  // prettier-ignore
  let x = _0n, y = _1n, u = _1n, v = _0n;
  while (a !== _0n) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    // prettier-ignore
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (gcd !== _1n) throw new Error('invert: does not exist');
  return mod(x, modulo);
}

/**
 * Takes a list of numbers, efficiently inverts all of them.
 * @param nums list of bigints
 * @param p modulo
 * @returns list of inverted bigints
 * @example
 * invertBatch([1n, 2n, 4n], 21n);
 * // => [1n, 11n, 16n]
 */
function invertBatch(nums: bigint[], p: bigint = CURVE.P): bigint[] {
  const scratch = new Array(nums.length);
  // Walk from first to last, multiply them by each other MOD p
  const lastMultiplied = nums.reduce((acc, num, i) => {
    if (num === _0n) return acc;
    scratch[i] = acc;
    return mod(acc * num, p);
  }, _1n);
  // Invert last element
  const inverted = invert(lastMultiplied, p);
  // Walk from last to first, multiply them by inverted each other MOD p
  nums.reduceRight((acc, num, i) => {
    if (num === _0n) return acc;
    scratch[i] = mod(acc * scratch[i], p);
    return mod(acc * num, p);
  }, inverted);
  return scratch;
}

const divNearest = (a: bigint, b: bigint) => (a + b / _2n) / b;
const ENDO = {
  a1: BigInt('0x3086d221a7d46bcde86c90e49284eb15'),
  b1: -_1n * BigInt('0xe4437ed6010e88286f547fa90abfe4c3'),
  a2: BigInt('0x114ca50f7a8e2f3f657c1108d9d44cfd8'),
  b2: BigInt('0x3086d221a7d46bcde86c90e49284eb15'), // === a1
  POW_2_128: BigInt('0x100000000000000000000000000000000'),
};
// Split 256-bit K into 2 128-bit (k1, k2) for which k1 + k2 * lambda = K.
// Used for endomorphism https://gist.github.com/paulmillr/eb670806793e84df628a7c434a873066
function splitScalarEndo(k: bigint) {
  const { n } = CURVE;
  const { a1, b1, a2, b2, POW_2_128 } = ENDO;
  const c1 = divNearest(b2 * k, n);
  const c2 = divNearest(-b1 * k, n);
  let k1 = mod(k - c1 * a1 - c2 * a2, n);
  let k2 = mod(-c1 * b1 - c2 * b2, n);
  const k1neg = k1 > POW_2_128;
  const k2neg = k2 > POW_2_128;
  if (k1neg) k1 = n - k1;
  if (k2neg) k2 = n - k2;
  if (k1 > POW_2_128 || k2 > POW_2_128) {
    throw new Error('splitScalarEndo: Endomorphism failed, k=' + k);
  }
  return { k1neg, k1, k2neg, k2 };
}

// Ensures ECDSA message hashes are 32 bytes and < curve order
function truncateHash(hash: Uint8Array): bigint {
  const { n } = CURVE;
  const byteLength = hash.length;
  const delta = byteLength * 8 - 256; // size of curve.n
  let h = bytesToNumber(hash);
  if (delta > 0) h = h >> BigInt(delta);
  if (h >= n) h -= n;
  return h;
}

// RFC6979 related code
type RecoveredSig = { sig: Signature; recovery: number };
type U8A = Uint8Array;

type Sha256FnSync = undefined | ((...messages: Uint8Array[]) => Uint8Array);
type HmacFnSync = undefined | ((key: Uint8Array, ...messages: Uint8Array[]) => Uint8Array);
let _sha256Sync: Sha256FnSync;
let _hmacSha256Sync: HmacFnSync;

// Minimal HMAC-DRBG (NIST 800-90) for signatures
// Used only for RFC6979, does not fully implement DRBG spec.
class HmacDrbg {
  k: Uint8Array;
  v: Uint8Array;
  counter: number;
  constructor() {
    // Step B, Step C
    this.v = new Uint8Array(32).fill(1);
    this.k = new Uint8Array(32).fill(0);
    this.counter = 0;
  }
  private hmac(...values: Uint8Array[]) {
    return utils.hmacSha256(this.k, ...values);
  }
  private hmacSync(...values: Uint8Array[]) {
    return _hmacSha256Sync!(this.k, ...values);
  }
  private checkSync() {
    if (typeof _hmacSha256Sync !== 'function') throw new ShaError('hmacSha256Sync needs to be set');
  }
  incr() {
    if (this.counter >= 1000) throw new Error('Tried 1,000 k values for sign(), all were invalid');
    this.counter += 1;
  }

  // We concatenate extraData into seed
  async reseed(seed = new Uint8Array()) {
    this.k = await this.hmac(this.v, Uint8Array.from([0x00]), seed);
    this.v = await this.hmac(this.v);
    if (seed.length === 0) return;
    this.k = await this.hmac(this.v, Uint8Array.from([0x01]), seed);
    this.v = await this.hmac(this.v);
  }
  reseedSync(seed = new Uint8Array()) {
    this.checkSync();
    this.k = this.hmacSync(this.v, Uint8Array.from([0x00]), seed);
    this.v = this.hmacSync(this.v);
    if (seed.length === 0) return;
    this.k = this.hmacSync(this.v, Uint8Array.from([0x01]), seed);
    this.v = this.hmacSync(this.v);
  }

  async generate(): Promise<Uint8Array> {
    this.incr();
    this.v = await this.hmac(this.v);
    return this.v;
  }
  generateSync(): Uint8Array {
    this.checkSync();
    this.incr();
    this.v = this.hmacSync(this.v);
    return this.v;
  }
  // There is no need in clean() method
  // It's useless, there are no guarantees with JS GC
  // whether bigints are removed even if you clean Uint8Arrays.
}

function isWithinCurveOrder(num: bigint): boolean {
  return _0n < num && num < CURVE.n;
}

function isValidFieldElement(num: bigint): boolean {
  return _0n < num && num < CURVE.P;
}

/**
 * Converts signature params into point & r/s, checks them for validity.
 * k must be in range [1, n-1]
 * @param k signature's k param: deterministic in our case, random in non-rfc6979 sigs
 * @param m message that would be signed
 * @param d private key
 * @returns Signature with its point on curve Q OR undefined if params were invalid
 */
function kmdToSig(kBytes: Uint8Array, m: bigint, d: bigint): RecoveredSig | undefined {
  const k = bytesToNumber(kBytes);
  if (!isWithinCurveOrder(k)) return;
  // Important: all mod() calls in the function must be done over `n`
  const { n } = CURVE;
  const q = Point.BASE.multiply(k);
  // r = x mod n
  const r = mod(q.x, n);
  if (r === _0n) return;
  // s = (1/k * (m + dr) mod n
  const s = mod(invert(k, n) * mod(m + d * r, n), n);
  if (s === _0n) return;
  const sig = new Signature(r, s);
  const recovery = (q.x === sig.r ? 0 : 2) | Number(q.y & _1n);
  return { sig, recovery };
}

function normalizePrivateKey(key: PrivKey): bigint {
  let num: bigint;
  if (typeof key === 'bigint') {
    num = key;
  } else if (typeof key === 'number' && Number.isSafeInteger(key) && key > 0) {
    num = BigInt(key);
  } else if (typeof key === 'string') {
    if (key.length !== 64) throw new Error('Expected 32 bytes of private key');
    num = hexToNumber(key);
  } else if (key instanceof Uint8Array) {
    if (key.length !== 32) throw new Error('Expected 32 bytes of private key');
    num = bytesToNumber(key);
  } else {
    throw new TypeError('Expected valid private key');
  }
  if (!isWithinCurveOrder(num)) throw new Error('Expected private key: 0 < key < n');
  return num;
}

/**
 * Normalizes hex, bytes, Point to Point. Checks for curve equation.
 */
function normalizePublicKey(publicKey: PubKey): Point {
  if (publicKey instanceof Point) {
    publicKey.assertValidity();
    return publicKey;
  } else {
    return Point.fromHex(publicKey);
  }
}

/**
 * Signatures can be in 64-byte compact representation,
 * or in (variable-length)-byte DER representation.
 * Since DER could also be 64 bytes, we check for it first.
 */
function normalizeSignature(signature: Sig): Signature {
  if (signature instanceof Signature) {
    signature.assertValidity();
    return signature;
  }
  try {
    return Signature.fromDER(signature);
  } catch (error) {
    return Signature.fromCompact(signature);
  }
}

/**
 * Computes public key for secp256k1 private key.
 * @param privateKey 32-byte private key
 * @param isCompressed whether to return compact (33-byte), or full (65-byte) key
 * @returns Public key, full by default; short when isCompressed=true
 */
export function getPublicKey(privateKey: PrivKey, isCompressed = false): Uint8Array {
  return Point.fromPrivateKey(privateKey).toRawBytes(isCompressed);
}

/**
 * Recovers public key from signature and recovery bit. Throws on invalid sig/hash.
 * @param msgHash message hash
 * @param signature DER or compact sig
 * @param recovery 0 or 1
 * @param isCompressed whether to return compact (33-byte), or full (65-byte) key
 * @returns Public key, full by default; short when isCompressed=true
 */
export function recoverPublicKey(
  msgHash: Hex,
  signature: Sig,
  recovery: number,
  isCompressed = false
): Uint8Array {
  return Point.fromSignature(msgHash, signature, recovery).toRawBytes(isCompressed);
}

/**
 * Quick and dirty check for item being public key. Does not validate hex, or being on-curve.
 */
function isProbPub(item: PrivKey | PubKey): boolean {
  const arr = item instanceof Uint8Array;
  const str = typeof item === 'string';
  const len = (arr || str) && (item as Hex).length;
  if (arr) return len === 33 || len === 65;
  if (str) return len === 66 || len === 130;
  if (item instanceof Point) return true;
  return false;
}

/**
 * ECDH (Elliptic Curve Diffie Hellman) implementation.
 * 1. Checks for validity of private key
 * 2. Checks for the public key of being on-curve
 * @param privateA private key
 * @param publicB different public key
 * @param isCompressed whether to return compact (33-byte), or full (65-byte) key
 * @returns shared public key
 */
export function getSharedSecret(
  privateA: PrivKey,
  publicB: PubKey,
  isCompressed = false
): Uint8Array {
  if (isProbPub(privateA)) throw new TypeError('getSharedSecret: first arg must be private key');
  if (!isProbPub(publicB)) throw new TypeError('getSharedSecret: second arg must be public key');
  const b = normalizePublicKey(publicB);
  b.assertValidity();
  return b.multiply(normalizePrivateKey(privateA)).toRawBytes(isCompressed);
}

type Entropy = Hex | true;
type OptsOther = { canonical?: boolean; der?: boolean; extraEntropy?: Entropy };
type OptsRecov = { recovered: true } & OptsOther;
type OptsNoRecov = { recovered?: false } & OptsOther;
type Opts = { recovered?: boolean } & OptsOther;
type SignOutput = Uint8Array | [Uint8Array, number];

// RFC6979 methods
function bits2int(bytes: Uint8Array) {
  const slice = bytes.length > 32 ? bytes.slice(0, 32) : bytes;
  return bytesToNumber(slice);
}
function bits2octets(bytes: Uint8Array): Uint8Array {
  const z1 = bits2int(bytes);
  const z2 = mod(z1, CURVE.n);
  return int2octets(z2 < _0n ? z1 : z2);
}
function int2octets(num: bigint): Uint8Array {
  return numTo32b(num); // prohibits >32 bytes
}

// Steps A, D of RFC6979 3.2
// Creates RFC6979 seed; converts msg/privKey to numbers.
function initSigArgs(msgHash: Hex, privateKey: PrivKey, extraEntropy?: Entropy) {
  if (msgHash == null) throw new Error(`sign: expected valid message hash, not "${msgHash}"`);
  // Step A is ignored, since we already provide hash instead of msg
  const h1 = ensureBytes(msgHash);
  const d = normalizePrivateKey(privateKey);
  // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1) || k')
  const seedArgs = [int2octets(d), bits2octets(h1)];
  // RFC6979 3.6: additional k' could be provided
  if (extraEntropy != null) {
    if (extraEntropy === true) extraEntropy = utils.randomBytes(32);
    const e = ensureBytes(extraEntropy);
    if (e.length !== 32) throw new Error('sign: Expected 32 bytes of extra data');
    seedArgs.push(e);
  }
  // seed is constructed from private key and message
  // Step D
  // V, 0x00 are done in HmacDRBG constructor.
  const seed = concatBytes(...seedArgs);
  const m = bits2int(h1);
  return { seed, m, d };
}

// Takes signature with its recovery bit, normalizes it
// Produces DER/compact signature and proper recovery bit
function finalizeSig(recSig: RecoveredSig, opts: OptsNoRecov | OptsRecov): SignOutput {
  let { sig, recovery } = recSig;
  const { canonical, der, recovered } = Object.assign({ canonical: true, der: true }, opts);
  if (canonical && sig.hasHighS()) {
    sig = sig.normalizeS();
    recovery ^= 1;
  }
  const hashed = der ? sig.toDERRawBytes() : sig.toCompactRawBytes();
  return recovered ? [hashed, recovery] : hashed;
}

/**
 * Signs message hash (not message: you need to hash it by yourself).
 * We don't auto-hash because some users would want non-SHA256 hash.
 * We are always using deterministic signatures (RFC6979 3.1) instead of
 * letting user specify random k.
 * HMAC-DRBG generates k, then calculates sig point Q & signature r, s based on it.
 * Could receive extra entropy k' as per RFC6979 3.6 Additional data.
 * k' is not generated by default, because of backwards-compatibility concerns.
 * We strongly recommend to pass {extraEntropy: true}.
 *
 * low-s signatures are generated by default. If you don't want it, use canonical: false.
 *
 * ```
 * sign(m, d, k) where
 *   (x, y) = G × k
 *   r = x mod n
 *   s = (1/k * (m + dr) mod n
 * ```
 * @param opts `recovered, canonical, der, extraEntropy`
 */
async function sign(msgHash: Hex, privKey: PrivKey, opts: OptsRecov): Promise<[U8A, number]>;
async function sign(msgHash: Hex, privKey: PrivKey, opts?: OptsNoRecov): Promise<U8A>;
async function sign(msgHash: Hex, privKey: PrivKey, opts: Opts = {}): Promise<SignOutput> {
  // Steps A, D of RFC6979 3.2.
  const { seed, m, d } = initSigArgs(msgHash, privKey, opts.extraEntropy);
  let sig: RecoveredSig | undefined;
  // Steps B, C, D, E, F, G
  const drbg = new HmacDrbg();
  await drbg.reseed(seed);
  // Step H3, repeat until k is in range [1, n-1]
  while (!(sig = kmdToSig(await drbg.generate(), m, d))) await drbg.reseed();
  return finalizeSig(sig, opts);
}

/**
 * Signs message hash (not message: you need to hash it by yourself).
 * Synchronous version of `sign()`: see its documentation.
 * @param opts `recovered, canonical, der, extraEntropy`
 */
function signSync(msgHash: Hex, privKey: PrivKey, opts: OptsRecov): [U8A, number];
function signSync(msgHash: Hex, privKey: PrivKey, opts?: OptsNoRecov): U8A;
function signSync(msgHash: Hex, privKey: PrivKey, opts: Opts = {}): SignOutput {
  // Steps A, D of RFC6979 3.2.
  const { seed, m, d } = initSigArgs(msgHash, privKey, opts.extraEntropy);
  let sig: RecoveredSig | undefined;
  // Steps B, C, D, E, F, G
  const drbg = new HmacDrbg();
  drbg.reseedSync(seed);
  // Step H3, repeat until k is in range [1, n-1]
  while (!(sig = kmdToSig(drbg.generateSync(), m, d))) drbg.reseedSync();
  return finalizeSig(sig, opts);
}
export { sign, signSync };

type VOpts = { strict?: boolean };
const vopts: VOpts = { strict: true };

/**
 * Verifies a signature against message hash and public key.
 * Rejects non-canonical / high-s signatures by default: to override,
 * specify option `{strict: false}`. Implements section 4.1.4 from https://www.secg.org/sec1-v2.pdf:
 *
 * ```
 * verify(r, s, h, P) where
 *   U1 = hs^-1 mod n
 *   U2 = rs^-1 mod n
 *   R = U1⋅G - U2⋅P
 *   mod(R.x, n) == r
 * ```
 */
export function verify(signature: Sig, msgHash: Hex, publicKey: PubKey, opts = vopts): boolean {
  let sig;
  try {
    sig = normalizeSignature(signature);
    msgHash = ensureBytes(msgHash);
  } catch (error) {
    return false;
  }
  const { r, s } = sig;
  if (opts.strict && sig.hasHighS()) return false;
  const h = truncateHash(msgHash);

  let P;
  try {
    P = normalizePublicKey(publicKey);
  } catch (error) {
    return false;
  }
  const { n } = CURVE;
  const sinv = invert(s, n); // s^-1
  // R = u1⋅G - u2⋅P
  const u1 = mod(h * sinv, n);
  const u2 = mod(r * sinv, n);

  // Some implementations compare R.x in jacobian, without inversion.
  // The speed-up is <5%, so we don't complicate the code.
  const R = Point.BASE.multiplyAndAddUnsafe(P, u1, u2);
  if (!R) return false;
  const v = mod(R.x, n);
  return v === r;
}

// Schnorr signatures are superior to ECDSA from above.
// Below is Schnorr-specific code as per BIP0340.
function schnorrChallengeFinalize(ch: Uint8Array): bigint {
  return mod(bytesToNumber(ch), CURVE.n);
}

class SchnorrSignature {
  constructor(readonly r: bigint, readonly s: bigint) {
    this.assertValidity();
  }
  static fromHex(hex: Hex) {
    const bytes = ensureBytes(hex);
    if (bytes.length !== 64)
      throw new TypeError(`SchnorrSignature.fromHex: expected 64 bytes, not ${bytes.length}`);
    const r = bytesToNumber(bytes.subarray(0, 32));
    const s = bytesToNumber(bytes.subarray(32, 64));
    return new SchnorrSignature(r, s);
  }
  assertValidity() {
    const { r, s } = this;
    if (!isValidFieldElement(r) || !isWithinCurveOrder(s)) throw new Error('Invalid signature');
  }
  toHex(): string {
    return numTo32bStr(this.r) + numTo32bStr(this.s);
  }
  toRawBytes(): Uint8Array {
    return hexToBytes(this.toHex());
  }
}

// Schnorr's pubkey is just `x` of Point
// BIP340
function schnorrGetPublicKey(privateKey: PrivKey): Uint8Array {
  return Point.fromPrivateKey(privateKey).toRawX();
}

// We are abstracting the signature creation process into the class
// because we need to provide two identical methods: async & sync. Usage:
//     new InternalSchnorrSignature(msg, privKey, auxRand).calc()
class InternalSchnorrSignature {
  private m: Uint8Array;
  private px: Uint8Array;
  private d: bigint;
  private rand: Uint8Array;

  constructor(message: Hex, privateKey: PrivKey, auxRand: Hex = utils.randomBytes()) {
    if (message == null) throw new TypeError(`sign: Expected valid message, not "${message}"`);
    this.m = ensureBytes(message);
    // checks for isWithinCurveOrder
    const { x, scalar } = this.getScalar(normalizePrivateKey(privateKey));
    this.px = x;
    this.d = scalar;
    this.rand = ensureBytes(auxRand);
    if (this.rand.length !== 32) throw new TypeError('sign: Expected 32 bytes of aux randomness');
  }

  private getScalar(priv: bigint) {
    const point = Point.fromPrivateKey(priv);
    const scalar = point.hasEvenY() ? priv : CURVE.n - priv;
    return { point, scalar, x: point.toRawX() };
  }

  private initNonce(d: bigint, t0h: Uint8Array): Uint8Array {
    return numTo32b(d ^ bytesToNumber(t0h));
  }
  private finalizeNonce(k0h: Uint8Array) {
    const k0 = mod(bytesToNumber(k0h), CURVE.n);
    if (k0 === _0n) throw new Error('sign: Creation of signature failed. k is zero');
    const { point: R, x: rx, scalar: k } = this.getScalar(k0);
    return { R, rx, k };
  }
  private finalizeSig(R: Point, k: bigint, e: bigint, d: bigint): Uint8Array {
    return new SchnorrSignature(R.x, mod(k + e * d, CURVE.n)).toRawBytes();
  }
  private error() {
    throw new Error('sign: Invalid signature produced');
  }

  async calc() {
    const { m, d, px, rand } = this;
    const tag = utils.taggedHash;
    const t = this.initNonce(d, await tag(TAGS.aux, rand));
    const { R, rx, k } = this.finalizeNonce(await tag(TAGS.nonce, t, px, m));
    const e = schnorrChallengeFinalize(await tag(TAGS.challenge, rx, px, m));
    const sig = this.finalizeSig(R, k, e, d);
    if (!(await schnorrVerify(sig, m, px))) this.error();
    return sig;
  }
  calcSync() {
    const { m, d, px, rand } = this;
    const tag = utils.taggedHashSync;
    const t = this.initNonce(d, tag(TAGS.aux, rand));
    const { R, rx, k } = this.finalizeNonce(tag(TAGS.nonce, t, px, m));
    const e = schnorrChallengeFinalize(tag(TAGS.challenge, rx, px, m));
    const sig = this.finalizeSig(R, k, e, d);
    if (!schnorrVerifySync(sig, m, px)) this.error();
    return sig;
  }
}

/**
 * Creates Schnorr signature. Improved security: verifies itself before producing an output.
 * @param msg message (not message hash)
 * @param privateKey private key
 * @param auxRand random bytes that would be added to k. Bad RNG won't break it.
 */
async function schnorrSign(msg: Hex, privKey: PrivKey, auxRand?: Hex): Promise<Uint8Array> {
  return new InternalSchnorrSignature(msg, privKey, auxRand).calc();
}

/**
 * Synchronously creates Schnorr signature. Improved security: verifies itself before
 * producing an output.
 * @param msg message (not message hash)
 * @param privateKey private key
 * @param auxRand random bytes that would be added to k. Bad RNG won't break it.
 */
function schnorrSignSync(msg: Hex, privKey: PrivKey, auxRand?: Hex): Uint8Array {
  return new InternalSchnorrSignature(msg, privKey, auxRand).calcSync();
}

function initSchnorrVerify(signature: Hex, message: Hex, publicKey: Hex) {
  const raw = signature instanceof SchnorrSignature;
  const sig: SchnorrSignature = raw ? signature : SchnorrSignature.fromHex(signature);
  if (raw) sig.assertValidity(); // just in case

  return {
    ...sig,
    m: ensureBytes(message),
    P: normalizePublicKey(publicKey),
  };
}

function finalizeSchnorrVerify(r: bigint, P: Point, s: bigint, e: bigint): boolean {
  // R = s⋅G - e⋅P
  // -eP == (n-e)P
  const R = Point.BASE.multiplyAndAddUnsafe(P, normalizePrivateKey(s), mod(-e, CURVE.n));
  if (!R || !R.hasEvenY() || R.x !== r) return false;
  return true;
}

/**
 * Verifies Schnorr signature.
 */
async function schnorrVerify(signature: Hex, message: Hex, publicKey: Hex): Promise<boolean> {
  try {
    const { r, s, m, P } = initSchnorrVerify(signature, message, publicKey);
    const e = schnorrChallengeFinalize(
      await utils.taggedHash(TAGS.challenge, numTo32b(r), P.toRawX(), m)
    );
    return finalizeSchnorrVerify(r, P, s, e);
  } catch (error) {
    return false;
  }
}

/**
 * Verifies Schnorr signature synchronously.
 */
function schnorrVerifySync(signature: Hex, message: Hex, publicKey: Hex): boolean {
  try {
    const { r, s, m, P } = initSchnorrVerify(signature, message, publicKey);
    const e = schnorrChallengeFinalize(
      utils.taggedHashSync(TAGS.challenge, numTo32b(r), P.toRawX(), m)
    );
    return finalizeSchnorrVerify(r, P, s, e);
  } catch (error) {
    if (error instanceof ShaError) throw error;
    return false;
  }
}

export const schnorr = {
  Signature: SchnorrSignature,
  getPublicKey: schnorrGetPublicKey,
  sign: schnorrSign,
  verify: schnorrVerify,
  signSync: schnorrSignSync,
  verifySync: schnorrVerifySync,
};

// Enable precomputes. Slows down first publicKey computation by 20ms.
Point.BASE._setWindowSize(8);

// Global symbol available in browsers only. Ensure we do not depend on @types/dom
declare const self: Record<string, any> | undefined;
const crypto: { node?: any; web?: any } = {
  node: nodeCrypto,
  web: typeof self === 'object' && 'crypto' in self ? self.crypto : undefined,
};

const TAGS = {
  challenge: 'BIP0340/challenge',
  aux: 'BIP0340/aux',
  nonce: 'BIP0340/nonce',
} as const;
/** An object mapping tags to their tagged hash prefix of [SHA256(tag) | SHA256(tag)] */
const TAGGED_HASH_PREFIXES: { [tag: string]: Uint8Array } = {};

export const utils = {
  bytesToHex,
  hexToBytes,
  concatBytes,
  mod,
  invert,

  isValidPrivateKey(privateKey: PrivKey) {
    try {
      normalizePrivateKey(privateKey);
      return true;
    } catch (error) {
      return false;
    }
  },
  _bigintTo32Bytes: numTo32b,
  _normalizePrivateKey: normalizePrivateKey,

  /**
   * Can take 40 or more bytes of uniform input e.g. from CSPRNG or KDF
   * and convert them into private key, with the modulo bias being neglible.
   * As per FIPS 186 B.4.1.
   * https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
   * @param hash hash output from sha512, or a similar function
   * @returns valid private key
   */
  hashToPrivateKey: (hash: Hex): Uint8Array => {
    hash = ensureBytes(hash);
    if (hash.length < 40 || hash.length > 1024)
      throw new Error('Expected 40-1024 bytes of private key as per FIPS 186');
    const num = mod(bytesToNumber(hash), CURVE.n - _1n) + _1n;
    return numTo32b(num);
  },

  randomBytes: (bytesLength: number = 32): Uint8Array => {
    if (crypto.web) {
      return crypto.web.getRandomValues(new Uint8Array(bytesLength));
    } else if (crypto.node) {
      const { randomBytes } = crypto.node;
      return Uint8Array.from(randomBytes(bytesLength));
    } else {
      throw new Error("The environment doesn't have randomBytes function");
    }
  },

  // Takes curve order + 64 bits from CSPRNG
  // so that modulo bias is neglible, matches FIPS 186 B.1.1.
  randomPrivateKey: (): Uint8Array => {
    return utils.hashToPrivateKey(utils.randomBytes(40));
  },

  sha256: async (...messages: Uint8Array[]): Promise<Uint8Array> => {
    if (crypto.web) {
      const buffer = await crypto.web.subtle.digest('SHA-256', concatBytes(...messages));
      return new Uint8Array(buffer);
    } else if (crypto.node) {
      const { createHash } = crypto.node;
      const hash = createHash('sha256');
      messages.forEach((m) => hash.update(m));
      return Uint8Array.from(hash.digest());
    } else {
      throw new Error("The environment doesn't have sha256 function");
    }
  },

  hmacSha256: async (key: Uint8Array, ...messages: Uint8Array[]): Promise<Uint8Array> => {
    if (crypto.web) {
      // prettier-ignore
      const ckey = await crypto.web.subtle.importKey(
        'raw', key, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign']
      );
      const message = concatBytes(...messages);
      const buffer = await crypto.web.subtle.sign('HMAC', ckey, message);
      return new Uint8Array(buffer);
    } else if (crypto.node) {
      const { createHmac } = crypto.node;
      const hash = createHmac('sha256', key);
      messages.forEach((m) => hash.update(m));
      return Uint8Array.from(hash.digest());
    } else {
      throw new Error("The environment doesn't have hmac-sha256 function");
    }
  },

  // See Object.defineProp below
  sha256Sync: undefined as Sha256FnSync,
  hmacSha256Sync: undefined as HmacFnSync,

  taggedHash: async (tag: string, ...messages: Uint8Array[]): Promise<Uint8Array> => {
    let tagP = TAGGED_HASH_PREFIXES[tag];
    if (tagP === undefined) {
      const tagH = await utils.sha256(Uint8Array.from(tag, (c) => c.charCodeAt(0)));
      tagP = concatBytes(tagH, tagH);
      TAGGED_HASH_PREFIXES[tag] = tagP;
    }

    return utils.sha256(tagP, ...messages);
  },

  taggedHashSync: (tag: string, ...messages: Uint8Array[]): Uint8Array => {
    if (typeof _sha256Sync !== 'function')
      throw new ShaError('sha256Sync is undefined, you need to set it');
    let tagP = TAGGED_HASH_PREFIXES[tag];
    if (tagP === undefined) {
      const tagH = _sha256Sync(Uint8Array.from(tag, (c) => c.charCodeAt(0)));
      tagP = concatBytes(tagH, tagH);
      TAGGED_HASH_PREFIXES[tag] = tagP;
    }

    return _sha256Sync(tagP, ...messages);
  },

  /**
   * 1. Returns cached point which you can use to pass to `getSharedSecret` or `#multiply` by it.
   * 2. Precomputes point multiplication table. Is done by default on first `getPublicKey()` call.
   * If you want your first getPublicKey to take 0.16ms instead of 20ms, make sure to call
   * utils.precompute() somewhere without arguments first.
   * @param windowSize 2, 4, 8, 16
   * @returns cached point
   */
  precompute(windowSize = 8, point = Point.BASE): Point {
    const cached = point === Point.BASE ? point : new Point(point.x, point.y);
    cached._setWindowSize(windowSize);
    cached.multiply(_3n);
    return cached;
  },
};

// Make sure sync hash could only be set once.
Object.defineProperties(utils, {
  sha256Sync: {
    configurable: false,
    get() {
      return _sha256Sync;
    },
    set(val) {
      if (!_sha256Sync) _sha256Sync = val;
    },
  },
  hmacSha256Sync: {
    configurable: false,
    get() {
      return _hmacSha256Sync;
    },
    set(val) {
      if (!_hmacSha256Sync) _hmacSha256Sync = val;
    },
  },
});
