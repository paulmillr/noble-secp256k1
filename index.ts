/*! noble-secp256k1 - MIT License (c) Paul Miller (paulmillr.com) */

// https://www.secg.org/sec2-v2.pdf
// Curve fomula is y^2 = x^3 + ax + b
const CURVE = {
  // Params: a, b
  a: 0n,
  b: 7n,
  // Field over which we'll do calculations
  P: 2n ** 256n - 2n ** 32n - 977n,
  // Subgroup order aka prime_order
  n: 2n ** 256n - 432420386565659656852420866394968145599n,
  // Cofactor
  h: 1n,
  // Base point (x, y) aka generator point
  Gx: 55066263022277343669578718895168534326250603453777594175500187360389116729240n,
  Gy: 32670510020758816978083085130507043184471273380659243275938904335757337482424n,

  // For endomorphism, see below.
  beta: 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501een,
};

// Cleaner js output if that's on a separate line.
export { CURVE };

// Short weistrass curve formula.
// y^2 = x^3 + ax + b
// Returns y^2
function weistrass(x: bigint) {
  const { a, b } = CURVE;
  return mod(x ** 3n + a * x + b);
}

type Hex = Uint8Array | string;
type PrivKey = Hex | bigint | number;
type PubKey = Hex | Point;
type Sig = Hex | Signature;

// Always true for secp256k1.
// We're including it here if you'll want to reuse code to support
// different curve (e.g. secp256r1) - just set it to false then.
// Endomorphism only works for Koblitz curves with a == 0.
// It improves efficiency:
// Uses 2x less RAM, speeds up precomputation by 2x and ECDH / sign key recovery by 20%.
// Should always be used for Jacobian's double-and-add multiplication.
// For affines cached multiplication, it trades off 1/2 init time & 1/3 ram for 20% perf hit.
// https://gist.github.com/paulmillr/eb670806793e84df628a7c434a873066
const USE_ENDOMORPHISM = CURVE.a === 0n;

// Default Point works in 2d / affine coordinates: (x, y)
// Jacobian Point works in 3d / jacobi coordinates: (x, y, z) ∋ (x=x/z^2, y=y/z^3)
// We're doing calculations in jacobi, because its operations don't require costly inversion.
class JacobianPoint {
  constructor(public x: bigint, public y: bigint, public z: bigint) {}

  static BASE = new JacobianPoint(CURVE.Gx, CURVE.Gy, 1n);
  static ZERO = new JacobianPoint(0n, 1n, 0n);
  static fromAffine(p: Point): JacobianPoint {
    if (!(p instanceof Point)) {
      throw new TypeError('JacobianPoint#fromAffine: expected Point');
    }
    return new JacobianPoint(p.x, p.y, 1n);
  }

  // Takes a bunch of Jacobian Points but executes only one
  // invert on all of them. invert is very slow operation,
  // so this improves performance massively.
  static toAffineBatch(points: JacobianPoint[]): Point[] {
    const toInv = invertBatch(points.map((p) => p.z));
    return points.map((p, i) => p.toAffine(toInv[i]));
  }

  static normalizeZ(points: JacobianPoint[]): JacobianPoint[] {
    return JacobianPoint.toAffineBatch(points).map(JacobianPoint.fromAffine);
  }

  // Compare one point to another.
  equals(other: JacobianPoint): boolean {
    const a = this;
    const b = other;
    const az2 = mod(a.z * a.z);
    const az3 = mod(a.z * az2);
    const bz2 = mod(b.z * b.z);
    const bz3 = mod(b.z * bz2);
    return mod(a.x * bz2) === mod(az2 * b.x) && mod(a.y * bz3) === mod(az3 * b.y);
  }

  // Flips point to one corresponding to (x, -y) in Affine coordinates.
  negate(): JacobianPoint {
    return new JacobianPoint(this.x, mod(-this.y), this.z);
  }

  // Fast algo for doubling 2 Jacobian Points when curve's a=0.
  // Note: cannot be reused for other curves when a != 0.
  // From: http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
  // Cost: 2M + 5S + 6add + 3*2 + 1*3 + 1*8.
  double(): JacobianPoint {
    const X1 = this.x;
    const Y1 = this.y;
    const Z1 = this.z;
    const A = X1 ** 2n;
    const B = Y1 ** 2n;
    const C = B ** 2n;
    const D = 2n * ((X1 + B) ** 2n - A - C);
    const E = 3n * A;
    const F = E ** 2n;
    const X3 = mod(F - 2n * D);
    const Y3 = mod(E * (D - X3) - 8n * C);
    const Z3 = mod(2n * Y1 * Z1);
    return new JacobianPoint(X3, Y3, Z3);
  }

  // Fast algo for adding 2 Jacobian Points when curve's a=0.
  // Note: cannot be reused for other curves when a != 0.
  // http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-1998-cmo-2
  // Cost: 12M + 4S + 6add + 1*2.
  // Note: 2007 Bernstein-Lange (11M + 5S + 9add + 4*2) is actually *slower*. No idea why.
  add(other: JacobianPoint): JacobianPoint {
    if (!(other instanceof JacobianPoint)) {
      throw new TypeError('JacobianPoint#add: expected JacobianPoint');
    }
    const X1 = this.x;
    const Y1 = this.y;
    const Z1 = this.z;
    const X2 = other.x;
    const Y2 = other.y;
    const Z2 = other.z;
    if (X2 === 0n || Y2 === 0n) return this;
    if (X1 === 0n || Y1 === 0n) return other;
    const Z1Z1 = Z1 ** 2n;
    const Z2Z2 = Z2 ** 2n;
    const U1 = X1 * Z2Z2;
    const U2 = X2 * Z1Z1;
    const S1 = Y1 * Z2 * Z2Z2;
    const S2 = Y2 * Z1 * Z1Z1;
    const H = mod(U2 - U1);
    const r = mod(S2 - S1);
    // H = 0 meaning it's the same point.
    if (H === 0n) {
      if (r === 0n) {
        return this.double();
      } else {
        return JacobianPoint.ZERO;
      }
    }
    const HH = mod(H ** 2n);
    const HHH = mod(H * HH);
    const V = U1 * HH;
    const X3 = mod(r ** 2n - HHH - 2n * V);
    const Y3 = mod(r * (V - X3) - S1 * HHH);
    const Z3 = mod(Z1 * Z2 * H);
    return new JacobianPoint(X3, Y3, Z3);
  }

  subtract(other: JacobianPoint) {
    return this.add(other.negate());
  }

  // Non-constant-time multiplication. Uses double-and-add algorithm.
  // It's faster, but should only be used when you don't care about
  // an exposed private key e.g. sig verification, which works over *public* keys.
  multiplyUnsafe(scalar: bigint): JacobianPoint {
    if (!isValidScalar(scalar)) throw new TypeError('Point#multiply: expected valid scalar');
    let n = mod(BigInt(scalar), CURVE.n);
    if (!USE_ENDOMORPHISM) {
      let p = JacobianPoint.ZERO;
      let d: JacobianPoint = this;
      while (n > 0n) {
        if (n & 1n) p = p.add(d);
        d = d.double();
        n >>= 1n;
      }
      return p;
    }
    let [k1neg, k1, k2neg, k2] = splitScalarEndo(n);
    let k1p = JacobianPoint.ZERO;
    let k2p = JacobianPoint.ZERO;
    let d: JacobianPoint = this;
    // TODO: see if we need to check for both zeros instead of one
    while (k1 > 0n || k2 > 0n) {
      if (k1 & 1n) k1p = k1p.add(d);
      if (k2 & 1n) k2p = k2p.add(d);
      d = d.double();
      k1 >>= 1n;
      k2 >>= 1n;
    }
    if (k1neg) k1p = k1p.negate();
    if (k2neg) k2p = k2p.negate();
    k2p = new JacobianPoint(mod(k2p.x * CURVE.beta), k2p.y, k2p.z);
    return k1p.add(k2p);
  }

  // Creates a wNAF precomputation window.
  // Used for caching.
  // Default window size is set by `utils.precompute()` and is equal to 8.
  // Which means we are caching 65536 points: 256 points for every bit from 0 to 256.
  private precomputeWindow(W: number): JacobianPoint[] {
    // splitScalarEndo could return 129-bit numbers, so we need at least 128 / W + 1
    const windows = USE_ENDOMORPHISM ? 128 / W + 1 : 256 / W + 1;
    let points: JacobianPoint[] = [];
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

  // Implements w-ary non-adjacent form for calculating ec multiplication
  // Optional `affinePoint` argument is used to save cached precompute windows on it.
  private wNAF(n: bigint, affinePoint?: Point): [JacobianPoint, JacobianPoint] {
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

    const windows = USE_ENDOMORPHISM ? 128 / W + 1 : 256 / W + 1;
    const windowSize = 2 ** (W - 1); // W=8 128
    const mask = BigInt(2 ** W - 1); // Create mask with W ones: 0b11111111 for W=8
    const maxNumber = 2 ** W; // W=8 256
    const shiftBy = BigInt(W); // W=8 8

    // TODO: review this more carefully
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
        n += 1n;
      }

      // Check if we're onto Zero point.
      // Add random point inside current window to f.
      if (wbits === 0) {
        // The most important part for const-time getPublicKey
        f = f.add(window % 2 ? precomputes[offset].negate() : precomputes[offset]);
      } else {
        const cached = precomputes[offset + Math.abs(wbits) - 1];
        p = p.add(wbits < 0 ? cached.negate() : cached);
      }
    }
    return [p, f];
  }

  // Constant time multiplication.
  // Uses wNAF method. Windowed method may be 10% faster,
  // but takes 2x longer to generate and consumes 2x memory.
  multiply(scalar: number | bigint, affinePoint?: Point): JacobianPoint {
    if (!isValidScalar(scalar)) throw new TypeError('Point#multiply: expected valid scalar');
    let n = mod(BigInt(scalar), CURVE.n);
    // Real point.
    let point: JacobianPoint;
    // Fake point, we use it to achieve constant-time multiplication.
    let fake: JacobianPoint;
    if (USE_ENDOMORPHISM) {
      const [k1neg, k1, k2neg, k2] = splitScalarEndo(n);
      let k1p, k2p, f1p, f2p;
      [k1p, f1p] = this.wNAF(k1, affinePoint);
      [k2p, f2p] = this.wNAF(k2, affinePoint);
      if (k1neg) k1p = k1p.negate();
      if (k2neg) k2p = k2p.negate();
      k2p = new JacobianPoint(mod(k2p.x * CURVE.beta), k2p.y, k2p.z);
      [point, fake] = [k1p.add(k2p), f1p.add(f2p)];
    } else {
      [point, fake] = this.wNAF(n, affinePoint);
    }
    // Normalize `z` for both points, but return only real one
    return JacobianPoint.normalizeZ([point, fake])[0];
  }

  // Converts Jacobian point to affine (x, y) coordinates.
  // Can accept precomputed Z^-1 - for example, from invertBatch.
  // (x, y, z) ∋ (x=x/z^2, y=y/z^3)
  toAffine(invZ: bigint = invert(this.z)): Point {
    const invZ2 = invZ ** 2n;
    const x = mod(this.x * invZ2);
    const y = mod(this.y * invZ2 * invZ);
    return new Point(x, y);
  }
}

// Stores precomputed values for points.
const pointPrecomputes = new WeakMap<Point, JacobianPoint[]>();

// Default Point works in default aka affine coordinates: (x, y)
export class Point {
  // Base point aka generator
  // public_key = Point.BASE * private_key
  static BASE: Point = new Point(CURVE.Gx, CURVE.Gy);
  // Identity point aka point at infinity
  // point = point + zero_point
  static ZERO: Point = new Point(0n, 0n);
  // We calculate precomputes for elliptic curve point multiplication
  // using windowed method. This specifies window size and
  // stores precomputed values. Usually only base point would be precomputed.
  _WINDOW_SIZE?: number;

  constructor(public x: bigint, public y: bigint) {}

  // "Private method", don't use it directly
  _setWindowSize(windowSize: number) {
    this._WINDOW_SIZE = windowSize;
    pointPrecomputes.delete(this);
  }

  // Supports compressed Schnorr (32-byte) and ECDSA (33-byte) points
  private static fromCompressedHex(bytes: Uint8Array) {
    const isShort = bytes.length === 32;
    const x = bytesToNumber(isShort ? bytes : bytes.slice(1));
    const sqrY = weistrass(x); // y^2 = x^3 + ax + b
    let y = sqrtMod(sqrY); // y = y2 ^ (p+1)/4
    if (isShort) {
      // Schnorr
      const isYOdd = (y & 1n) === 1n;
      if (isYOdd) y = mod(-y);
    } else {
      // ECDSA
      const isFirstByteOdd = (bytes[0] & 1) === 1;
      const isYOdd = (y & 1n) === 1n;
      if (isFirstByteOdd !== isYOdd) y = mod(-y);
    }
    const point = new Point(x, y);
    point.assertValidity();
    return point;
  }

  // Schnorr doesn't support uncompressed points, so this is only for ECDSA
  private static fromUncompressedHex(bytes: Uint8Array) {
    const x = bytesToNumber(bytes.slice(1, 33));
    const y = bytesToNumber(bytes.slice(33));
    const point = new Point(x, y);
    point.assertValidity();
    return point;
  }

  // Converts hash string or Uint8Array to Point.
  static fromHex(hex: Hex): Point {
    const bytes = hex instanceof Uint8Array ? hex : hexToBytes(hex);
    const header = bytes[0];
    if (bytes.length === 32 || (bytes.length === 33 && (header === 0x02 || header === 0x03))) {
      return this.fromCompressedHex(bytes);
    }
    if (bytes.length === 65 && header === 0x04) return this.fromUncompressedHex(bytes);
    throw new TypeError(
      `Point.fromHex: received invalid point. Expected 32-33 compressed bytes or 65 uncompressed bytes, not ${bytes.length}`
    );
  }

  // Multiplies generator point by privateKey.
  static fromPrivateKey(privateKey: PrivKey) {
    return Point.BASE.multiply(normalizePrivateKey(privateKey));
  }

  // Recovers public key from ECDSA signature.
  // https://crypto.stackexchange.com/questions/60218
  // Uses following formula:
  // Q = (r ** -1)(sP - hG)
  static fromSignature(msgHash: Hex, signature: Sig, recovery: number): Point {
    let h: bigint;
    if (typeof msgHash === 'string') {
      h = hexToNumber(msgHash);
    } else if (msgHash instanceof Uint8Array) {
      h = bytesToNumber(msgHash);
    } else {
      throw new TypeError('Message hash must be a hex string or Uint8Array');
    }
    const { r, s } = normalizeSignature(signature);
    if (r === 0n || s === 0n) throw new Error('Invalid signature');
    if (recovery !== 0 && recovery !== 1) throw new Error('Invalid yParity bit');
    const prefix = 2 + (recovery & 1);
    const P_ = Point.fromHex(`0${prefix}${pad64(r)}`);
    const sP = JacobianPoint.fromAffine(P_).multiplyUnsafe(s);
    const hG = JacobianPoint.BASE.multiply(h);
    const rinv = invert(r, CURVE.n);
    const Q = sP.subtract(hG).multiplyUnsafe(rinv);
    const point = Q.toAffine();
    point.assertValidity();
    return point;
  }

  toRawBytes(isCompressed = false): Uint8Array {
    return hexToBytes(this.toHex(isCompressed));
  }

  toHex(isCompressed = false): string {
    const x = pad64(this.x);
    if (isCompressed) {
      return `${this.y & 1n ? '03' : '02'}${x}`;
    } else {
      return `04${x}${pad64(this.y)}`;
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
    const { x, y } = this;
    if (x === 0n || y === 0n || x >= CURVE.P || y >= CURVE.P) {
      throw new TypeError('Point is not on elliptic curve');
    }
    const left = mod(y * y);
    const right = weistrass(x);
    const valid = (left - right) % CURVE.P === 0n;
    if (!valid) throw new TypeError('Point is not on elliptic curve');
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
}

function sliceDer(s: string): string {
  // Proof: any([(i>=0x80) == (int(hex(i).replace('0x', '').zfill(2)[0], 16)>=8)  for i in range(0, 256)])
  // Padding done by numberToHex
  return parseInt(s[0], 16) >= 8 ? '00' + s : s;
}

// Represents ECDSA signature with its (r, s) properties
export class Signature {
  constructor(public r: bigint, public s: bigint) {}

  // DER encoded ECDSA signature
  // TODO: verify more thoroughly
  // https://bitcoin.stackexchange.com/questions/57644/what-are-the-parts-of-a-bitcoin-transaction-input-script
  static fromHex(hex: Hex) {
    if (typeof hex !== 'string' && !(hex instanceof Uint8Array)) {
      throw new TypeError(`Invalid signature. Expected string or Uint8Array`);
    }
    const str = hex instanceof Uint8Array ? bytesToHex(hex) : hex;

    // `30${length}02${rLen}${rHex}02${sLen}${sHex}`
    const length = parseByte(str.slice(2, 4));
    if (str.slice(0, 2) !== '30' || length !== str.length - 4 || str.slice(4, 6) !== '02') {
      throw new Error('Signature.fromHex: Invalid signature');
    }

    // r
    const rLen = parseByte(str.slice(6, 8));
    const rEnd = 8 + rLen;
    const r = hexToNumber(str.slice(8, rEnd));

    // s
    const check3 = str.slice(rEnd, rEnd + 2);
    if (check3 !== '02') {
      throw new Error('SignResult.fromHex: Invalid signature');
    }
    const sLen = parseByte(str.slice(rEnd + 2, rEnd + 4));
    const sStart = rEnd + 4;
    const s = hexToNumber(str.slice(sStart, sStart + sLen));

    return new Signature(r, s);
  }

  toRawBytes(isCompressed = false) {
    return hexToBytes(this.toHex(isCompressed));
  }

  toHex(isCompressed = false) {
    const sHex = sliceDer(numberToHex(this.s));
    if (isCompressed) return sHex;
    const rHex = sliceDer(numberToHex(this.r));
    const rLen = numberToHex(rHex.length / 2);
    const sLen = numberToHex(sHex.length / 2);
    const length = numberToHex(rHex.length / 2 + sHex.length / 2 + 4);
    return `30${length}02${rLen}${rHex}02${sLen}${sHex}`;
  }
}
export const SignResult = Signature; // backwards compatibility

// Concatenates two Uint8Arrays into one.
// TODO: check if we're copying data instead of moving it and if that's ok
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
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
function bytesToHex(uint8a: Uint8Array): string {
  // pre-caching chars could speed this up 6x.
  let hex = '';
  for (let i = 0; i < uint8a.length; i++) {
    hex += uint8a[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function pad64(num: number | bigint): string {
  return num.toString(16).padStart(64, '0');
}

function pad32b(num: bigint): Uint8Array {
  return hexToBytes(pad64(num));
}

function numberToHex(num: number | bigint): string {
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

function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string' || hex.length % 2) throw new Error('Expected valid hex');
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
  }
  return array;
}

// Big Endian
function bytesToNumber(bytes: Uint8Array): bigint {
  return hexToNumber(bytesToHex(bytes));
}

function parseByte(str: string): number {
  return Number.parseInt(str, 16) * 2;
}

function isValidScalar(num: number | bigint): boolean {
  if (typeof num === 'bigint' && num > 0n) return true;
  if (typeof num === 'number' && num > 0 && Number.isSafeInteger(num)) return true;
  return false;
}

// -------------------------

// Calculates a modulo b
function mod(a: bigint, b: bigint = CURVE.P): bigint {
  const result = a % b;
  return result >= 0 ? result : b + result;
}

// Does x ^ (2 ^ power). E.g. 30 ^ (2 ^ 4)
function pow2(x: bigint, power: bigint): bigint {
  const { P } = CURVE;
  let res = x;
  while (power-- > 0n) {
    res *= res;
    res %= P;
  }
  return res;
}

// Used to calculate y - the square root of y^2.
// Exponentiates it to very big number (P+1)/4.
// We are unwrapping the loop because it's 2x faster.
// (P+1n/4n).toString(2) would produce bits [223x 1, 0, 22x 1, 4x 0, 11, 00]
// We are multiplying it bit-by-bit
function sqrtMod(x: bigint): bigint {
  const { P } = CURVE;
  const b2 = (x * x * x) % P; // x^3, 11
  const b3 = (b2 * b2 * x) % P; // x^7
  const b6 = (pow2(b3, 3n) * b3) % P;
  const b9 = (pow2(b6, 3n) * b3) % P;
  const b11 = (pow2(b9, 2n) * b2) % P;
  const b22 = (pow2(b11, 11n) * b11) % P;
  const b44 = (pow2(b22, 22n) * b22) % P;
  const b88 = (pow2(b44, 44n) * b44) % P;
  const b176 = (pow2(b88, 88n) * b88) % P;
  const b220 = (pow2(b176, 44n) * b44) % P;
  const b223 = (pow2(b220, 3n) * b3) % P;
  const t1 = (pow2(b223, 23n) * b22) % P;
  const t2 = (pow2(t1, 6n) * b2) % P;
  return pow2(t2, 2n);
}

// Inverses number over modulo
function invert(number: bigint, modulo: bigint = CURVE.P): bigint {
  if (number === 0n || modulo <= 0n) {
    throw new Error('invert: expected positive integers');
  }
  // Eucledian GCD https://brilliant.org/wiki/extended-euclidean-algorithm/
  let a = mod(number, modulo);
  let b = modulo;
  let [x, y, u, v] = [0n, 1n, 1n, 0n];
  while (a !== 0n) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    [b, a] = [a, r];
    [x, y] = [u, v];
    [u, v] = [m, n];
  }
  const gcd = b;
  if (gcd !== 1n) throw new Error('invert: does not exist');
  return mod(x, modulo);
}

// Takes a bunch of numbers, inverses all of them
function invertBatch(nums: bigint[], n: bigint = CURVE.P): bigint[] {
  const len = nums.length;
  const scratch = new Array(len);
  let acc = 1n;
  for (let i = 0; i < len; i++) {
    if (nums[i] === 0n) continue;
    scratch[i] = acc;
    acc = mod(acc * nums[i], n);
  }
  acc = invert(acc, n);
  for (let i = len - 1; i >= 0; i--) {
    if (nums[i] === 0n) continue;
    const tmp = mod(acc * nums[i], n);
    nums[i] = mod(acc * scratch[i], n);
    acc = tmp;
  }
  return nums;
}

const divNearest = (a: bigint, b: bigint) => (a + b / 2n) / b;
const POW_2_128 = 2n ** 128n;
// Split 256-bit K into 2 128-bit (k1, k2) for which k1 + k2 * lambda = K.
// Used for endomorphism https://gist.github.com/paulmillr/eb670806793e84df628a7c434a873066
function splitScalarEndo(k: bigint): [boolean, bigint, boolean, bigint] {
  const { n } = CURVE;
  const a1 = 0x3086d221a7d46bcde86c90e49284eb15n;
  const b1 = -0xe4437ed6010e88286f547fa90abfe4c3n;
  const a2 = 0x114ca50f7a8e2f3f657c1108d9d44cfd8n;
  const b2 = a1;
  const c1 = divNearest(b2 * k, n);
  const c2 = divNearest(-b1 * k, n);
  let k1 = mod(k - c1 * a1 - c2 * a2, n);
  let k2 = mod(-c1 * b1 - c2 * b2, n);
  const k1neg = k1 > POW_2_128;
  const k2neg = k2 > POW_2_128;
  if (k1neg) k1 = n - k1;
  if (k2neg) k2 = n - k2;
  if (k1 > POW_2_128 || k2 > POW_2_128) throw new Error('Endomorphism failed');
  return [k1neg, k1, k2neg, k2];
}

function truncateHash(hash: string | Uint8Array): bigint {
  if (typeof hash !== 'string') hash = bytesToHex(hash);
  let msg = hexToNumber(hash || '0');
  const byteLength = hash.length / 2;
  const delta = byteLength * 8 - 256; // size of curve.n
  if (delta > 0) {
    msg = msg >> BigInt(delta);
  }
  if (msg >= CURVE.n) {
    msg -= CURVE.n;
  }
  return msg;
}

// RFC6979 related code
type QRS = [Point, bigint, bigint];

// Deterministic k generation as per RFC6979.
// Generates k, and then calculates Q & Signature {r, s} based on it.
// https://tools.ietf.org/html/rfc6979#section-3.1
async function getQRSrfc6979(msgHash: Hex, privateKey: bigint) {
  // Step A is ignored, since we already provide hash instead of msg
  const num = typeof msgHash === 'string' ? hexToNumber(msgHash) : bytesToNumber(msgHash);
  const h1 = pad32b(num);
  const x = pad32b(privateKey);
  const h1n = bytesToNumber(h1);

  // Step B
  let v = new Uint8Array(32).fill(1);
  // Step C
  let k = new Uint8Array(32).fill(0);
  const b0 = Uint8Array.from([0x00]);
  const b1 = Uint8Array.from([0x01]);

  // Step D
  k = await utils.hmacSha256(k, v, b0, x, h1);
  // Step E
  v = await utils.hmacSha256(k, v);
  // Step F
  k = await utils.hmacSha256(k, v, b1, x, h1);
  // Step G
  v = await utils.hmacSha256(k, v);

  // Step H3, repeat until 1 < T < n - 1
  for (let i = 0; i < 1000; i++) {
    v = await utils.hmacSha256(k, v);
    const T = bytesToNumber(v);
    let qrs: QRS;
    if (isValidPrivateKey(T) && (qrs = calcQRSFromK(T, h1n, privateKey)!)) {
      return qrs;
    }
    k = await utils.hmacSha256(k, v, b0);
    v = await utils.hmacSha256(k, v);
  }

  throw new TypeError('secp256k1: Tried 1,000 k values for sign(), all were invalid');
}

// Private key must be in bounds 0 < key < n
function isValidPrivateKey(privateKey: bigint): boolean {
  return 0 < privateKey && privateKey < CURVE.n;
}

function calcQRSFromK(k: bigint, msg: bigint, priv: bigint): QRS | undefined {
  const max = CURVE.n;
  const q = Point.BASE.multiply(k);
  const r = mod(q.x, max);
  const s = mod(invert(k, max) * (msg + r * priv), max);
  if (r === 0n || s === 0n) return;
  return [q, r, s];
}

function normalizePrivateKey(privateKey: PrivKey): bigint {
  let key: bigint;
  if (privateKey instanceof Uint8Array) {
    if (privateKey.length !== 32) throw new Error('Expected 32 bytes of private key');
    key = bytesToNumber(privateKey);
  } else if (typeof privateKey === 'string') {
    if (privateKey.length !== 64) throw new Error('Expected 32 bytes of private key');
    key = hexToNumber(privateKey);
  } else if (Number.isSafeInteger(privateKey) && privateKey > 0) {
    key = BigInt(privateKey);
  } else if (typeof privateKey === 'bigint' && privateKey > 0n && privateKey < CURVE.P) {
    key = privateKey;
  } else {
    throw new TypeError('Expected valid private key');
  }
  return key;
}

function normalizePublicKey(publicKey: PubKey): Point {
  return publicKey instanceof Point ? publicKey : Point.fromHex(publicKey);
}

function normalizeSignature(signature: Sig): Signature {
  return signature instanceof Signature ? signature : Signature.fromHex(signature);
}

export function getPublicKey(
  privateKey: Uint8Array | number | bigint,
  isCompressed?: boolean
): Uint8Array;
export function getPublicKey(privateKey: string, isCompressed?: boolean): string;
export function getPublicKey(privateKey: PrivKey, isCompressed = false): PubKey {
  const point = Point.fromPrivateKey(privateKey);
  if (typeof privateKey === 'string') {
    return point.toHex(isCompressed);
  }
  return point.toRawBytes(isCompressed);
}

export function recoverPublicKey(
  msgHash: string,
  signature: string,
  recovery: number
): string | undefined;
export function recoverPublicKey(
  msgHash: Uint8Array,
  signature: Uint8Array,
  recovery: number
): Uint8Array | undefined;
export function recoverPublicKey(msgHash: Hex, signature: Sig, recovery: number): Hex | undefined {
  const point = Point.fromSignature(msgHash, signature, recovery);
  return typeof msgHash === 'string' ? point.toHex() : point.toRawBytes();
}

function isPub(item: PrivKey | PubKey): boolean {
  const arr = item instanceof Uint8Array;
  const str = typeof item === 'string';
  const len = (arr || str) && (item as Hex).length;
  if (arr) return len === 33 || len === 65;
  if (str) return len === 66 || len === 130;
  if (item instanceof Point) return true;
  return false;
}

// ECDH (Elliptic Curve Diffie Hellman) implementation.
export function getSharedSecret(privateA: PrivKey, publicB: PubKey, isCompressed = false): Hex {
  if (isPub(privateA)) throw new TypeError('getSharedSecret: first arg must be private key');
  if (!isPub(publicB)) throw new TypeError('getSharedSecret: second arg must be public key');
  const b = publicB instanceof Point ? publicB : Point.fromHex(publicB);
  b.assertValidity();
  const shared = b.multiply(normalizePrivateKey(privateA));
  return typeof privateA === 'string'
    ? shared.toHex(isCompressed)
    : shared.toRawBytes(isCompressed);
}

type OptsRecovered = { recovered: true; canonical?: true };
type OptsNoRecovered = { recovered?: false; canonical?: true };
type Opts = { recovered?: boolean; canonical?: true };

export async function sign(
  msgHash: Uint8Array,
  privateKey: PrivKey,
  opts: OptsRecovered
): Promise<[Uint8Array, number]>;
export async function sign(
  msgHash: string,
  privateKey: PrivKey,
  opts: OptsRecovered
): Promise<[string, number]>;
export async function sign(
  msgHash: Uint8Array,
  privateKey: PrivKey,
  opts?: OptsNoRecovered
): Promise<Uint8Array>;
export async function sign(
  msgHash: string,
  privateKey: PrivKey,
  opts?: OptsNoRecovered
): Promise<string>;
export async function sign(
  msgHash: string,
  privateKey: PrivKey,
  opts?: OptsNoRecovered
): Promise<string>;
export async function sign(
  msgHash: Hex,
  privateKey: PrivKey,
  { recovered, canonical }: Opts = {}
): Promise<Hex | [Hex, number]> {
  if (msgHash == null) throw new Error(`Expected valid msgHash, not "${msgHash}"`);
  const priv = normalizePrivateKey(privateKey);
  // We are using deterministic signature scheme
  // instead of letting user specify random `k`.
  const [q, r, s] = await getQRSrfc6979(msgHash, priv);

  let recovery = (q.x === r ? 0 : 2) | Number(q.y & 1n);
  let adjustedS = s;
  const HIGH_NUMBER = CURVE.n >> 1n;
  if (s > HIGH_NUMBER && canonical) {
    adjustedS = CURVE.n - s;
    recovery ^= 1;
  }
  const sig = new Signature(r, adjustedS);
  const hashed = typeof msgHash === 'string' ? sig.toHex() : sig.toRawBytes();
  return recovered ? [hashed, recovery] : hashed;
}

export function verify(signature: Sig, msgHash: Hex, publicKey: PubKey): boolean {
  const { n } = CURVE;
  const { r, s } = normalizeSignature(signature);
  if (r <= 0n || r >= n || s <= 0n || s >= n) return false;
  const h = truncateHash(msgHash);
  const pubKey = JacobianPoint.fromAffine(normalizePublicKey(publicKey));
  const s1 = invert(s, n);
  const Ghs1 = JacobianPoint.BASE.multiply(mod(h * s1, n));
  const Prs1 = pubKey.multiplyUnsafe(mod(r * s1, n));
  const res = Ghs1.add(Prs1).toAffine();
  return res.x === r;
}

// Schnorr-specific code as per BIP0340.

// Strip first byte that signifies whether y is positive or negative, leave only x.
async function taggedHash(tag: string, ...messages: Uint8Array[]): Promise<bigint> {
  const tagB = new Uint8Array(tag.split('').map((c) => c.charCodeAt(0)));
  const tagH = await utils.sha256(tagB);
  const h = await utils.sha256(concatBytes(tagH, tagH, ...messages));
  return bytesToNumber(h);
}

async function createChallenge(x: bigint, P: Point, message: Uint8Array) {
  const rx = pad32b(x);
  const t = await taggedHash('BIP0340/challenge', rx, P.toRawX(), message);
  return mod(t, CURVE.n);
}

function hasEvenY(point: Point) {
  return mod(point.y, 2n) === 0n;
}

class SchnorrSignature {
  constructor(readonly r: bigint, readonly s: bigint) {
    if (r === 0n || s === 0n || r >= CURVE.P || s >= CURVE.n) throw new Error('Invalid signature');
  }
  static fromHex(hex: Hex) {
    const bytes = hex instanceof Uint8Array ? hex : hexToBytes(hex);
    if (bytes.length !== 64) {
      throw new TypeError(`SchnorrSignature.fromHex: expected 64 bytes, not ${bytes.length}`);
    }
    const r = bytesToNumber(bytes.slice(0, 32));
    const s = bytesToNumber(bytes.slice(32));
    return new SchnorrSignature(r, s);
  }
  toHex(): string {
    return pad64(this.r) + pad64(this.s);
  }
  toRawBytes(): Uint8Array {
    return hexToBytes(this.toHex());
  }
}

// Schnorr's pubkey is just `x` of Point
function schnorrGetPublicKey(privateKey: Uint8Array): Uint8Array;
function schnorrGetPublicKey(privateKey: string): string;
function schnorrGetPublicKey(privateKey: PrivKey): Hex {
  const P = Point.fromPrivateKey(privateKey);
  return typeof privateKey === 'string' ? P.toHexX() : P.toRawX();
}

// Schnorr signature verifies itself before producing an output, which makes it safer
async function schnorrSign(msgHash: string, privateKey: string, auxRand?: Hex): Promise<string>;
async function schnorrSign(
  msgHash: Uint8Array,
  privateKey: Uint8Array,
  auxRand?: Hex
): Promise<Uint8Array>;
async function schnorrSign(
  msgHash: Hex,
  privateKey: PrivKey,
  auxRand: Hex = utils.randomPrivateKey()
): Promise<Hex> {
  if (msgHash == null) throw new TypeError(`Expected valid message, not "${msgHash}"`);
  // if (privateKey == null) throw new TypeError('Expected valid private key');
  if (!privateKey) privateKey = 0n;
  const { n } = CURVE;
  const m = typeof msgHash === 'string' ? hexToBytes(msgHash) : msgHash;
  const d0 = normalizePrivateKey(privateKey);
  if (!(0 < d0 && d0 < n)) throw new Error('Invalid private key');
  const rand = typeof auxRand === 'string' ? hexToBytes(auxRand) : auxRand;
  if (rand.length !== 32) throw new TypeError('Expected 32 bytes of aux randomness');

  const P = Point.fromPrivateKey(d0);
  const d = hasEvenY(P) ? d0 : n - d0;

  const t0h = await taggedHash('BIP0340/aux', rand);
  const t = d ^ t0h;

  const k0h = await taggedHash('BIP0340/nonce', pad32b(t), P.toRawX(), m);
  const k0 = mod(k0h, n);
  if (k0 === 0n) throw new Error('Creation of signature failed. k is zero');

  // R = k'⋅G
  const R = Point.fromPrivateKey(k0);
  const k = hasEvenY(R) ? k0 : n - k0;
  const e = await createChallenge(R.x, P, m);
  const sig = new SchnorrSignature(R.x, mod(k + e * d, n));
  const isValid = await schnorrVerify(sig.toRawBytes(), m, P.toRawX());

  if (!isValid) throw new Error('Invalid signature produced');
  return typeof msgHash === 'string' ? sig.toHex() : sig.toRawBytes();
}

// Also used in sign() function.
async function schnorrVerify(signature: Hex, msgHash: Hex, publicKey: Hex): Promise<boolean> {
  const sig =
    signature instanceof SchnorrSignature ? signature : SchnorrSignature.fromHex(signature);
  const m = typeof msgHash === 'string' ? hexToBytes(msgHash) : msgHash;

  const P = normalizePublicKey(publicKey);
  const e = await createChallenge(sig.r, P, m);

  // R = s⋅G - e⋅P
  const sG = Point.fromPrivateKey(sig.s);
  const eP = P.multiply(e);
  const R = sG.subtract(eP);

  if (R.equals(Point.BASE) || !hasEvenY(R) || R.x !== sig.r) return false;
  return true;
}

export const schnorr = {
  Signature: SchnorrSignature,
  getPublicKey: schnorrGetPublicKey,
  sign: schnorrSign,
  verify: schnorrVerify,
};

// Enable precomputes. Slows down first publicKey computation by 20ms.
Point.BASE._setWindowSize(8);

export const utils = {
  isValidPrivateKey(privateKey: PrivKey) {
    return isValidPrivateKey(normalizePrivateKey(privateKey));
  },

  randomPrivateKey: (bytesLength: number = 32): Uint8Array => {
    // @ts-ignore
    if (typeof window == 'object' && 'crypto' in window) {
      // @ts-ignore
      return window.crypto.getRandomValues(new Uint8Array(bytesLength));
      // @ts-ignore
    } else if (typeof process === 'object' && 'node' in process.versions) {
      // @ts-ignore
      const { randomBytes } = require('crypto');
      return new Uint8Array(randomBytes(bytesLength).buffer);
    } else {
      throw new Error("The environment doesn't have randomBytes function");
    }
  },

  sha256: async (message: Uint8Array): Promise<Uint8Array> => {
    // @ts-ignore
    if (typeof window == 'object' && 'crypto' in window) {
      // @ts-ignore
      const buffer = await window.crypto.subtle.digest('SHA-256', message.buffer);
      // @ts-ignore
      return new Uint8Array(buffer);
      // @ts-ignore
    } else if (typeof process === 'object' && 'node' in process.versions) {
      // @ts-ignore
      const { createHash } = require('crypto');
      return Uint8Array.from(createHash('sha256').update(message).digest());
    } else {
      throw new Error("The environment doesn't have sha256 function");
    }
  },

  hmacSha256: async (key: Uint8Array, ...messages: Uint8Array[]): Promise<Uint8Array> => {
    // @ts-ignore
    if (typeof window == 'object' && 'crypto' in window) {
      // @ts-ignore
      const ckey = await window.crypto.subtle.importKey(
        'raw',
        key,
        { name: 'HMAC', hash: { name: 'SHA-256' } },
        false,
        ['sign']
      );
      const message = concatBytes(...messages);
      // @ts-ignore
      const buffer = await window.crypto.subtle.sign('HMAC', ckey, message);
      return new Uint8Array(buffer);
      // @ts-ignore
    } else if (typeof process === 'object' && 'node' in process.versions) {
      // @ts-ignore
      const { createHmac, randomBytes } = require('crypto');
      const hash = createHmac('sha256', key);
      for (let message of messages) {
        hash.update(message);
      }
      return Uint8Array.from(hash.digest());
    } else {
      throw new Error("The environment doesn't have hmac-sha256 function");
    }
  },

  precompute(windowSize = 8, point = Point.BASE): Point {
    const cached = point === Point.BASE ? point : new Point(point.x, point.y);
    cached._setWindowSize(windowSize);
    cached.multiply(3n);
    return cached;
  },
};
