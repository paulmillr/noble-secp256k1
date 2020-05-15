/*! noble-secp256k1 - MIT License (c) Paul Miller (paulmillr.com) */
'use strict';
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

const P_DIV4_1 = (CURVE.P + 1n) / 4n;

// Cleaner js output if that's on a separate line.
export { CURVE };

// Short weistrass curve formula.
// y**2 = x**3 + ax + b
// Returns sqrY
function weistrass(x: bigint) {
  const { a, b } = CURVE;
  return mod(x ** 3n + a * x + b);
}

type Hex = Uint8Array | string;
type PrivKey = Hex | bigint | number;
type PubKey = Hex | Point;
type Signature = Hex | SignResult;

const PRIME_SIZE = 256;

// If we're using Koblitz curve, we can improve efficiency by using endomorphism.
// Uses 2x less RAM, speeds up precomputation by 2x and ECDH / sign key recovery by 20%.
// Should always be used for Jacobian's double-and-add multiplication.
// For affines cached multiplication, it trades off 1/2 init time & 1/3 ram for 20% perf hit.
// https://gist.github.com/paulmillr/eb670806793e84df628a7c434a873066
const USE_ENDOMORPHISM = CURVE.a === 0n;

// Default Point works in default aka affine coordinates: (x, y)
// Jacobian Point works in jacobi coordinates: (x, y, z) ∋ (x=x/z^2, y=y/z^3)
class JacobianPoint {
  constructor(public x: bigint, public y: bigint, public z: bigint) {}

  static BASE = new JacobianPoint(CURVE.Gx, CURVE.Gy, 1n);
  static ZERO = new JacobianPoint(0n, 0n, 1n);
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

  // Non-constant-time multiplication. Uses double-and-add algorithm.
  // It's faster, but should only be used when you don't care about
  // an exposed private key e.g. sig verification.
  multiplyUnsafe(scalar: bigint): JacobianPoint {
    if (typeof scalar !== 'number' && typeof scalar !== 'bigint') {
      throw new TypeError('Point#multiply: expected number or bigint');
    }
    let n = mod(BigInt(scalar), CURVE.n);
    if (n <= 0) {
      throw new Error('Point#multiply: invalid scalar, expected positive integer');
    }
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
    let [k1neg, k1, k2neg, k2] = splitScalar(n);
    let k1p = JacobianPoint.ZERO;
    let k2p = JacobianPoint.ZERO;
    let d: JacobianPoint = this;
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

  private precomputeWindow(W: number): JacobianPoint[] {
    const windows = USE_ENDOMORPHISM ? 128 / W + 2 : 256 / W + 1;
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

  private wNAF(n: bigint, affinePoint?: Point): [JacobianPoint, JacobianPoint] {
    if (!affinePoint && this.equals(JacobianPoint.BASE)) affinePoint = Point.BASE;
    const W = (affinePoint && affinePoint._WINDOW_SIZE) || 1;
    if (256 % W) {
      throw new Error('Point#wNAF: Invalid precomputation window, must be power of 2');
    }

    let precomputes = affinePoint && pointPrecomputes.get(affinePoint);
    if (!precomputes) {
      precomputes = this.precomputeWindow(W);
      if (affinePoint && W !== 1) {
        precomputes = JacobianPoint.normalizeZ(precomputes);
        pointPrecomputes.set(affinePoint, precomputes);
      }
    }

    let p = JacobianPoint.ZERO;
    let f = JacobianPoint.ZERO;

    const windows = USE_ENDOMORPHISM ? 128 / W + 2 : 256 / W + 1;
    const windowSize = 2 ** (W - 1);
    const mask = BigInt(2 ** W - 1); // Create mask with W ones: 0b1111 for W=4 etc.
    const maxNumber = 2 ** W;
    const shiftBy = BigInt(W);

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
    if (typeof scalar !== 'number' && typeof scalar !== 'bigint') {
      throw new TypeError('Point#multiply: expected number or bigint');
    }
    let n = mod(BigInt(scalar), CURVE.n);
    if (n <= 0) {
      throw new Error('Point#multiply: invalid scalar, expected positive integer');
    }
    // Real point.
    let point: JacobianPoint;
    // Fake point, we use it to achieve constant-time multiplication.
    let fake: JacobianPoint;
    if (USE_ENDOMORPHISM) {
      const [k1neg, k1, k2neg, k2] = splitScalar(n);
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
    return JacobianPoint.normalizeZ([point, fake])[0];
  }

  // Converts Jacobian point to default (x, y) coordinates.
  // Can accept precomputed Z^-1 - for example, from invertBatch.
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

  // "Private method", don't use it directly.
  _setWindowSize(windowSize: number) {
    this._WINDOW_SIZE = windowSize;
    pointPrecomputes.delete(this);
  }

  private static fromCompressedHex(bytes: Uint8Array) {
    if (bytes.length !== 33) {
      throw new TypeError(`Point.fromHex: compressed expects 66 bytes, not ${bytes.length * 2}`);
    }
    const x = arrayToNumber(bytes.slice(1));
    const sqrY = weistrass(x);
    let y = powMod(sqrY, P_DIV4_1, CURVE.P);
    const isFirstByteOdd = (bytes[0] & 1) === 1;
    const isYOdd = (y & 1n) === 1n;
    if (isFirstByteOdd !== isYOdd) {
      y = mod(-y);
    }
    const point = new Point(x, y);
    point.assertValidity();
    return point;
  }

  private static fromUncompressedHex(bytes: Uint8Array) {
    if (bytes.length !== 65) {
      throw new TypeError(`Point.fromHex: uncompressed expects 130 bytes, not ${bytes.length * 2}`);
    }
    const x = arrayToNumber(bytes.slice(1, 33));
    const y = arrayToNumber(bytes.slice(33));
    const point = new Point(x, y);
    point.assertValidity();
    return point;
  }

  // Converts hash string or Uint8Array to Point.
  static fromHex(hex: Hex) {
    const bytes = hex instanceof Uint8Array ? hex : hexToArray(hex);
    const header = bytes[0];
    if (header === 0x02 || header === 0x03) return this.fromCompressedHex(bytes);
    if (header === 0x04) return this.fromUncompressedHex(bytes);
    throw new TypeError('Point.fromHex: received invalid point');
  }

  // Multiplies generator point by privateKey.
  static fromPrivateKey(privateKey: PrivKey) {
    return Point.BASE.multiply(normalizePrivateKey(privateKey));
  }

  // Recovers public key from ECDSA signature.
  // TODO: Ensure proper hash length
  // Uses following formula:
  // Q = (r ** -1)(sP - hG)
  // https://crypto.stackexchange.com/questions/60218
  static fromSignature(msgHash: Hex, signature: Signature, recovery: number): Point | undefined {
    const sign = normalizeSignature(signature);
    const { r, s } = sign;
    if (r === 0n || s === 0n) return;
    const rinv = invert(r, CURVE.n);
    const h = typeof msgHash === 'string' ? hexToNumber(msgHash) : arrayToNumber(msgHash);
    const P_ = Point.fromHex(`0${2 + (recovery & 1)}${pad64(r)}`);
    const sP = JacobianPoint.fromAffine(P_).multiplyUnsafe(s);
    const hG = JacobianPoint.BASE.multiply(h).negate();
    const Q = sP.add(hG).multiplyUnsafe(rinv);
    const point = Q.toAffine();
    point.assertValidity();
    return point;
  }

  toRawBytes(isCompressed = false) {
    return hexToArray(this.toHex(isCompressed));
  }

  toHex(isCompressed = false) {
    const x = pad64(this.x);
    if (isCompressed) {
      return `${this.y & 1n ? '03' : '02'}${x}`;
    } else {
      return `04${x}${pad64(this.y)}`;
    }
  }

  // A point on curve is valid if it conforms to equation.
  assertValidity(): void {
    const { x, y } = this;
    if (x === 0n || y === 0n || x >= CURVE.P || y >= CURVE.P) {
      throw new TypeError('Point is not on elliptic curve');
    }

    const sqrY = mod(y * y);
    const yEquivalence = weistrass(x);
    const left1 = sqrY;
    const left2 = mod(-sqrY);
    const right1 = yEquivalence;
    const right2 = mod(-yEquivalence);
    const res = left1 === right1 || left1 === right2 || left2 === right1 || left2 === right2;
    if (!res) throw new TypeError('Point is not on elliptic curve');
  }

  equals(other: Point): boolean {
    return this.x === other.x && this.y === other.y;
  }

  negate() {
    return new Point(this.x, mod(-this.y));
  }

  double() {
    return JacobianPoint.fromAffine(this).double().toAffine();
  }

  add(other: Point) {
    return JacobianPoint.fromAffine(this).add(JacobianPoint.fromAffine(other)).toAffine();
  }

  subtract(other: Point) {
    return this.add(other.negate());
  }

  // Constant time multiplication.
  multiply(scalar: number | bigint) {
    return JacobianPoint.fromAffine(this).multiply(scalar, this).toAffine();
  }
}

export class SignResult {
  constructor(public r: bigint, public s: bigint) {}

  // DER encoded ECDSA signature
  // https://bitcoin.stackexchange.com/questions/57644/what-are-the-parts-of-a-bitcoin-transaction-input-script
  static fromHex(hex: Hex) {
    // `30${length}02${rLen}${rHex}02${sLen}${sHex}`
    const str = hex instanceof Uint8Array ? arrayToHex(hex) : hex;
    if (typeof str !== 'string') throw new TypeError({}.toString.call(hex));

    const check1 = str.slice(0, 2);
    const length = parseByte(str.slice(2, 4));
    const check2 = str.slice(4, 6);
    if (check1 !== '30' || length !== str.length - 4 || check2 !== '02') {
      throw new Error('SignResult.fromHex: Invalid signature');
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

    return new SignResult(r, s);
  }

  toRawBytes(isCompressed = false) {
    return hexToArray(this.toHex(isCompressed));
  }

  toHex(isCompressed = false) {
    const sHex = numberToHex(this.s);
    if (isCompressed) return sHex;
    const rHex = numberToHex(this.r);
    const rLen = numberToHex(rHex.length / 2);
    const sLen = numberToHex(sHex.length / 2);
    const length = numberToHex(rHex.length / 2 + sHex.length / 2 + 4);
    return `30${length}02${rLen}${rHex}02${sLen}${sHex}`;
  }
}

function concatTypedArrays(...arrays: Uint8Array[]): Uint8Array {
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
function arrayToHex(uint8a: Uint8Array): string {
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

function hexToArray(hex: string): Uint8Array {
  hex = hex.length & 1 ? `0${hex}` : hex;
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    let j = i * 2;
    array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
  }
  return array;
}

// Big Endian
function arrayToNumber(bytes: Uint8Array): bigint {
  return hexToNumber(arrayToHex(bytes));
}

function parseByte(str: string): number {
  return Number.parseInt(str, 16) * 2;
}

// -------------------------

function mod(a: bigint, b: bigint = CURVE.P): bigint {
  const result = a % b;
  return result >= 0 ? result : b + result;
}

function powMod(x: bigint, power: bigint, order: bigint) {
  let res = 1n;
  while (power > 0) {
    if (power & 1n) {
      res = mod(res * x, order);
    }
    power >>= 1n;
    x = mod(x * x, order);
  }
  return res;
}

// Eucledian GCD
// https://brilliant.org/wiki/extended-euclidean-algorithm/
function egcd(a: bigint, b: bigint) {
  let [x, y, u, v] = [0n, 1n, 1n, 0n];
  while (a !== 0n) {
    let q = b / a;
    let r = b % a;
    let m = x - u * q;
    let n = y - v * q;
    [b, a] = [a, r];
    [x, y] = [u, v];
    [u, v] = [m, n];
  }
  let gcd = b;
  return [gcd, x, y];
}

function invert(number: bigint, modulo: bigint = CURVE.P) {
  if (number === 0n || modulo <= 0n) {
    throw new Error('invert: expected positive integers');
  }
  let [gcd, x] = egcd(mod(number, modulo), modulo);
  if (gcd !== 1n) {
    throw new Error('invert: does not exist');
  }
  return mod(x, modulo);
}

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
    let tmp = mod(acc * nums[i], n);
    nums[i] = mod(acc * scratch[i], n);
    acc = tmp;
  }
  return nums;
}

// Split 256-bit K into 2 128-bit (k1, k2) for which k1 + k2 * lambda = K.
// https://gist.github.com/paulmillr/eb670806793e84df628a7c434a873066
function splitScalar(k: bigint): [boolean, bigint, boolean, bigint] {
  const { n } = CURVE;
  const a1 = 0x3086d221a7d46bcde86c90e49284eb15n;
  const b1 = -0xe4437ed6010e88286f547fa90abfe4c3n;
  const a2 = 0x114ca50f7a8e2f3f657c1108d9d44cfd8n;
  const b2 = a1;
  const c1 = (b2 * k) / n;
  const c2 = (-b1 * k) / n;
  const k1 = k - c1 * a1 - c2 * a2;
  const k2 = -c1 * b1 - c2 * b2;
  const k1neg = k1 < 0;
  const k2neg = k2 < 0;
  // let lambda = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72n;
  return [k1neg, k1neg ? -k1 : k1, k2neg, k2neg ? -k2 : k2];
}

function truncateHash(hash: string | Uint8Array): bigint {
  hash = typeof hash === 'string' ? hash : arrayToHex(hash);
  let msg = hexToNumber(hash || '0');
  const delta = (hash.length / 2) * 8 - PRIME_SIZE;
  if (delta > 0) {
    msg = msg >> BigInt(delta);
  }
  if (msg >= CURVE.n) {
    msg -= CURVE.n;
  }
  return msg;
}

type QRS = [Point, bigint, bigint];

// Deterministic k generation as per RFC6979.
// Generates k, and then calculates Q & Signature {r, s} based on it.
// https://tools.ietf.org/html/rfc6979#section-3.1
async function getQRSrfc6979(msgHash: Hex, privateKey: bigint) {
  // Step A is ignored, since we already provide hash instead of msg
  const num = typeof msgHash === 'string' ? hexToNumber(msgHash) : arrayToNumber(msgHash);
  const h1 = hexToArray(pad64(num));
  const x = hexToArray(pad64(privateKey));
  const h1n = arrayToNumber(h1);

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
    const T = arrayToNumber(v);
    let qrs: QRS;
    if (isValidPrivateKey(T) && (qrs = calcQRSFromK(T, h1n, privateKey)!)) {
      return qrs;
    }
    k = await utils.hmacSha256(k, v, b0);
    v = await utils.hmacSha256(k, v);
  }

  throw new TypeError('secp256k1: Tried 1,000 k values for sign(), all were invalid');
}

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
  if (!privateKey) throw new Error(`Expected receive valid private key, not "${privateKey}"`);
  let key: bigint;
  if (privateKey instanceof Uint8Array) {
    key = arrayToNumber(privateKey);
  } else if (typeof privateKey === 'string') {
    key = hexToNumber(privateKey);
  } else {
    key = BigInt(privateKey);
  }
  return key;
}

function normalizePublicKey(publicKey: PubKey): Point {
  return publicKey instanceof Point ? publicKey : Point.fromHex(publicKey);
}

function normalizeSignature(signature: Signature): SignResult {
  return signature instanceof SignResult ? signature : SignResult.fromHex(signature);
}

export function getPublicKey(
  privateKey: Uint8Array | bigint | number,
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
export function recoverPublicKey(
  msgHash: Hex,
  signature: Signature,
  recovery: number
): Hex | undefined {
  const point = Point.fromSignature(msgHash, signature, recovery);
  if (!point) return;
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
  if (isPub(privateA) && !isPub(publicB)) {
    [privateA, publicB] = [publicB as PrivKey, privateA as PubKey];
  } else if (!isPub(publicB)) {
    throw new Error('Received invalid keys');
  }
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
  const sig = new SignResult(r, adjustedS);
  const hashed = typeof msgHash === 'string' ? sig.toHex() : sig.toRawBytes();
  return recovered ? [hashed, recovery] : hashed;
}

export function verify(signature: Signature, msgHash: Hex, publicKey: PubKey): boolean {
  const h = truncateHash(msgHash);
  const { r, s } = normalizeSignature(signature);
  const pubKey = JacobianPoint.fromAffine(normalizePublicKey(publicKey));
  const s1 = invert(s, CURVE.n);
  const Ghs1 = JacobianPoint.BASE.multiply(mod(h * s1, CURVE.n));
  const Prs1 = pubKey.multiplyUnsafe(mod(r * s1, CURVE.n));
  const res = Ghs1.add(Prs1).toAffine();
  return res.x === r;
}

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

  hmacSha256: async (key: Uint8Array, ...messages: Uint8Array[]): Promise<Uint8Array> => {
    // @ts-ignore
    if (typeof window == 'object' && 'crypto' in window) {
      // @ts-ignore
      const ckey = await window.crypto.subtle.importKey(
        'raw',
        key,
        { name: 'HMAC', hash: { name: 'SHA-256' } },
        false,
        ['sign', 'verify']
      );
      const message = concatTypedArrays(...messages);
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
