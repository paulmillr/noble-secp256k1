/*! noble-secp256k1 - MIT License (c) Paul Miller (paulmillr.com) */
'use strict';

// https://www.secg.org/sec2-v2.pdf
// Curve fomula is y^2 = x^3 + ax + b
export const CURVE_PARAMS = {
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
  Gy: 32670510020758816978083085130507043184471273380659243275938904335757337482424n
};

// y**2 = x**3 + ax + b
// Returns sqrY
function curve(x: bigint) {
  const { a, b } = CURVE_PARAMS;
  return mod(x ** 3n + a * x + b);
}

type PrivKey = Uint8Array | string | bigint | number;
type PubKey = Uint8Array | string | Point;
type Hex = Uint8Array | string;
type Signature = Uint8Array | string | SignResult;

const P = CURVE_PARAMS.P;
const PRIME_ORDER = CURVE_PARAMS.n;

const PRIME_SIZE = 256;
const HIGH_NUMBER = PRIME_ORDER >> 1n;
const SUBPN = P - PRIME_ORDER;

// Default Point works in default aka affine coordinates: (x, y)
// Jacobian Point works in jacobi coordinates: (x, y, z) ∋ (x=x/z^2, y=y/z^3)
class JacobianPoint {
  static ZERO_POINT = new JacobianPoint(0n, 0n, 1n);
  static fromAffine(p: Point): JacobianPoint {
    return new JacobianPoint(p.x, p.y, 1n);
  }

  constructor(public x: bigint, public y: bigint, public z: bigint) {}

  // Takes a bunch of Jacobian Points but executes only one
  // modInverse on all of them. modInverse is very slow operation,
  // so this improves performance massively.
  static batchAffine(points: JacobianPoint[]): Point[] {
    const toInv = batchInverse(points.map(p => p.z));
    return points.map((p, i) => p.toAffine(toInv[i]));
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

  // Inverses point to one corresponding to (x, -y) in Affine coordinates.
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
        return JacobianPoint.ZERO_POINT;
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
    let n = mod(BigInt(scalar), PRIME_ORDER);
    if (n <= 0) {
      throw new Error('Point#multiply: invalid scalar, expected positive integer');
    }
    let p = JacobianPoint.ZERO_POINT;
    let d: JacobianPoint = this;
    while (n > 0n) {
      if (n & 1n) p = p.add(d);
      d = d.double();
      n >>= 1n;
    }
    return p;
  }

  // Converts Jacobian point to default (x, y) coordinates.
  // Can accept precomputed Z^-1 - for example, from batchInverse.
  toAffine(invZ: bigint = modInverse(this.z)): Point {
    const invZ2 = invZ ** 2n;
    const x = mod(this.x * invZ2);
    const y = mod(this.y * invZ2 * invZ);
    return new Point(x, y);
  }
}

// Default Point works in default aka affine coordinates: (x, y)
export class Point {
  // Base point aka generator
  // public_key = base_point * private_key
  static BASE_POINT: Point = new Point(CURVE_PARAMS.Gx, CURVE_PARAMS.Gy);
  // Identity point aka point at infinity
  // point = point + zero_point
  static ZERO_POINT: Point = new Point(0n, 0n);
  // We calculate precomputes for elliptic curve point multiplication
  // using windowed method. This specifies window size and
  // stores precomputed values. Usually only base point would be precomputed.
  private WINDOW_SIZE?: number;
  private PRECOMPUTES?: JacobianPoint[];

  constructor(public x: bigint, public y: bigint) {}

  // "Private method", don't use it directly.
  _setWindowSize(windowSize: number) {
    this.WINDOW_SIZE = windowSize;
    this.PRECOMPUTES = undefined;
  }

  // A point on curve is valid if it conforms to equation.
  static isValid(x: bigint, y: bigint) {
    if (x === 0n || y === 0n || x >= P || y >= P) return false;

    const sqrY = mod(y * y);
    const yEquivalence = curve(x);
    const left1 = sqrY;
    const left2 = mod(-sqrY);
    const right1 = yEquivalence;
    const right2 = mod(-yEquivalence);
    return left1 === right1 || left1 === right2 || left2 === right1 || left2 === right2;
  }

  private static fromCompressedHex(bytes: Uint8Array) {
    if (bytes.length !== 33) {
      throw new TypeError(`Point.fromHex: compressed expects 66 bytes, not ${bytes.length * 2}`);
    }
    const x = arrayToNumber(bytes.slice(1));
    const sqrY = curve(x);
    let y = powMod(sqrY, (P + 1n) / 4n, P);
    const isFirstByteOdd = (bytes[0] & 1) === 1;
    const isYOdd = (y & 1n) === 1n;
    if (isFirstByteOdd !== isYOdd) {
      y = mod(-y);
    }
    if (!this.isValid(x, y)) {
      throw new TypeError('Point.fromHex: Point is not on elliptic curve');
    }
    return new Point(x, y);
  }

  private static fromUncompressedHex(bytes: Uint8Array) {
    if (bytes.length !== 65) {
      throw new TypeError(`Point.fromHex: uncompressed expects 130 bytes, not ${bytes.length * 2}`);
    }
    const x = arrayToNumber(bytes.slice(1, 33));
    const y = arrayToNumber(bytes.slice(33));
    if (!this.isValid(x, y)) {
      throw new TypeError('Point.fromHex: Point is not on elliptic curve');
    }
    return new Point(x, y);
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
    return Point.BASE_POINT.multiply(normalizePrivateKey(privateKey));
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
    const rinv = modInverse(r, PRIME_ORDER);
    const h = typeof msgHash === 'string' ? hexToNumber(msgHash) : arrayToNumber(msgHash);
    const P_ = Point.fromHex(`0${2 + (recovery & 1)}${pad64(r)}`);
    const sP = P_.multiply(s, false);
    const hG = Point.BASE_POINT.multiply(h, false).negate();
    const Q = sP.add(hG).multiplyUnsafe(rinv);
    return Q.toAffine();
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

  equals(other: Point): boolean {
    return this.x === other.x && this.y === other.y;
  }

  negate(): Point {
    return new Point(this.x, mod(-this.y));
  }

  // Adds point to itself. http://hyperelliptic.org/EFD/g1p/auto-shortw.html
  double(): Point {
    const X1 = this.x;
    const Y1 = this.y;
    const lambda = mod(3n * X1 ** 2n * modInverse(2n * Y1));
    const X3 = mod(lambda * lambda - 2n * X1);
    const Y3 = mod(lambda * (X1 - X3) - Y1);
    return new Point(X3, Y3);
  }

  // Adds point to other point. http://hyperelliptic.org/EFD/g1p/auto-shortw.html
  add(other: Point): Point {
    if (!(other instanceof Point)) {
      throw new TypeError('Point#add: expected Point');
    }
    const a = this;
    const b = other;
    const X1 = a.x;
    const Y1 = a.y;
    const X2 = b.x;
    const Y2 = b.y;
    if (a.equals(Point.ZERO_POINT)) return b;
    if (b.equals(Point.ZERO_POINT)) return a;
    if (X1 === X2) {
      if (Y1 === Y2) {
        return this.double();
      } else {
        // return ZERO_POINT;
        // TODO: remove Point at undefined.
        throw new TypeError('Point#add: cannot add points (a.x == b.x, a.y != b.y)');
      }
    }
    const lambda = mod((Y2 - Y1) * modInverse(X2 - X1));
    const X3 = mod(lambda * lambda - X1 - X2);
    const Y3 = mod(lambda * (X1 - X3) - Y1);
    return new Point(X3, Y3);
  }

  subtract(other: Point) {
    return this.add(other.negate());
  }

  private precomputeWindow(W: number): JacobianPoint[] {
    if (this.PRECOMPUTES) return this.PRECOMPUTES;
    const points: JacobianPoint[] = new Array((2 ** W - 1) * W);
    let currPoint: JacobianPoint = JacobianPoint.fromAffine(this);
    const winSize = 2 ** W - 1;
    for (let currWin = 0; currWin < 256 / W; currWin++) {
      let offset = currWin * winSize;
      let point: JacobianPoint = currPoint;
      for (let i = 0; i < winSize; i++) {
        points[offset + i] = point;
        point = point.add(currPoint);
      }
      currPoint = point;
    }
    let res = points;
    if (W !== 1) {
      res = JacobianPoint.batchAffine(points).map(p => JacobianPoint.fromAffine(p));
      this.PRECOMPUTES = res;
    }
    return res;
  }

  // Constant time multiplication.
  // Uses window method to generate 2^W precomputed points.
  multiply(scalar: bigint, isAffine: false): JacobianPoint;
  multiply(scalar: bigint, isAffine?: true): Point;
  multiply(scalar: bigint, isAffine = true): Point | JacobianPoint {
    if (typeof scalar !== 'number' && typeof scalar !== 'bigint') {
      throw new TypeError('Point#multiply: expected number or bigint');
    }
    let n = mod(BigInt(scalar), PRIME_ORDER);
    if (n <= 0) {
      throw new Error('Point#multiply: invalid scalar, expected positive integer');
    }
    // TODO: remove the check in the future, need to adjust tests.
    if (scalar > PRIME_ORDER) {
      throw new Error('Point#multiply: invalid scalar, expected < PRIME_ORDER');
    }
    const W = this.WINDOW_SIZE || 1;
    if (256 % W) {
      throw new Error('Point#multiply: Invalid precomputation window, must be power of 2');
    }
    const precomputes = this.precomputeWindow(W);
    const winSize = 2 ** W - 1;
    let p = JacobianPoint.ZERO_POINT;
    let f = JacobianPoint.ZERO_POINT;
    for (let byteIdx = 0; byteIdx < 256 / W; byteIdx++) {
      const offset = winSize * byteIdx;
      const masked = Number(n & BigInt(winSize));
      if (masked) {
        p = p.add(precomputes[offset + masked - 1]);
      } else {
        f = f.add(precomputes[offset]);
      }
      n >>= BigInt(W);
    }
    return isAffine ? JacobianPoint.batchAffine([p, f])[0] : p;
  }
}

const { BASE_POINT } = Point;

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

// HMAC-SHA256 implementation.
let hmac: (key: Uint8Array, ...messages: Uint8Array[]) => Promise<Uint8Array>;
let generateRandomPrivateKey = (bytesLength: number = 32) => new Uint8Array(0);

if (typeof window == 'object' && 'crypto' in window) {
  hmac = async (key: Uint8Array, ...messages: Uint8Array[]) => {
    const ckey = await window.crypto.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash: { name: 'SHA-256' } },
      false,
      ['sign', 'verify']
    );
    const message = concatTypedArrays(...messages);
    const buffer = await window.crypto.subtle.sign('HMAC', ckey, message);
    return new Uint8Array(buffer);
  };
  generateRandomPrivateKey = (bytesLength: number = 32): Uint8Array => {
    return window.crypto.getRandomValues(new Uint8Array(bytesLength));
  };
} else if (typeof process === 'object' && 'node' in process.versions) {
  const req = require;
  const { createHmac, randomBytes } = req('crypto');

  hmac = async (key: Uint8Array, ...messages: Uint8Array[]) => {
    const hash = createHmac('sha256', key);
    for (let message of messages) {
      hash.update(message);
    }
    return Uint8Array.from(hash.digest());
  };
  generateRandomPrivateKey = (bytesLength: number = 32): Uint8Array => {
    return new Uint8Array(randomBytes(bytesLength).buffer);
  };
} else {
  throw new Error("The environment doesn't have hmac-sha256 function");
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

function mod(a: bigint, b: bigint = P): bigint {
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

function modInverse(number: bigint, modulo: bigint = P) {
  if (number === 0n || modulo <= 0n) {
    throw new Error('modInverse: expected positive integers');
  }
  let [gcd, x] = egcd(mod(number, modulo), modulo);
  if (gcd !== 1n) {
    throw new Error('modInverse: does not exist');
  }
  return mod(x, modulo);
}

function batchInverse(nums: bigint[], n: bigint = P): bigint[] {
  const len = nums.length;
  const scratch = new Array(len);
  let acc = 1n;
  for (let i = 0; i < len; i++) {
    if (nums[i] === 0n) continue;
    scratch[i] = acc;
    acc = mod(acc * nums[i], n);
  }
  acc = modInverse(acc, n);
  for (let i = len - 1; i >= 0; i--) {
    if (nums[i] === 0n) continue;
    let tmp = mod(acc * nums[i], n);
    nums[i] = mod(acc * scratch[i], n);
    acc = tmp;
  }
  return nums;
}

function truncateHash(hash: string | Uint8Array): bigint {
  hash = typeof hash === 'string' ? hash : arrayToHex(hash);
  let msg = hexToNumber(hash || '0');
  const delta = (hash.length / 2) * 8 - PRIME_SIZE;
  if (delta > 0) {
    msg = msg >> BigInt(delta);
  }
  if (msg >= PRIME_ORDER) {
    msg -= PRIME_ORDER;
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
  k = await hmac(k, v, b0, x, h1);
  // Step E
  v = await hmac(k, v);
  // Step F
  k = await hmac(k, v, b1, x, h1);
  // Step G
  v = await hmac(k, v);

  // Step H3, repeat until 1 < T < n - 1
  for (let i = 0; i < 1000; i++) {
    v = await hmac(k, v);
    const T = arrayToNumber(v);
    let qrs: QRS;
    if (isValidPrivateKey(T) && (qrs = calcQRSFromK(T, h1n, privateKey)!)) {
      return qrs;
    }
    k = await hmac(k, v, b0);
    v = await hmac(k, v);
  }

  throw new TypeError('secp256k1: Tried 1,000 k values for sign(), all were invalid');
}

function isValidPrivateKey(privateKey: bigint): boolean {
  return 0 < privateKey && privateKey < PRIME_ORDER;
}

function calcQRSFromK(k: bigint, msg: bigint, priv: bigint): QRS | undefined {
  const q = BASE_POINT.multiply(k);
  const r = mod(q.x, PRIME_ORDER);
  const s = mod(modInverse(k, PRIME_ORDER) * (msg + r * priv), PRIME_ORDER);
  if (r === 0n || s === 0n) return;
  return [q, r, s];
}

function normalizePrivateKey(privateKey: PrivKey): bigint {
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
export function getPublicKey(privateKey: PrivKey, isCompressed?: boolean): PubKey {
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

export function getSharedSecret(privateA: PrivKey, publicB: PubKey): Uint8Array | string {
  const point = publicB instanceof Point ? publicB : Point.fromHex(publicB);
  const shared = point.multiply(normalizePrivateKey(privateA));
  return typeof privateA === 'string' ? shared.toHex() : shared.toRawBytes();
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
  const priv = normalizePrivateKey(privateKey);
  if (!isValidPrivateKey(priv)) {
    throw new Error('Private key is invalid. Expected 0 < key < PRIME_ORDER');
  }
  // We are using deterministic signature scheme
  // instead of letting user specify random `k`.
  const [q, r, s] = await getQRSrfc6979(msgHash, priv);

  let recovery = (q.x === r ? 0 : 2) | Number(q.y & 1n);
  let adjustedS = s;
  if (s > HIGH_NUMBER && canonical) {
    adjustedS = PRIME_ORDER - s;
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
  const s1 = modInverse(s, PRIME_ORDER);
  const Ghs1 = BASE_POINT.multiply(mod(h * s1, PRIME_ORDER), false);
  const Prs1 = pubKey.multiplyUnsafe(mod(r * s1, PRIME_ORDER));
  const res = Ghs1.add(Prs1).toAffine();
  return res.x === r;
}

// Enable precomputes. Slows down first publicKey computation by 20ms.
BASE_POINT._setWindowSize(4);

export const utils = {
  isValidPrivateKey(privateKey: PrivKey) {
    return isValidPrivateKey(normalizePrivateKey(privateKey));
  },

  generateRandomPrivateKey,

  precompute(windowSize = 4, point = BASE_POINT): Point {
    const cached = point === BASE_POINT ? point : new Point(point.x, point.y);
    cached._setWindowSize(windowSize);
    cached.multiply(1n);
    return cached;
  }
};
