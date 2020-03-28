/*! noble-secp256k1 - MIT License (c) Paul Miller (paulmillr.com) */

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

function batchInverse(elms: bigint[], n: bigint) {
  let scratch = Array(elms.length);
  let acc = 1n;
  for (let i = 0; i < elms.length; i++) {
    if (!elms[i]) continue;
    scratch[i] = acc;
    acc = mod(acc * elms[i], n);
  }
  acc = modInverse(acc, n);
  for (let i = elms.length - 1; i >= 0; i--) {
    if (!elms[i]) continue;
    let tmp = mod(acc * elms[i], n);
    elms[i] = mod(acc * scratch[i], n);
    acc = tmp;
  }
}

function batchAdd(parrs: Point[][]): Point[] {
  // if length is not even -- save last point
  let lastArr = new Array(parrs.length);
  for (let i = 0; i < parrs.length; i++) {
    let parr = parrs[i],
      last = [];
    if (parr.length % 2) last.push(parr.pop() as Point);
    lastArr[i] = last;
  }
  // First pass: add inversions to batch
  let to_inv = [];
  for (let i = 0; i < parrs.length; i++) {
    let parr = parrs[i];
    let last = lastArr[i];
    for (let j = 0; j < parr.length; j += 2) {
      let p1 = parr[j];
      let p2 = parr[j + 1];
      let p1z = p1.equals(Point.ZERO_POINT);
      let p2z = p2.equals(Point.ZERO_POINT);
      let inv = 0n;
      if (p1z && p2z) {
      } else if (p1z) last.push(p2);
      else if (p2z) last.push(p1);
      else if (p1.x !== p2.x) inv = mod(p2.x - p1.x, P);
      // add
      else if (p1.y === p2.y) inv = mod(2n * p1.y, P);
      // double
      else throw new TypeError('Point#batchAdd: incorrect invariant');
      to_inv.push(inv);
    }
  }
  batchInverse(to_inv, P);
  // Second pass: process rest of formula
  let ij = 0;
  for (let i = 0; i < parrs.length; i++) {
    let parr = parrs[i];
    let last = lastArr[i];
    for (let j = 0; j < parr.length; j += 2) {
      let p1 = parr[j];
      let p2 = parr[j + 1];
      let inv = to_inv[ij++];
      if (!inv) continue;
      let x, y;
      if (p1.x !== p2.x) {
        // add
        let m = mod((p2.y - p1.y) * inv, P);
        x = mod(m * m - p1.x - p2.x, P);
        y = mod(m * (p1.x - x) - p1.y, P);
      } else {
        // double
        let m = mod(3n * p1.x * p1.x * inv, P);
        x = mod(m * m - 2n * p1.x, P);
        y = mod(m * (p1.x - x) - p1.y, P);
      }
      last.push(new Point(x, y));
    }
  }
  // Recursively process rest of parrs if they has 2 or more elements
  let output = new Array(parrs.length);
  let toProcess = [];
  for (let i = 0; i < lastArr.length; i++) {
    let last = lastArr[i];
    if (last.length > 1) toProcess.push(last);
    else output[i] = !last.length ? Point.ZERO_POINT : last[0];
  }
  if (toProcess.length) {
    let j = 0;
    let processed = batchAdd(toProcess);
    for (let i = 0; i < output.length; i++) output[i] = output[i] || processed[j++];
  }
  return output;
}

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
  WINDOW_SIZE?: number;
  private PRECOMPUTES?: Point[];

  constructor(public x: bigint, public y: bigint) {}

  // A point on curve is valid if it conforms to equation
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

  static fromHex(hex: Hex) {
    const bytes = hex instanceof Uint8Array ? hex : hexToArray(hex);
    const header = bytes[0];
    if (header === 0x02 || header === 0x03) return this.fromCompressedHex(bytes);
    if (header === 0x04) return this.fromUncompressedHex(bytes);
    throw new TypeError('Point.fromHex: received invalid point');
  }

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
    const sP = P_.multiply(s);
    const hG = Point.BASE_POINT.multiply(h).negate();
    const Q = sP.add(hG).multiply(rinv);
    return Q;
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

  negate(): Point {
    return new Point(this.x, mod(-this.y));
  }

  add(other: Point): Point {
    if (!(other instanceof Point)) {
      throw new TypeError('Point#add: expected Point');
    }
    const a = this;
    const b = other;
    if (a.equals(Point.ZERO_POINT)) return b;
    if (b.equals(Point.ZERO_POINT)) return a;
    if (a.x === b.x) {
      if (a.y === b.y) {
        return this.double();
      } else {
        // return ZERO_POINT;
        // Point at undefined.
        throw new TypeError('Point#add: cannot add points (a.x == b.x, a.y != b.y)');
      }
    }
    const lamAdd = mod((b.y - a.y) * modInverse(b.x - a.x));
    const x = mod(lamAdd * lamAdd - a.x - b.x);
    const y = mod(lamAdd * (a.x - x) - a.y);
    return new Point(x, y);
  }

  subtract(other: Point) {
    return this.add(other.negate());
  }

  private double(): Point {
    const a = this;
    const lam = mod(3n * a.x * a.x * modInverse(2n * a.y));
    const x = mod(lam * lam - 2n * a.x);
    const y = mod(lam * (a.x - x) - a.y);
    return new Point(x, y);
  }

  equals(other: Point) {
    return this.x === other.x && this.y === other.y;
  }

  private precomputeWindow(W: number): Point[] {
    if (this.PRECOMPUTES) return this.PRECOMPUTES;
    const points: Point[] = new Array((2 ** W - 1) * W);
    if (W !== 1) {
      this.PRECOMPUTES = points;
    }
    let currPoint: Point = this;
    const winSize = 2 ** W - 1;
    for (let currWin = 0; currWin < 256 / W; currWin++) {
      let offset = currWin * winSize;
      let point: Point = currPoint;
      for (let i = 0; i < winSize; i++) {
        points[offset + i] = point;
        point = point.add(currPoint);
      }
      currPoint = point;
    }
    return points;
  }

  multiply(scalar: bigint): Point {
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
    let win_sz = 2 ** W - 1,
      parr = [],
      farr = [];
    let p = new Point(0n, 0n);
    for (let byte_idx = 0; byte_idx < 256 / W; byte_idx++) {
      const offset = win_sz * byte_idx;
      const masked = Number(n & BigInt(win_sz));
      if (!masked) {
        farr.push(precomputes[offset]);
      } else {
        parr.push(precomputes[offset + masked - 1]);
      }
      n >>= BigInt(W);
    }
    return batchAdd([parr, farr])[0];
  }

  // Constant time multiplication.
  // Benchmark of different methods for the reference:
  // - windowed method (current): 4ms (30ms custom point), 75ms first start
  // - powers of 2 constant-time: 14ms (30ms custom point), 35ms first start
  // - double-and-add constant-time: 30ms
  // - wNAF with w=4: 0.12ms - 18ms, non-constant
  multiply2(scalar: number | bigint): Point {
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
    let p = Point.ZERO_POINT;
    let f = Point.ZERO_POINT;
    const winSize = 2 ** W - 1;
    for (let currWin = 0; currWin < 256 / W; currWin++) {
      const offset = currWin * winSize;
      const masked = Number(n & BigInt(winSize));
      if (masked) {
        p = p.add(precomputes[offset + masked - 1]);
      } else {
        f = f.add(precomputes[offset]);
      }
      n >>= BigInt(W);
    }
    return p;
  }
}

function parseByte(str: string) {
  return Number.parseInt(str, 16) * 2;
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

  toHex(compressed = false) {
    const rHex = numberToHex(this.r); //.padStart(64, '0');
    const sHex = numberToHex(this.s); //.padStart(64, '0');
    if (compressed) return sHex;
    const rLen = numberToHex(rHex.length / 2);
    const sLen = numberToHex(sHex.length / 2);
    const length = numberToHex(rHex.length / 2 + sHex.length / 2 + 4);
    return `30${length}02${rLen}${rHex}02${sLen}${sHex}`;
  }
}

// HMAC-SHA256 implementation.
let hmac: (key: Uint8Array, message: Uint8Array) => Promise<Uint8Array>;

if (typeof window == 'object' && 'crypto' in window) {
  hmac = async (key: Uint8Array, message: Uint8Array) => {
    const ckey = await window.crypto.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash: { name: 'SHA-256' } },
      false,
      ['sign', 'verify']
    );
    const buffer = await window.crypto.subtle.sign('HMAC', ckey, message);
    return new Uint8Array(buffer);
  };
} else if (typeof process === 'object' && 'node' in process.versions) {
  const req = require;
  const { createHmac } = req('crypto');

  hmac = async (key: Uint8Array, message: Uint8Array) => {
    const hash = createHmac('sha256', key);
    hash.update(message);
    return Uint8Array.from(hash.digest());
  };
} else {
  throw new Error("The environment doesn't have hmac-sha256 function");
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

function arrayToNumber(bytes: Uint8Array): bigint {
  return hexToNumber(arrayToHex(bytes));
}

function pad64(num: number | bigint): string {
  return num.toString(16).padStart(64, '0');
}

// -------------------------

function mod(a: bigint, b: bigint = P): bigint {
  const result = a % b;
  return result >= 0 ? result : b + result;
}

function modInverse(v: bigint, n: bigint = P): bigint {
  let lm = 1n;
  let hm = 0n;
  let low = mod(v, n);
  let high = n;
  let ratio = 0n;
  let nm = 0n;
  let enew = 0n;
  while (low > 1n) {
    ratio = high / low;
    nm = hm - lm * ratio;
    enew = high - low * ratio;
    hm = lm;
    lm = nm;
    high = low;
    low = enew;
  }
  return mod(nm, n);
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

function concatTypedArrays(...args: Array<Uint8Array>): Uint8Array {
  const result = new Uint8Array(args.reduce((a, arr) => a + arr.length, 0));
  for (let i = 0, pad = 0; i < args.length; i++) {
    const arr = args[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
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
  const concat = concatTypedArrays;

  // Step D
  k = await hmac(k, concat(v, b0, x, h1));
  // Step E
  v = await hmac(k, v);
  // Step F
  k = await hmac(k, concat(v, b1, x, h1));
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
    k = await hmac(k, concat(v, b0));
    v = await hmac(k, v);
  }

  throw new TypeError('secp256k1: Tried 1,000 k values for sign(), all were invalid');
}

function isValidPrivateKey(privateKey: bigint): boolean {
  return 0 < privateKey && privateKey < PRIME_ORDER;
}

function calcQRSFromK(k: bigint, msg: bigint, priv: bigint): QRS | undefined {
  const q = Point.BASE_POINT.multiply(k);
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

export function getSharedSecret(privateA: PrivKey, publicB: PubKey): Uint8Array | string {
  const point = publicB instanceof Point ? publicB : Point.fromHex(publicB);
  const shared = point.multiply(normalizePrivateKey(privateA));
  const returnHex = typeof privateA === 'string';
  return returnHex ? shared.toHex() : shared.toRawBytes();
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
  const res = new SignResult(r, adjustedS).toHex();
  const hashed = msgHash instanceof Uint8Array ? hexToArray(res) : res;
  return recovered ? [hashed, recovery] : hashed;
}

export function verify(signature: Signature, msgHash: Hex, publicKey: PubKey): boolean {
  const msg = truncateHash(msgHash);
  const sign = normalizeSignature(signature);
  const point = normalizePublicKey(publicKey);
  const w = modInverse(sign.s, PRIME_ORDER);
  const point1 = Point.BASE_POINT.multiply(mod(msg * w, PRIME_ORDER));
  const point2 = point.multiply(mod(sign.r * w, PRIME_ORDER));
  const point3 = point1.add(point2);
  return point3.x === sign.r;
}

// Enable precomputes. Slows down first publicKey computation by 80ms.
Point.BASE_POINT.WINDOW_SIZE = 4;

export const utils = {
  isValidPrivateKey(privateKey: PrivKey) {
    return isValidPrivateKey(normalizePrivateKey(privateKey));
  },

  precompute(windowSize = 4, point = Point.BASE_POINT): true {
    point.WINDOW_SIZE = windowSize;
    point.multiply(1n);
    return true;
  }
};
