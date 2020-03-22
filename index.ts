/*! noble-secp256k1 - MIT License (c) Paul Miller (paulmillr.com) */
// https://www.secg.org/sec2-v2.pdf
const A = 0n;
const B = 7n;
// 𝔽p
export const P = 2n ** 256n - 2n ** 32n - 977n;
// Subgroup order, cofactor is 1
export const PRIME_ORDER = 2n ** 256n - 432420386565659656852420866394968145599n;
const PRIME_SIZE = 256;
const HIGH_NUMBER = PRIME_ORDER >> 1n;
const SUBPN = P - PRIME_ORDER;

type PrivKey = Uint8Array | string | bigint | number;
type PubKey = Uint8Array | string | Point;
type Hex = Uint8Array | string;
type Signature = Uint8Array | string | SignResult;

export class Point {
  constructor(public x: bigint, public y: bigint) {}

  private static fromCompressedHex(bytes: Uint8Array) {
    if (bytes.length !== 33) {
      throw new TypeError(`Point.fromHex: compressed expects 66 bytes, not ${bytes.length * 2}`);
    }
    const x = arrayToNumber(bytes.slice(1));
    const sqrY = mod(x ** 3n + A * x + B, P);
    let y = powMod(sqrY, (P + 1n) / 4n, P);
    const isFirstByteOdd = (bytes[0] & 1) === 1;
    const isYOdd = (y & 1n) === 1n;
    if (isFirstByteOdd !== isYOdd) {
      y = mod(-y, P);
    }
    if (!Point.isValidPoint(x, y)) {
      throw new TypeError('Point.fromHex: Point is not on elliptic curve');
    }
    return new Point(x, y);
  }

  static isValidPoint(x: bigint, y: bigint) {
    if (x === 0n || y === 0n || x >= P || y >= P) return false;

    const sqrY = y * y;
    const yEquivalence = x ** 3n + A * x + B;
    const actualSqrY1 = mod(sqrY, P);
    const actualSqrY2 = mod(-sqrY, P);
    const expectedSqrY1 = mod(yEquivalence, P);
    const expectedSqrY2 = mod(-yEquivalence, P);
    return (
      actualSqrY1 === expectedSqrY1 ||
      actualSqrY1 === expectedSqrY2 ||
      actualSqrY2 === expectedSqrY1 ||
      actualSqrY2 === expectedSqrY2
    );
  }

  private static fromUncompressedHex(bytes: Uint8Array) {
    if (bytes.length !== 65) {
      throw new TypeError(`Point.fromHex: uncompressed expects 130 bytes, not ${bytes.length * 2}`);
    }
    const x = arrayToNumber(bytes.slice(1, 33));
    const y = arrayToNumber(bytes.slice(33));
    if (!this.isValidPoint(x, y)) {
      throw new TypeError('Point.fromHex: Point is not on elliptic curve');
    }
    return new Point(x, y);
  }

  static fromHex(hash: Hex) {
    const bytes = hash instanceof Uint8Array ? hash : hexToArray(hash);
    const header = bytes[0];
    if (header === 0x02 || header === 0x03) return this.fromCompressedHex(bytes);
    if (header === 0x04) return this.fromUncompressedHex(bytes);
    throw new TypeError('Point.fromHex: received invalid point');
  }

  static fromPrivateKey(privateKey: PrivKey) {
    return BASE_POINT.multiply(normalizePrivateKey(privateKey));
  }

  static fromSignature(hash: Hex, signature: Signature, recovery: number): Point | undefined {
    recovery = Number(recovery);
    const sign = normalizeSignature(signature);
    const message = truncateHash(typeof hash === 'string' ? hexToArray(hash) : hash);
    if (sign.r === 0n || sign.s === 0n) {
      return;
    }
    let publicKeyX = sign.r;
    if (recovery >> 1) {
      if (publicKeyX >= SUBPN) {
        return;
      }
      publicKeyX = sign.r + PRIME_ORDER;
    }

    const compresedHex = `0${2 + (recovery & 1)}${pad64(publicKeyX)}`;
    // const compresedHex = `$0{2n + (recovery & 1n)}${publicKeyX.toString(16)}`;
    const publicKey = Point.fromHex(compresedHex);
    const rInv = modInverse(sign.r, PRIME_ORDER);
    const s1 = mod((PRIME_ORDER - message) * rInv, P);
    const s2 = mod(sign.s * rInv, P);
    const point1 = BASE_POINT.multiply(s1);
    const point2 = publicKey.multiply(s2);
    return point1.add(point2);
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

  add(other: Point): Point {
    if (!(other instanceof Point)) {
      throw new TypeError('Point#add: expected Point');
    }
    const a = this;
    const b = other;
    if (a.x === 0n && a.y === 0n) {
      return b;
    }
    if (b.x === 0n && b.y === 0n) {
      return a;
    }
    if (a.x === b.y && a.y === -b.y) {
      return new Point(0n, 0n);
    }
    if (a.x === b.x) {
      if (a.y === b.y) {
        return this.double();
      } else {
        // Point at undefined.
        throw new TypeError('Point#add: cannot add points (a.x == b.x, a.y != b.y)');
      }
    }
    const lamAdd = mod((b.y - a.y) * modInverse(b.x - a.x, P), P);
    const x = mod(lamAdd * lamAdd - a.x - b.x, P);
    const y = mod(lamAdd * (a.x - x) - a.y, P);
    return new Point(x, y);
  }

  private double(): Point {
    const a = this;
    const lam = mod(3n * a.x * a.x * modInverse(2n * a.y, P), P);
    const x = mod(lam * lam - 2n * a.x, P);
    const y = mod(lam * (a.x - x) - a.y, P);
    return new Point(x, y);
  }

  // Constant time multiplication.
  // Since koblitz curves do not support Montgomery ladder,
  // we emulate constant-time by multiplying to every power of 2.
  multiply(scalar: number | bigint): Point {
    if (typeof scalar !== 'number' && typeof scalar !== 'bigint') {
      throw new TypeError('Point#multiply: expected number or bigint');
    }
    let n = BigInt(scalar);
    if (!isValidPrivateKey(n)) {
      throw new Error('Private key is invalid. Expected 0 < key < PRIME_ORDER');
    }

    let Q = new Point(0n, 0n);
    // Fake point.
    let F = new Point(this.x, this.y);

    let P: Point = this;
    for (let bit = 0; bit <= 256; bit++) {
      let added = false;

      if (n > 0) {
        if ((n & 1n) === 1n) {
          Q = Q.add(P);
          added = true;
        }
        n >>= 1n;
      }

      if (!added) {
        F = F.add(P);
      }

      P = P.double();
    }
    return Q;
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

// https://www.secg.org/sec2-v2.pdf
export const BASE_POINT = new Point(
  55066263022277343669578718895168534326250603453777594175500187360389116729240n,
  32670510020758816978083085130507043184471273380659243275938904335757337482424n
);

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

function mod(a: bigint, b: bigint): bigint {
  const result = a % b;
  return result >= 0 ? result : b + result;
}

function modInverse(v: bigint, n: bigint): bigint {
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
async function getQRSrfc6979(hash: Hex, privateKey: bigint) {
  // Step A is ignored, since we already provide hash instead of msg
  const num = typeof hash === 'string' ? hexToNumber(hash) : arrayToNumber(hash);
  const h1 = hexToArray(pad64(num));
  const x = hexToArray(pad64(privateKey));
  const h1n = arrayToNumber(h1);

  // Step B
  let v = new Uint8Array(32).fill(1);
  // Step C
  let k = new Uint8Array(32).fill(0);

  const b0 = Uint8Array.from([0x00]);
  const b1 = Uint8Array.from([0x01]);
  // const x = privateKey;

  // console.log('start', arrayToHex(h1), arrayToHex(x));
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

export function recoverPublicKey(
  hash: Hex,
  signature: Signature,
  recovery: number
): Uint8Array | undefined {
  const point = Point.fromSignature(hash, signature, recovery);
  return point && point.toRawBytes();
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

export function getSharedSecret(privateA: PrivKey, publicB: PubKey): Uint8Array {
  const point = publicB instanceof Point ? publicB : Point.fromHex(publicB);
  return point.multiply(normalizePrivateKey(privateA)).toRawBytes();
}

type OptsRecovered = { recovered: true; canonical?: true };
type OptsNoRecovered = { recovered?: false; canonical?: true };
type Opts = { recovered?: boolean; canonical?: true };

export async function sign(hash: string, privateKey: PrivKey, opts: OptsRecovered): Promise<[string, number]>;
export async function sign(hash: Uint8Array, privateKey: PrivKey, opts: OptsRecovered): Promise<[Uint8Array, number]>;
export async function sign(hash: Uint8Array, privateKey: PrivKey, opts?: OptsNoRecovered): Promise<Uint8Array>;
export async function sign(hash: string, privateKey: PrivKey, opts?: OptsNoRecovered): Promise<string>;
export async function sign(hash: string, privateKey: PrivKey, opts?: OptsNoRecovered): Promise<string>;
export async function sign(
  hash: Hex,
  privateKey: PrivKey,
  { recovered, canonical }: Opts = {}
): Promise<Hex | [Hex, number]> {
  const priv = normalizePrivateKey(privateKey);
  if (!isValidPrivateKey(priv)) {
    throw new Error('Private key is invalid. Expected 0 < key < PRIME_ORDER');
  }
  // We are using deterministic signature scheme
  // instead of letting user specify random `k`.
  const [q, r, s] = await getQRSrfc6979(hash, priv);

  let recovery = (q.x === r ? 0 : 2) | Number(q.y & 1n);
  let adjustedS = s;
  if (s > HIGH_NUMBER && canonical) {
    adjustedS = PRIME_ORDER - s;
    recovery ^= 1;
  }
  const res = new SignResult(r, adjustedS).toHex();
  const hashed = hash instanceof Uint8Array ? hexToArray(res) : res;
  return recovered ? [hashed, recovery] : hashed;
}

export function verify(signature: Signature, hash: Hex, publicKey: PubKey): boolean {
  const msg = truncateHash(hash);
  const sign = normalizeSignature(signature);
  const point = normalizePublicKey(publicKey);
  const w = modInverse(sign.s, PRIME_ORDER);
  const point1 = BASE_POINT.multiply(mod(msg * w, PRIME_ORDER));
  const point2 = point.multiply(mod(sign.r * w, PRIME_ORDER));
  const point3 = point1.add(point2);
  return point3.x === sign.r;
}

export const utils = {
  isValidPrivateKey(privateKey: PrivKey) {
    return isValidPrivateKey(normalizePrivateKey(privateKey));
  }
};
