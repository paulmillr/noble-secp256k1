/*! noble-secp256k1 - MIT License (c) Paul Miller (paulmillr.com) */
// https://www.secg.org/sec2-v2.pdf
const A = 0n;
const B = 7n;
// 𝔽p
export const P = 2n ** 256n - 2n ** 32n - 977n;
// Subgroup order, cofactor is 1
export const PRIME_ORDER =
  2n ** 256n - 432420386565659656852420866394968145599n;
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
      throw new Error(`Point.fromCompressedHex expects 66 bytes, not ${bytes.length * 2}`);
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
      throw new Error("secp256k1: Point is not on elliptic curve");
    }
    return new Point(x, y);
  }

  static isValidPoint(x: bigint, y: bigint) {
    if (x === 0n || y === 0n || x >= P || y >= P) return false;

    console.log('isValidPoint', x, y);
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
      throw new Error(`Point.fromUncompressedHex expects 130 bytes, not ${bytes.length * 2}`);
    }
    const x = arrayToNumber(bytes.slice(1, 33));
    const y = arrayToNumber(bytes.slice(33));
    if (!this.isValidPoint(x, y)) {
      throw new Error("secp256k1: Point is not on elliptic curve");
    }
    return new Point(x, y);
  }

  static fromHex(hash: Hex) {
    const bytes = hash instanceof Uint8Array ? hash : hexToArray(hash);
    const header = bytes[0]
    if (header === 0x04) return this.fromUncompressedHex(bytes);
    if (header === 0x02 || header === 0x03) return this.fromCompressedHex(bytes);
    throw new TypeError('Point.fromHex: received invalid point');
  }

  static fromPrivateKey(privateKey: PrivKey) {
    return BASE_POINT.multiply(normalizePrivateKey(privateKey));
  }

  static fromSignature(
    hash: Hex,
    signature: Signature,
    recovery: number | bigint
  ): Point | undefined {
    recovery = BigInt(recovery);
    const sign = normalizeSignature(signature);
    const message = truncateHash(
      typeof hash === "string" ? hexToArray(hash) : hash
    );
    if (sign.r === 0n || sign.s === 0n) {
      return;
    }
    let publicKeyX = sign.r;
    if (recovery >> 1n) {
      if (publicKeyX >= SUBPN) {
        return;
      }
      publicKeyX = sign.r + PRIME_ORDER;
    }

    const compresedHex = `$0{2n + (recovery & 1n)}${publicKeyX.toString(16)}`;
    const publicKey = Point.fromHex(compresedHex);
    const rInv = modInverse(sign.r, PRIME_ORDER);
    const s1 = mod((PRIME_ORDER - message) * rInv, P);
    const s2 = mod(sign.s * rInv, P);
    const point1 = BASE_POINT.multiply(s1);
    const point2 = publicKey.multiply(s2);
    return point1.add(point2);
  }

  private uncompressedHex() {
    const yHex = this.y.toString(16).padStart(64, "0");
    const xHex = this.x.toString(16).padStart(64, "0");
    return `04${xHex}${yHex}`;
  }

  private compressedHex() {
    let hex = this.x.toString(16).padStart(64, "0");
    const head = this.y & 1n ? "03" : "02";
    return `${head}${hex}`;
  }

  toRawBytes(isCompressed = false) {
    const hex = this.toHex(isCompressed);
    return hexToArray(hex);
  }

  toHex(isCompressed = false) {
    return isCompressed ? this.compressedHex() : this.uncompressedHex();
  }

  add(other: Point): Point {
    const a = this;
    const b = other;
    if (a.x === 0n && a.y === 0n) {
      return b;
    }
    if (b.x === 0n && b.y === 0n) {
      return a;
    }
    if (a.x === b.y && a.y == -b.y) {
      return new Point(0n, 0n);
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
  multiply(scalar: number | bigint | Uint8Array): Point {
    let n = scalar instanceof Uint8Array ?
      arrayToNumber(scalar) : BigInt(scalar);
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


export class SignResult {
  constructor(public r: bigint, public s: bigint) {}

  static fromHex(hex: Hex) {
    const hash = hex instanceof Uint8Array ? arrayToHex(hex) : hex;
    const rLength = parseInt(`${hash[6]}${hash[7]}`, 16) * 2;
    const r = BigInt(`0x${hash.substr(8, rLength)}`);
    const s = BigInt(`0x${hash.slice(12 + rLength)}`);
    return new SignResult(r, s);
  }

  private formatLength(hex: string) {
    return (hex.length / 2).toString(16).padStart(2, "0");
  }

  private formatNumberToHex(num: bigint | number) {
    const res = num.toString(16);
    return res.length & 1 ? `0${res}` : res;
  }

  // DER encoded ECDSA signature
  // https://bitcoin.stackexchange.com/questions/57644/what-are-the-parts-of-a-bitcoin-transaction-input-script
  toHex() {
    const rHex = `00${this.formatNumberToHex(this.r)}`;
    const sHex = this.formatNumberToHex(this.s);
    const rLen = this.formatLength(rHex);
    const sLen = this.formatLength(sHex);
    const length = this.formatNumberToHex(
      rHex.length / 2 + sHex.length / 2 + 4
    );
    return `30${length}02${rLen}${rHex}02${sLen}${sHex}`;
  }
}

// https://www.secg.org/sec2-v2.pdf
export const BASE_POINT = new Point(
  55066263022277343669578718895168534326250603453777594175500187360389116729240n,
  32670510020758816978083085130507043184471273380659243275938904335757337482424n
);

let secureRandom = (bytesLength: number) => new Uint8Array(bytesLength);

if (typeof window == "object" && "crypto" in window) {
  secureRandom = (bytesLength: number): Uint8Array => {
    const array = new Uint8Array(bytesLength);
    window.crypto.getRandomValues(array);
    return array;
  };
} else if (typeof process === "object" && "node" in process.versions) {
  const req = require;
  const { randomBytes } = req("crypto");
  secureRandom = (bytesLength: number): Uint8Array => {
    const b: Buffer = randomBytes(bytesLength);
    return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
  };
} else {
  throw new Error(
    "The environment doesn't have cryptographically secure random function"
  );
}

// HMAC-SHA256 implementation.
let hmac: (key: Uint8Array, message: Uint8Array) => Promise<Uint8Array>;

if (typeof window == "object" && "crypto" in window) {
  hmac = async (key: Uint8Array, message: Uint8Array) => {
    const ckey = await window.crypto.subtle.importKey(
      "raw", key,
      {name: "HMAC", hash: {name: "SHA-256"}},
      false, ["sign", "verify"]
    );
    const buffer = await window.crypto.subtle.sign("HMAC", ckey, message);
    return new Uint8Array(buffer);
  };
} else if (typeof process === "object" && "node" in process.versions) {
  const req = require;
  const { createHmac } = req("crypto");
  hmac = async (key: Uint8Array, message: Uint8Array) => {
    const hash = createHmac("sha256", key);
    hash.update(message);
    return Uint8Array.from(hash.digest());
  };
} else {
  throw new Error("The environment doesn't have hmac-sha256 function");
}

function getRandomValue(bytesLength: number): bigint {
  return arrayLEToNumber(secureRandom(bytesLength));
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

function arrayToHex(uint8a: Uint8Array): string {
  return Array.from(uint8a)
    .map(c => c.toString(16).padStart(2, "0"))
    .join("");
}

function hexToArray(hash: string): Uint8Array {
  hash = hash.length & 1 ? `0${hash}` : hash;
  const len = hash.length;
  const result = new Uint8Array(len / 2);
  for (let i = 0, j = 0; i < len - 1; i += 2, j++) {
    result[j] = parseInt(hash[i] + hash[i + 1], 16);
  }
  return result;
}

function hexToNumber(hex: string) {
  return BigInt(`0x${hex}`);
}

function numberToArray(number: bigint, length: number = 64) {
  return hexToArray(number.toString(16).padStart(length, '0'));
}

function arrayToNumber(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1, j = 0; i >= 0; i--, j++) {
    value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(j));
  }
  return value;
}

function arrayLEToNumber(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = 0; i < bytes.length; i++) {
    value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(i));
  }
  return value;
}

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
  hash = typeof hash === "string" ? hash : arrayToHex(hash);
  let msg = BigInt(`0x${hash || "0"}`);
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
  // console.log('concat', result.length);
  for (let i = 0, pad = 0; i < args.length; i++) {
    const arr = args[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
}

// Deterministic k generation as per RFC6979.
// https://tools.ietf.org/html/rfc6979#section-3.1
async function deterministicK(hash: Uint8Array, privateKey: Uint8Array) {
  const concat = concatTypedArrays;
  // Step A is ignored, since we already provide hash instead of msg
  const h1 = numberToArray(mod(arrayToNumber(hash), PRIME_ORDER));
  const h1n = arrayToNumber(h1);
  const pn = arrayToNumber(privateKey);

  // Step B
  let v = new Uint8Array(32).fill(1);
  // Step C
  let k = new Uint8Array(32).fill(0);

  const b0 = Uint8Array.from([0x00]);
  const b1 = Uint8Array.from([0x01]);
  const x = privateKey;

  // console.log('start', arrayToHex(h1), arrayToHex(x));

  // Step D
  k = await hmac(k, concat(v, b0, x, h1));
  // console.log('d', arrayToHex(k));
  // Step E
  v = await hmac(k, v);
  // console.log('e', arrayToHex(v));
  // Step F
  k = await hmac(k, concat(v, b1, x, h1));
  // console.log('f', arrayToHex(k));
  // Step G
  v = await hmac(k, v);
  // console.log('g', arrayToHex(v));

  // Step H3, repeat until 1 < T < n - 1
  for (let i = 0; i < 10000; i++) {
    v = await hmac(k, v);
    const T = arrayToNumber(v);
    // console.log('try #', i, arrayToHex(numberToArray(T)));
    if (isValidPrivateKey(T) && isValidK(T, h1n, pn)) return T;
    k = await hmac(k, concat(v, b0));
    v = await hmac(k, v);
  }

  throw new TypeError('Too many k');
  // return T;
}

function isValidPrivateKey(privateKey: bigint): boolean {
  if (typeof privateKey !== 'bigint') {
    throw new TypeError('isValidPrivateKey expects bigint');
  }
  return 0 < privateKey && privateKey < PRIME_ORDER;
}

function isValidK(k: bigint, msg: bigint, priv: bigint) {
  const q = BASE_POINT.multiply(k);
  const r = mod(q.x, PRIME_ORDER);
  // console.log('isValidK', 1, r === 0n, k > r);
  if (r === 0n || k > r) return false;
  let s = mod(modInverse(k, PRIME_ORDER) * (msg + r * priv), PRIME_ORDER);
  // console.log('isValidK', 2, s === 0n);
  if (s === 0n) return false;
  return true;
}

function normalizePrivateKey(privateKey: PrivKey): bigint {
  let key: bigint;
  if (privateKey instanceof Uint8Array) {
    key = arrayToNumber(privateKey);
  } else if (typeof privateKey === "string") {
    key = hexToNumber(privateKey);
  } else {
    key = BigInt(privateKey)
  }
  if (!isValidPrivateKey(key)) {
    throw new Error("Private key is invalid. It should be less than PRIME_ORDER");
  };
  return key;
}

function normalizePublicKey(publicKey: PubKey): Point {
  return publicKey instanceof Point ? publicKey : Point.fromHex(publicKey);
}

function normalizeSignature(signature: Signature): SignResult {
  return signature instanceof SignResult
    ? signature
    : SignResult.fromHex(signature);
}

export function recoverPublicKey(
  hash: Hex, signature: Signature, recovery: number | bigint
): Uint8Array | undefined {
  const point = Point.fromSignature(hash, signature, recovery);
  return point && point.toRawBytes();
}

export function getPublicKey(privateKey: Uint8Array | bigint | number, isCompressed?: boolean): Uint8Array;
export function getPublicKey(privateKey: string, isCompressed?: boolean): string;
export function getPublicKey(privateKey: PrivKey, isCompressed?: boolean): PubKey {
  const point = Point.fromPrivateKey(privateKey);
  if (typeof privateKey === "string") {
    return point.toHex(isCompressed);
  }
  return point.toRawBytes(isCompressed);
}

export function getSharedSecret(privateA: PrivKey, publicB: PubKey): Uint8Array {
  const point = publicB instanceof Point ? publicB : Point.fromHex(publicB);
  return point.multiply(normalizePrivateKey(privateA)).toRawBytes();
}

type Options = {
  recovered: true;
  canonical?: true;
  k?: number | bigint;
};

type OptionsWithK = Partial<Options>;

// export function sign(hash: string, privateKey: PrivKey, opts: Options): [string, bigint];
// export function sign(hash: Uint8Array, privateKey: PrivKey, opts: Options): [Uint8Array, bigint];
// export function sign(hash: Uint8Array, privateKey: PrivKey, opts?: OptionsWithK): Uint8Array;
// export function sign(hash: string, privateKey: PrivKey, opts?: OptionsWithK): string;
// export function sign(hash: string, privateKey: PrivKey, opts?: OptionsWithK): string;
export async function sign(
  hash: Hex,
  privateKey: PrivKey,
  { k = undefined, recovered, canonical }: OptionsWithK = {}
): Promise<Hex | [Hex, bigint]> {
  const priv = normalizePrivateKey(privateKey);
  // k = BigInt(k);
  const arr = typeof hash === 'string' ? hexToArray(hash) : hash;
  k = await deterministicK(arr, numberToArray(priv));
  const q = BASE_POINT.multiply(k);
  const r = mod(q.x, PRIME_ORDER);

  const msg = truncateHash(hash);
  let s = mod(modInverse(k, PRIME_ORDER) * (msg + r * priv), PRIME_ORDER);
  let recovery = (q.x === r ? 0n : 2n) | (q.y & 1n);
  if (s > HIGH_NUMBER && canonical) {
    s = PRIME_ORDER - s;
    recovery ^= 1n;
  }
  const res = new SignResult(r, s).toHex();
  const hashed = hash instanceof Uint8Array ? hexToArray(res) : res;
  return recovered ? [hashed, recovery] : hashed;
}

export function verify(signature: Signature, hash: Hex, publicKey: PubKey): boolean {
  const msg = truncateHash(hash);
  const point = normalizePublicKey(publicKey);
  const sign = normalizeSignature(signature);
  const w = modInverse(sign.s, PRIME_ORDER);
  const point1 = BASE_POINT.multiply(mod(msg * w, PRIME_ORDER));
  const point2 = point.multiply(mod(sign.r * w, PRIME_ORDER));
  const { x } = point1.add(point2);
  return x === sign.r;
}
