/*! noble-secp256k1 - MIT License (c) Paul Miller (paulmillr.com) */
// https://en.bitcoin.it/wiki/Secp256k1
// https://bitcoin.stackexchange.com/questions/21907/what-does-the-curve-used-in-bitcoin-secp256k1-look-like
const A = 0n;
const B = 7n;
const ENCODING_LENGTH = 32;
// p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
export const P = 2n ** 256n - 2n ** 32n - 977n;
export const PRIME_ORDER =
  2n ** 256n - 432420386565659656852420866394968145599n;

type PrivKey = Uint8Array | string | bigint | number;
type PubKey = Uint8Array | string | Point;
type Hex = Uint8Array | string;
type Signature = Uint8Array | string | SignResult;

export class Point {
  constructor(public x: bigint, public y: bigint) {}

  private static fromCompressedHex(bytes: Uint8Array) {
    const x = numberFromByteArray(bytes.slice(1));
    const sqrY = mod(x ** 3n + A * x + B, P);
    let y = powMod(sqrY, (P + 1n) / 4n, P);
    const isFirstByteOdd = (bytes[0] & 1) === 1;
    const isYOdd = (y & 1n) === 1n;
    if (isFirstByteOdd !== isYOdd) {
      y = mod(-y, P);
    }
    return new Point(x, y);
  }

  private static fromUncompressedHex(bytes: Uint8Array) {
    const x = numberFromByteArray(bytes.slice(1, 64));
    const y = numberFromByteArray(bytes.slice(64));
    return new Point(x, y);
  }

  static fromHex(hash: Hex) {
    const bytes = hash instanceof Uint8Array ? hash : hexToArray(hash);
    return bytes[0] === 0x4
      ? this.fromUncompressedHex(bytes)
      : this.fromCompressedHex(bytes);
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
}

export class SignResult {
  constructor(public r: bigint, public s: bigint) {}

  static fromHex(hex: Hex) {
    const hash = hex instanceof Uint8Array ? arrayToHex(hex) : hex;
    const rLength = parseInt(`${hash[6]}${hash[7]}`, 16);
    const r = BigInt(`0x${hash.substr(8, rLength)}`);
    const s = BigInt(`0x${hash.slice(12 + rLength)}`);
    return new SignResult(r, s);
  }

  // DER encoded ECDSA signature
  // https://bitcoin.stackexchange.com/questions/57644/what-are-the-parts-of-a-bitcoin-transaction-input-script
  toHex() {
    const rHex = this.r.toString(16);
    const sHex = this.s.toString(16);
    const len = (rHex.length + sHex.length + 6).toString(16).padStart(2, "0");
    const rLen = rHex.length.toString(16).padStart(2, "0");
    const sLen = sHex.length.toString(16).padStart(2, "0");
    return `30${len}02${rLen}${rHex}02${sLen}${sHex}`;
  }
}

// https://www.secg.org/sec2-v2.pdf
export const BASE_POINT = new Point(
  55066263022277343669578718895168534326250603453777594175500187360389116729240n,
  32670510020758816978083085130507043184471273380659243275938904335757337482424n
);

const N_BIT_LENGTH = 256n;

let cryptoRandom = (n: number) => new Uint8Array(0);

if (typeof window == "object" && "crypto" in window) {
  cryptoRandom = (bytesLength: number): Uint8Array => {
    const array = new Uint8Array(bytesLength);
    window.crypto.getRandomValues(array);
    return array;
  };
} else if (typeof process === "object" && "node" in process.versions) {
  const { randomBytes } = require("crypto");
  cryptoRandom = (bytesLength: number): Uint8Array => {
    const b = randomBytes(bytesLength);
    return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
  };
} else {
  throw new Error(
    "The environment doesn't have cryptographically secure random function"
  );
}

function getRandomValue(bytesLength: number): bigint {
  return numberFromByteArrayLE(cryptoRandom(bytesLength));
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

function numberFromByteArray(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1, j = 0; i >= 0; i--, j++) {
    value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(j));
  }
  return value;
}

function numberFromByteArrayLE(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = 0; i < bytes.length; i++) {
    value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(i));
  }
  return value;
}

function bitLength(n: bigint) {
  let i = 0n;
  while (n) {
    n >>= 1n;
    i++;
  }
  return i;
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

function add(a: Point, b: Point): Point {
  if (a.x === 0n && a.y === 0n) {
    return b;
  }
  if (b.x === 0n && b.y === 0n) {
    return a;
  }
  const lamAdd = mod((b.y - a.y) * modInverse(b.x - a.x, P), P);
  const x = mod(lamAdd * lamAdd - a.x - b.x, P);
  const y = mod(lamAdd * (a.x - x) - a.y, P);
  return new Point(x, y);
}

function double(a: Point): Point {
  const lam = mod(3n * a.x * a.x * modInverse(2n * a.y, P), P);
  const x = mod(lam * lam - 2n * a.x, P);
  const y = mod(lam * (a.x - x) - a.y, P);
  return new Point(x, y);
}

function multiple(g: Point, n: bigint): Point {
  let q = new Point(0n, 0n);
  for (let db = g; n > 0n; n >>= 1n, db = double(db)) {
    if ((n & 1n) === 1n) {
      q = add(q, db);
    }
  }
  return q;
}

function truncateHash(hash: Uint8Array): bigint {
  const e = numberFromByteArrayLE(hash);
  const delta = bitLength(e) - N_BIT_LENGTH;
  return delta > 0 ? e >> delta : e;
}

function isValidPrivateKey(privateKey: PrivKey) {
  if (privateKey instanceof Uint8Array) {
    return privateKey.length <= 32;
  }
  if (typeof privateKey === "string") {
    return /^[0-9a-f]{0,64}$/i.test(privateKey);
  }
  return privateKey.toString(16).length <= 64;
}

function normalizePrivateKey(privateKey: PrivKey): bigint {
  if (!isValidPrivateKey(privateKey)) {
    throw new Error("Private key is invalid. It should be less than 257 bit or contain valid hex string");
  }
  if (privateKey instanceof Uint8Array) {
    return numberFromByteArray(privateKey);
  }
  if (typeof privateKey === "string") {
    return hexToNumber(privateKey);
  }
  return BigInt(privateKey);
}

function normalizePublicKey(publicKey: PubKey): Point {
  return publicKey instanceof Point ? publicKey : Point.fromHex(publicKey);
}

function normalizePoint(
  point: Point,
  privateKey: PrivKey,
  isCompressed = false
): Uint8Array | string | Point {
  if (privateKey instanceof Uint8Array) {
    return point.toRawBytes(isCompressed);
  }
  if (typeof privateKey === "string") {
    return point.toHex(isCompressed);
  }
  return point;
}

function normalizeSignature(signature: Signature): SignResult {
  return signature instanceof SignResult
    ? signature
    : SignResult.fromHex(signature);
}

export function getPublicKey(privateKey: Uint8Array, isCompressed?: boolean): Uint8Array;
export function getPublicKey(privateKey: string, isCompressed?: boolean): string;
export function getPublicKey(privateKey: bigint | number, isCompressed?: boolean): Point;
export function getPublicKey(privateKey: PrivKey, isCompressed?: boolean): PubKey {
  const number = normalizePrivateKey(privateKey);
  const point = multiple(BASE_POINT, number);
  return normalizePoint(point, privateKey, isCompressed);
}

export function sign(hash: Uint8Array, privateKey: PrivKey, k?: bigint | number): Uint8Array;
export function sign(hash: string, privateKey: PrivKey, k?: bigint | number): string;
export function sign(hash: Hex, privateKey: PrivKey, k: bigint | number = getRandomValue(5)): Hex {
  const number = normalizePrivateKey(privateKey);
  k = BigInt(k);
  const message = truncateHash(
    typeof hash === "string" ? hexToArray(hash) : hash
  );
  const q = multiple(BASE_POINT, k);
  const r = mod(q.x, PRIME_ORDER);
  const s = mod(
    modInverse(k, PRIME_ORDER) * (message + r * number),
    PRIME_ORDER
  );
  const res = new SignResult(r, s).toHex();
  return hash instanceof Uint8Array ? hexToArray(res) : res;
}

export function verify(signature: Signature, hash: Hex, publicKey: PubKey): boolean {
  const message = truncateHash(
    typeof hash === "string" ? hexToArray(hash) : hash
  );
  const point = normalizePublicKey(publicKey);
  const sign = normalizeSignature(signature);
  const w = modInverse(sign.s, PRIME_ORDER);
  const point1 = multiple(BASE_POINT, mod(message * w, PRIME_ORDER));
  const point2 = multiple(point, mod(sign.r * w, PRIME_ORDER));
  const { x } = add(point1, point2);
  return x === sign.r;
}
