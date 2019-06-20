"use strict";
/*! noble-secp256k1 - MIT License (c) Paul Miller (paulmillr.com) */
Object.defineProperty(exports, "__esModule", { value: true });
const A = 0n;
const B = 7n;
const ENCODING_LENGTH = 32;
exports.P = 2n ** 256n - 2n ** 32n - 977n;
exports.PRIME_ORDER = 2n ** 256n - 432420386565659656852420866394968145599n;
class Point {
    constructor(x, y) {
        this.x = x;
        this.y = y;
    }
    static fromCompressedHex(bytes) {
        const x = numberFromByteArray(bytes.slice(1));
        const sqrY = mod(x ** 3n + A * x + B, exports.P);
        let y = powMod(sqrY, (exports.P + 1n) / 4n, exports.P);
        const isFirstByteOdd = (bytes[0] & 1) === 1;
        const isYOdd = (y & 1n) === 1n;
        if (isFirstByteOdd !== isYOdd) {
            y = mod(-y, exports.P);
        }
        return new Point(x, y);
    }
    static fromUncompressedHex(bytes) {
        const x = numberFromByteArray(bytes.slice(1, 64));
        const y = numberFromByteArray(bytes.slice(64));
        return new Point(x, y);
    }
    static fromHex(hash) {
        const bytes = hash instanceof Uint8Array ? hash : hexToArray(hash);
        return bytes[0] === 0x4
            ? this.fromUncompressedHex(bytes)
            : this.fromCompressedHex(bytes);
    }
    uncompressedHex() {
        const yHex = this.y.toString(16).padStart(64, "0");
        const xHex = this.x.toString(16).padStart(64, "0");
        return `04${xHex}${yHex}`;
    }
    compressedHex() {
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
exports.Point = Point;
class SignResult {
    constructor(r, s) {
        this.r = r;
        this.s = s;
    }
    static fromHex(hex) {
        const hash = hex instanceof Uint8Array ? arrayToHex(hex) : hex;
        const rLength = parseInt(`${hash[6]}${hash[7]}`, 16);
        const r = BigInt(`0x${hash.substr(8, rLength)}`);
        const s = BigInt(`0x${hash.slice(12 + rLength)}`);
        return new SignResult(r, s);
    }
    toHex() {
        const rHex = this.r.toString(16);
        const sHex = this.s.toString(16);
        const len = (rHex.length + sHex.length + 6).toString(16).padStart(2, "0");
        const rLen = rHex.length.toString(16).padStart(2, "0");
        const sLen = sHex.length.toString(16).padStart(2, "0");
        return `30${len}02${rLen}${rHex}02${sLen}${sHex}`;
    }
}
exports.SignResult = SignResult;
exports.BASE_POINT = new Point(55066263022277343669578718895168534326250603453777594175500187360389116729240n, 32670510020758816978083085130507043184471273380659243275938904335757337482424n);
const N_BIT_LENGTH = 256n;
let cryptoRandom = (n) => new Uint8Array(0);
if (typeof window == "object" && "crypto" in window) {
    cryptoRandom = (bytesLength) => {
        const array = new Uint8Array(bytesLength);
        window.crypto.getRandomValues(array);
        return array;
    };
}
else if (typeof process === "object" && "node" in process.versions) {
    const { randomBytes } = require("crypto");
    cryptoRandom = (bytesLength) => {
        const b = randomBytes(bytesLength);
        return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
    };
}
else {
    throw new Error("The environment doesn't have cryptographically secure random function");
}
function getRandomValue(bytesLength) {
    return numberFromByteArrayLE(cryptoRandom(bytesLength));
}
function powMod(x, power, order) {
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
function arrayToHex(uint8a) {
    return Array.from(uint8a)
        .map(c => c.toString(16).padStart(2, "0"))
        .join("");
}
function hexToArray(hash) {
    hash = hash.length & 1 ? `0${hash}` : hash;
    const len = hash.length;
    const result = new Uint8Array(len / 2);
    for (let i = 0, j = 0; i < len - 1; i += 2, j++) {
        result[j] = parseInt(hash[i] + hash[i + 1], 16);
    }
    return result;
}
function hexToNumber(hex) {
    return BigInt(`0x${hex}`);
}
function numberFromByteArray(bytes) {
    let value = 0n;
    for (let i = bytes.length - 1, j = 0; i >= 0; i--, j++) {
        value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(j));
    }
    return value;
}
function numberFromByteArrayLE(bytes) {
    let value = 0n;
    for (let i = 0; i < bytes.length; i++) {
        value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(i));
    }
    return value;
}
function bitLength(n) {
    let i = 0n;
    while (n) {
        n >>= 1n;
        i++;
    }
    return i;
}
function mod(a, b) {
    const result = a % b;
    return result >= 0 ? result : b + result;
}
function modInverse(v, n) {
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
function add(a, b) {
    if (a.x === 0n && a.y === 0n) {
        return b;
    }
    if (b.x === 0n && b.y === 0n) {
        return a;
    }
    const lamAdd = mod((b.y - a.y) * modInverse(b.x - a.x, exports.P), exports.P);
    const x = mod(lamAdd * lamAdd - a.x - b.x, exports.P);
    const y = mod(lamAdd * (a.x - x) - a.y, exports.P);
    return new Point(x, y);
}
function double(a) {
    const lam = mod(3n * a.x * a.x * modInverse(2n * a.y, exports.P), exports.P);
    const x = mod(lam * lam - 2n * a.x, exports.P);
    const y = mod(lam * (a.x - x) - a.y, exports.P);
    return new Point(x, y);
}
function multiple(g, n) {
    let q = new Point(0n, 0n);
    for (let db = g; n > 0n; n >>= 1n, db = double(db)) {
        if ((n & 1n) === 1n) {
            q = add(q, db);
        }
    }
    return q;
}
function truncateHash(hash) {
    const e = numberFromByteArrayLE(hash);
    const delta = bitLength(e) - N_BIT_LENGTH;
    return delta > 0 ? e >> delta : e;
}
function isValidPrivateKey(privateKey) {
    if (privateKey instanceof Uint8Array) {
        return privateKey.length <= 32;
    }
    if (typeof privateKey === "string") {
        return /^[0-9a-f]{0,64}$/i.test(privateKey);
    }
    return privateKey.toString(16).length <= 64;
}
function normalizePrivateKey(privateKey) {
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
function normalizePublicKey(publicKey) {
    return publicKey instanceof Point ? publicKey : Point.fromHex(publicKey);
}
function normalizePoint(point, privateKey, isCompressed = false) {
    if (privateKey instanceof Uint8Array) {
        return point.toRawBytes(isCompressed);
    }
    if (typeof privateKey === "string") {
        return point.toHex(isCompressed);
    }
    return point;
}
function normalizeSignature(signature) {
    return signature instanceof SignResult
        ? signature
        : SignResult.fromHex(signature);
}
function getPublicKey(privateKey, isCompressed) {
    const number = normalizePrivateKey(privateKey);
    const point = multiple(exports.BASE_POINT, number);
    return normalizePoint(point, privateKey, isCompressed);
}
exports.getPublicKey = getPublicKey;
function sign(hash, privateKey, k = getRandomValue(5)) {
    const number = normalizePrivateKey(privateKey);
    k = BigInt(k);
    const message = truncateHash(typeof hash === "string" ? hexToArray(hash) : hash);
    const q = multiple(exports.BASE_POINT, k);
    const r = mod(q.x, exports.PRIME_ORDER);
    const s = mod(modInverse(k, exports.PRIME_ORDER) * (message + r * number), exports.PRIME_ORDER);
    const res = new SignResult(r, s).toHex();
    return hash instanceof Uint8Array ? hexToArray(res) : res;
}
exports.sign = sign;
function verify(signature, hash, publicKey) {
    const message = truncateHash(typeof hash === "string" ? hexToArray(hash) : hash);
    const point = normalizePublicKey(publicKey);
    const sign = normalizeSignature(signature);
    const w = modInverse(sign.s, exports.PRIME_ORDER);
    const point1 = multiple(exports.BASE_POINT, mod(message * w, exports.PRIME_ORDER));
    const point2 = multiple(point, mod(sign.r * w, exports.PRIME_ORDER));
    const { x } = add(point1, point2);
    return x === sign.r;
}
exports.verify = verify;
