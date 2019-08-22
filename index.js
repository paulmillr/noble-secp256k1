"use strict";
/*! noble-secp256k1 - MIT License (c) Paul Miller (paulmillr.com) */
Object.defineProperty(exports, "__esModule", { value: true });
const A = 0n;
const B = 7n;
exports.P = 2n ** 256n - 2n ** 32n - 977n;
exports.PRIME_ORDER = 2n ** 256n - 432420386565659656852420866394968145599n;
const PRIME_SIZE = 256;
const HIGH_NUMBER = exports.PRIME_ORDER >> 1n;
const SUBPN = exports.P - exports.PRIME_ORDER;
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
    static isValidPoint(x, y) {
        const sqrY = y * y;
        const yEquivalence = x ** 3n + A * x + B;
        const actualSqrY1 = mod(sqrY, exports.P);
        const actualSqrY2 = mod(-sqrY, exports.P);
        const expectedSqrY1 = mod(yEquivalence, exports.P);
        const expectedSqrY2 = mod(-yEquivalence, exports.P);
        return (actualSqrY1 === expectedSqrY1 ||
            actualSqrY1 === expectedSqrY2 ||
            actualSqrY2 === expectedSqrY1 ||
            actualSqrY2 === expectedSqrY2);
    }
    static fromUncompressedHex(bytes) {
        const x = numberFromByteArray(bytes.slice(1, 33));
        const y = numberFromByteArray(bytes.slice(33));
        if (!this.isValidPoint(x, y)) {
            throw new Error("secp256k1: Point is not on elliptic curve");
        }
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
    add(other) {
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
        const lamAdd = mod((b.y - a.y) * modInverse(b.x - a.x, exports.P), exports.P);
        const x = mod(lamAdd * lamAdd - a.x - b.x, exports.P);
        const y = mod(lamAdd * (a.x - x) - a.y, exports.P);
        return new Point(x, y);
    }
    double() {
        const a = this;
        const lam = mod(3n * a.x * a.x * modInverse(2n * a.y, exports.P), exports.P);
        const x = mod(lam * lam - 2n * a.x, exports.P);
        const y = mod(lam * (a.x - x) - a.y, exports.P);
        return new Point(x, y);
    }
    multiply(scalar) {
        const g = this;
        let n = scalar;
        let q = new Point(0n, 0n);
        for (let db = g; n > 0n; n >>= 1n, db = db.double()) {
            if ((n & 1n) === 1n) {
                q = q.add(db);
            }
        }
        return q;
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
        const rLength = parseInt(`${hash[6]}${hash[7]}`, 16) * 2;
        const r = BigInt(`0x${hash.substr(8, rLength)}`);
        const s = BigInt(`0x${hash.slice(12 + rLength)}`);
        return new SignResult(r, s);
    }
    formatLength(hex) {
        return (hex.length / 2).toString(16).padStart(2, "0");
    }
    formatNumberToHex(num) {
        const res = num.toString(16);
        return res.length & 1 ? `0${res}` : res;
    }
    toHex() {
        const rHex = `00${this.formatNumberToHex(this.r)}`;
        const sHex = this.formatNumberToHex(this.s);
        const rLen = this.formatLength(rHex);
        const sLen = this.formatLength(sHex);
        const length = this.formatNumberToHex(rHex.length / 2 + sHex.length / 2 + 4);
        return `30${length}02${rLen}${rHex}02${sLen}${sHex}`;
    }
}
exports.SignResult = SignResult;
exports.BASE_POINT = new Point(55066263022277343669578718895168534326250603453777594175500187360389116729240n, 32670510020758816978083085130507043184471273380659243275938904335757337482424n);
let secureRandom = (bytesLength) => new Uint8Array(bytesLength);
if (typeof window == "object" && "crypto" in window) {
    secureRandom = (bytesLength) => {
        const array = new Uint8Array(bytesLength);
        window.crypto.getRandomValues(array);
        return array;
    };
}
else if (typeof process === "object" && "node" in process.versions) {
    const { randomBytes } = require("crypto");
    secureRandom = (bytesLength) => {
        const b = randomBytes(bytesLength);
        return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
    };
}
else {
    throw new Error("The environment doesn't have cryptographically secure random function");
}
function getRandomValue(bytesLength) {
    return numberFromByteArrayLE(secureRandom(bytesLength));
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
function truncateHash(hash) {
    hash = typeof hash === "string" ? hash : arrayToHex(hash);
    let msg = BigInt(`0x${hash || "0"}`);
    const delta = (hash.length / 2) * 8 - PRIME_SIZE;
    if (delta > 0) {
        msg = msg >> BigInt(delta);
    }
    if (msg >= exports.PRIME_ORDER) {
        msg -= exports.PRIME_ORDER;
    }
    return msg;
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
function recoverPublicKey(hash, signature, recovery) {
    const sign = normalizeSignature(signature);
    const message = truncateHash(typeof hash === "string" ? hexToArray(hash) : hash);
    if (sign.r === 0n || sign.s === 0n) {
        return null;
    }
    let publicKeyX = sign.r;
    if (recovery >> 1n) {
        if (publicKeyX >= SUBPN) {
            return null;
        }
        publicKeyX = sign.r + exports.PRIME_ORDER;
    }
    const compresedHex = `$0{2n + (recovery & 1n)}${publicKeyX.toString(16)}`;
    const publicKey = Point.fromHex(compresedHex);
    const rInv = modInverse(sign.r, exports.PRIME_ORDER);
    const s1 = mod((exports.PRIME_ORDER - message) * rInv, exports.P);
    const s2 = mod(sign.s * rInv, exports.P);
    const point1 = exports.BASE_POINT.multiply(s1);
    const point2 = publicKey.multiply(s2);
    return point1.add(point2);
}
exports.recoverPublicKey = recoverPublicKey;
function getPublicKey(privateKey, isCompressed) {
    const number = normalizePrivateKey(privateKey);
    const point = exports.BASE_POINT.multiply(number);
    return normalizePoint(point, privateKey, isCompressed);
}
exports.getPublicKey = getPublicKey;
function sign(hash, privateKey, { k = getRandomValue(5), recovered, canonical } = {}) {
    const number = normalizePrivateKey(privateKey);
    k = BigInt(k);
    const message = truncateHash(hash);
    const q = exports.BASE_POINT.multiply(k);
    const r = mod(q.x, exports.PRIME_ORDER);
    let s = mod(modInverse(k, exports.PRIME_ORDER) * (message + r * number), exports.PRIME_ORDER);
    let recovery = (q.x === r ? 0n : 2n) | (q.y & 1n);
    if (s > HIGH_NUMBER && canonical) {
        s = exports.PRIME_ORDER - s;
        recovery ^= 1n;
    }
    const res = new SignResult(r, s).toHex();
    const hashed = hash instanceof Uint8Array ? hexToArray(res) : res;
    return recovered ? [hashed, recovery] : hashed;
}
exports.sign = sign;
function verify(signature, hash, publicKey) {
    const message = truncateHash(hash);
    const point = normalizePublicKey(publicKey);
    const sign = normalizeSignature(signature);
    const w = modInverse(sign.s, exports.PRIME_ORDER);
    const point1 = exports.BASE_POINT.multiply(mod(message * w, exports.PRIME_ORDER));
    const point2 = point.multiply(mod(sign.r * w, exports.PRIME_ORDER));
    const { x } = point1.add(point2);
    return x === sign.r;
}
exports.verify = verify;
