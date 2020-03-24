"use strict";
/*! noble-secp256k1 - MIT License (c) Paul Miller (paulmillr.com) */
Object.defineProperty(exports, "__esModule", { value: true });
const A = 0n;
const B = 7n;
exports.P = 2n ** 256n - 2n ** 32n - 977n;
exports.PRIME_ORDER = 2n ** 256n - 432420386565659656852420866394968145599n;
function curve(x) {
    return x ** 3n + A * x + B;
}
const PRIME_SIZE = 256;
const HIGH_NUMBER = exports.PRIME_ORDER >> 1n;
const SUBPN = exports.P - exports.PRIME_ORDER;
const powersOf2 = new Array(256);
for (let i = 0n; i < 256n; i++)
    powersOf2[Number(i)] = 2n ** i;
let BASE_POINT_DOUBLES;
class Point {
    constructor(x, y) {
        this.x = x;
        this.y = y;
    }
    static isValidPoint(x, y) {
        if (x === 0n || y === 0n || x >= exports.P || y >= exports.P)
            return false;
        const sqrY = y * y;
        const yEquivalence = curve(x);
        const left1 = mod(sqrY, exports.P);
        const left2 = mod(-sqrY, exports.P);
        const right1 = mod(yEquivalence, exports.P);
        const right2 = mod(-yEquivalence, exports.P);
        return left1 === right1 || left1 === right2 || left2 === right1 || left2 === right2;
    }
    static fromCompressedHex(bytes) {
        if (bytes.length !== 33) {
            throw new TypeError(`Point.fromHex: compressed expects 66 bytes, not ${bytes.length * 2}`);
        }
        const x = arrayToNumber(bytes.slice(1));
        const sqrY = mod(curve(x), exports.P);
        let y = powMod(sqrY, (exports.P + 1n) / 4n, exports.P);
        const isFirstByteOdd = (bytes[0] & 1) === 1;
        const isYOdd = (y & 1n) === 1n;
        if (isFirstByteOdd !== isYOdd) {
            y = mod(-y, exports.P);
        }
        if (!Point.isValidPoint(x, y)) {
            throw new TypeError('Point.fromHex: Point is not on elliptic curve');
        }
        return new Point(x, y);
    }
    static fromUncompressedHex(bytes) {
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
    static fromHex(hex) {
        const bytes = hex instanceof Uint8Array ? hex : hexToArray(hex);
        const header = bytes[0];
        if (header === 0x02 || header === 0x03)
            return this.fromCompressedHex(bytes);
        if (header === 0x04)
            return this.fromUncompressedHex(bytes);
        throw new TypeError('Point.fromHex: received invalid point');
    }
    static fromPrivateKey(privateKey) {
        return exports.BASE_POINT.multiply(normalizePrivateKey(privateKey));
    }
    static fromSignature(msgHash, signature, recovery) {
        const sign = normalizeSignature(signature);
        const { r, s } = sign;
        if (r === 0n || s === 0n)
            return;
        const rinv = modInverse(r, exports.PRIME_ORDER);
        const h = typeof msgHash === 'string' ? hexToNumber(msgHash) : arrayToNumber(msgHash);
        const P_ = Point.fromHex(`0${2 + (recovery & 1)}${pad64(r)}`);
        const sP = P_.multiply(s);
        const hG = exports.BASE_POINT.multiply(h).negate();
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
        }
        else {
            return `04${x}${pad64(this.y)}`;
        }
    }
    negate() {
        return new Point(this.x, exports.P - this.y);
    }
    add(other) {
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
            }
            else {
                throw new TypeError('Point#add: cannot add points (a.x == b.x, a.y != b.y)');
            }
        }
        const lamAdd = mod((b.y - a.y) * modInverse(b.x - a.x, exports.P), exports.P);
        const x = mod(lamAdd * lamAdd - a.x - b.x, exports.P);
        const y = mod(lamAdd * (a.x - x) - a.y, exports.P);
        return new Point(x, y);
    }
    multiply(scalar) {
        if (typeof scalar !== 'number' && typeof scalar !== 'bigint') {
            throw new TypeError('Point#multiply: expected number or bigint');
        }
        let n = BigInt(scalar);
        if (!isValidPrivateKey(n)) {
            throw new Error('Private key is invalid. Expected 0 < key < PRIME_ORDER');
        }
        let p = new Point(0n, 0n);
        let f = new Point(0n, 0n);
        const doubles = this.precomputeDoubles();
        for (let bit = 0; bit < 256; bit++) {
            const pow = powersOf2[bit];
            const powPoint = doubles[bit];
            const hasBit = (n & pow) === pow;
            if (hasBit) {
                p = p.add(powPoint);
            }
            else {
                f = f.add(powPoint);
            }
        }
        return p;
    }
    double() {
        const a = this;
        const lam = mod(3n * a.x * a.x * modInverse(2n * a.y, exports.P), exports.P);
        const x = mod(lam * lam - 2n * a.x, exports.P);
        const y = mod(lam * (a.x - x) - a.y, exports.P);
        return new Point(x, y);
    }
    precomputeDoubles() {
        let points = new Array(256);
        if (this.x === exports.BASE_POINT.x && this.y === exports.BASE_POINT.y) {
            if (BASE_POINT_DOUBLES)
                return BASE_POINT_DOUBLES;
            points = BASE_POINT_DOUBLES = new Array(256);
        }
        for (let bit = 0, point = this; bit < 256; bit++, point = point.double()) {
            points[bit] = point;
        }
        return points;
    }
}
exports.Point = Point;
function parseByte(str) {
    return Number.parseInt(str, 16) * 2;
}
class SignResult {
    constructor(r, s) {
        this.r = r;
        this.s = s;
    }
    static fromHex(hex) {
        const str = hex instanceof Uint8Array ? arrayToHex(hex) : hex;
        if (typeof str !== 'string')
            throw new TypeError({}.toString.call(hex));
        const check1 = str.slice(0, 2);
        const length = parseByte(str.slice(2, 4));
        const check2 = str.slice(4, 6);
        if (check1 !== '30' || length !== str.length - 4 || check2 !== '02') {
            throw new Error('SignResult.fromHex: Invalid signature');
        }
        const rLen = parseByte(str.slice(6, 8));
        const rEnd = 8 + rLen;
        const r = hexToNumber(str.slice(8, rEnd));
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
        const rHex = numberToHex(this.r);
        const sHex = numberToHex(this.s);
        if (compressed)
            return sHex;
        const rLen = numberToHex(rHex.length / 2);
        const sLen = numberToHex(sHex.length / 2);
        const length = numberToHex(rHex.length / 2 + sHex.length / 2 + 4);
        return `30${length}02${rLen}${rHex}02${sLen}${sHex}`;
    }
}
exports.SignResult = SignResult;
exports.BASE_POINT = new Point(55066263022277343669578718895168534326250603453777594175500187360389116729240n, 32670510020758816978083085130507043184471273380659243275938904335757337482424n);
let hmac;
if (typeof window == 'object' && 'crypto' in window) {
    hmac = async (key, message) => {
        const ckey = await window.crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign', 'verify']);
        const buffer = await window.crypto.subtle.sign('HMAC', ckey, message);
        return new Uint8Array(buffer);
    };
}
else if (typeof process === 'object' && 'node' in process.versions) {
    const req = require;
    const { createHmac } = req('crypto');
    hmac = async (key, message) => {
        const hash = createHmac('sha256', key);
        hash.update(message);
        return Uint8Array.from(hash.digest());
    };
}
else {
    throw new Error("The environment doesn't have hmac-sha256 function");
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
    let hex = '';
    for (let i = 0; i < uint8a.length; i++) {
        hex += uint8a[i].toString(16).padStart(2, '0');
    }
    return hex;
}
function numberToHex(num) {
    const hex = num.toString(16);
    return hex.length & 1 ? `0${hex}` : hex;
}
function hexToNumber(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
    }
    return BigInt(`0x${hex}`);
}
function hexToArray(hex) {
    hex = hex.length & 1 ? `0${hex}` : hex;
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        let j = i * 2;
        array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
    }
    return array;
}
function arrayToNumber(bytes) {
    return hexToNumber(arrayToHex(bytes));
}
function pad64(num) {
    return num.toString(16).padStart(64, '0');
}
function bitset(num) {
    return num
        .toString(2)
        .split('')
        .reverse()
        .map(n => Number.parseInt(n, 2));
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
    hash = typeof hash === 'string' ? hash : arrayToHex(hash);
    let msg = hexToNumber(hash || '0');
    const delta = (hash.length / 2) * 8 - PRIME_SIZE;
    if (delta > 0) {
        msg = msg >> BigInt(delta);
    }
    if (msg >= exports.PRIME_ORDER) {
        msg -= exports.PRIME_ORDER;
    }
    return msg;
}
function concatTypedArrays(...args) {
    const result = new Uint8Array(args.reduce((a, arr) => a + arr.length, 0));
    for (let i = 0, pad = 0; i < args.length; i++) {
        const arr = args[i];
        result.set(arr, pad);
        pad += arr.length;
    }
    return result;
}
async function getQRSrfc6979(msgHash, privateKey) {
    const num = typeof msgHash === 'string' ? hexToNumber(msgHash) : arrayToNumber(msgHash);
    const h1 = hexToArray(pad64(num));
    const x = hexToArray(pad64(privateKey));
    const h1n = arrayToNumber(h1);
    let v = new Uint8Array(32).fill(1);
    let k = new Uint8Array(32).fill(0);
    const b0 = Uint8Array.from([0x00]);
    const b1 = Uint8Array.from([0x01]);
    const concat = concatTypedArrays;
    k = await hmac(k, concat(v, b0, x, h1));
    v = await hmac(k, v);
    k = await hmac(k, concat(v, b1, x, h1));
    v = await hmac(k, v);
    for (let i = 0; i < 1000; i++) {
        v = await hmac(k, v);
        const T = arrayToNumber(v);
        let qrs;
        if (isValidPrivateKey(T) && (qrs = calcQRSFromK(T, h1n, privateKey))) {
            return qrs;
        }
        k = await hmac(k, concat(v, b0));
        v = await hmac(k, v);
    }
    throw new TypeError('secp256k1: Tried 1,000 k values for sign(), all were invalid');
}
function isValidPrivateKey(privateKey) {
    return 0 < privateKey && privateKey < exports.PRIME_ORDER;
}
function calcQRSFromK(k, msg, priv) {
    const q = exports.BASE_POINT.multiply(k);
    const r = mod(q.x, exports.PRIME_ORDER);
    const s = mod(modInverse(k, exports.PRIME_ORDER) * (msg + r * priv), exports.PRIME_ORDER);
    if (r === 0n || s === 0n)
        return;
    return [q, r, s];
}
function normalizePrivateKey(privateKey) {
    let key;
    if (privateKey instanceof Uint8Array) {
        key = arrayToNumber(privateKey);
    }
    else if (typeof privateKey === 'string') {
        key = hexToNumber(privateKey);
    }
    else {
        key = BigInt(privateKey);
    }
    return key;
}
function normalizePublicKey(publicKey) {
    return publicKey instanceof Point ? publicKey : Point.fromHex(publicKey);
}
function normalizeSignature(signature) {
    return signature instanceof SignResult ? signature : SignResult.fromHex(signature);
}
function recoverPublicKey(msgHash, signature, recovery) {
    const point = Point.fromSignature(msgHash, signature, recovery);
    if (!point)
        return;
    return typeof msgHash === 'string' ? point.toHex() : point.toRawBytes();
}
exports.recoverPublicKey = recoverPublicKey;
function getPublicKey(privateKey, isCompressed) {
    const point = Point.fromPrivateKey(privateKey);
    if (typeof privateKey === 'string') {
        return point.toHex(isCompressed);
    }
    return point.toRawBytes(isCompressed);
}
exports.getPublicKey = getPublicKey;
function getSharedSecret(privateA, publicB) {
    const point = publicB instanceof Point ? publicB : Point.fromHex(publicB);
    const shared = point.multiply(normalizePrivateKey(privateA));
    const returnHex = typeof privateA === 'string';
    return returnHex ? shared.toHex() : shared.toRawBytes();
}
exports.getSharedSecret = getSharedSecret;
async function sign(msgHash, privateKey, { recovered, canonical } = {}) {
    const priv = normalizePrivateKey(privateKey);
    if (!isValidPrivateKey(priv)) {
        throw new Error('Private key is invalid. Expected 0 < key < PRIME_ORDER');
    }
    const [q, r, s] = await getQRSrfc6979(msgHash, priv);
    let recovery = (q.x === r ? 0 : 2) | Number(q.y & 1n);
    let adjustedS = s;
    if (s > HIGH_NUMBER && canonical) {
        adjustedS = exports.PRIME_ORDER - s;
        recovery ^= 1;
    }
    const res = new SignResult(r, adjustedS).toHex();
    const hashed = msgHash instanceof Uint8Array ? hexToArray(res) : res;
    return recovered ? [hashed, recovery] : hashed;
}
exports.sign = sign;
function verify(signature, msgHash, publicKey) {
    const msg = truncateHash(msgHash);
    const sign = normalizeSignature(signature);
    const point = normalizePublicKey(publicKey);
    const w = modInverse(sign.s, exports.PRIME_ORDER);
    const point1 = exports.BASE_POINT.multiply(mod(msg * w, exports.PRIME_ORDER));
    const point2 = point.multiply(mod(sign.r * w, exports.PRIME_ORDER));
    const point3 = point1.add(point2);
    return point3.x === sign.r;
}
exports.verify = verify;
exports.utils = {
    isValidPrivateKey(privateKey) {
        return isValidPrivateKey(normalizePrivateKey(privateKey));
    }
};
