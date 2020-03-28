'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
exports.CURVE_PARAMS = {
    a: 0n,
    b: 7n,
    P: 2n ** 256n - 2n ** 32n - 977n,
    n: 2n ** 256n - 432420386565659656852420866394968145599n,
    h: 1n,
    Gx: 55066263022277343669578718895168534326250603453777594175500187360389116729240n,
    Gy: 32670510020758816978083085130507043184471273380659243275938904335757337482424n
};
function curve(x) {
    const { a, b } = exports.CURVE_PARAMS;
    return mod(x ** 3n + a * x + b);
}
const P = exports.CURVE_PARAMS.P;
const PRIME_ORDER = exports.CURVE_PARAMS.n;
const PRIME_SIZE = 256;
const HIGH_NUMBER = PRIME_ORDER >> 1n;
const SUBPN = P - PRIME_ORDER;
class JacobianPoint {
    constructor(x, y, z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }
    static fromPoint(p) {
        return new JacobianPoint(p.x, p.y, 1n);
    }
    static batchAffine(points) {
        const toInv = new Array(points.length);
        for (let i = 0; i < points.length; i++)
            toInv[i] = points[i].z;
        batchInverse(toInv, P);
        const res = new Array(points.length);
        for (let i = 0; i < res.length; i++)
            res[i] = points[i].toAffine(toInv[i]);
        return res;
    }
    double() {
        const a = this.x ** 2n;
        const b = this.y ** 2n;
        const c = b ** 2n;
        const d = 2n * ((this.x + b) ** 2n - a - c);
        const e = 3n * a;
        const f = e ** 2n;
        const x = mod(f - 2n * d);
        const y = mod(e * (d - x) - 8n * c);
        const z = mod(2n * this.y * this.z);
        return new JacobianPoint(x, y, z);
    }
    add(other) {
        const a = this;
        const b = other;
        if (!b.x || !b.y)
            return a;
        if (!a.x || !a.y)
            return b;
        const z1z1 = a.z ** 2n;
        const z2z2 = b.z ** 2n;
        const u1 = a.x * z2z2;
        const u2 = b.x * z1z1;
        const s1 = a.y * b.z * z2z2;
        const s2 = b.y * a.z * z1z1;
        const h = mod(u2 - u1);
        const r = mod(s2 - s1);
        if (!h) {
            if (!r) {
                return a.double();
            }
            else {
                return JacobianPoint.ZERO_POINT;
            }
        }
        const hh = h ** 2n;
        const hhh = h * hh;
        const v = u1 * hh;
        const x = mod(r ** 2n - hhh - 2n * v);
        const y = mod(r * (v - x) - s1 * hhh);
        const z = mod(this.z * b.z * h);
        return new JacobianPoint(x, y, z);
    }
    toAffine(negZ) {
        const negZ2 = negZ ** 2n;
        const x = mod(this.x * negZ2, P);
        const y = mod(this.y * negZ2 * negZ, P);
        return new Point(x, y);
    }
}
JacobianPoint.ZERO_POINT = new JacobianPoint(0n, 0n, 1n);
class Point {
    constructor(x, y) {
        this.x = x;
        this.y = y;
    }
    static isValid(x, y) {
        if (x === 0n || y === 0n || x >= P || y >= P)
            return false;
        const sqrY = mod(y * y);
        const yEquivalence = curve(x);
        const left1 = sqrY;
        const left2 = mod(-sqrY);
        const right1 = yEquivalence;
        const right2 = mod(-yEquivalence);
        return left1 === right1 || left1 === right2 || left2 === right1 || left2 === right2;
    }
    static fromCompressedHex(bytes) {
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
    static fromUncompressedHex(bytes) {
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
        return Point.BASE_POINT.multiply(normalizePrivateKey(privateKey));
    }
    static fromSignature(msgHash, signature, recovery) {
        const sign = normalizeSignature(signature);
        const { r, s } = sign;
        if (r === 0n || s === 0n)
            return;
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
        }
        else {
            return `04${x}${pad64(this.y)}`;
        }
    }
    negate() {
        return new Point(this.x, mod(-this.y));
    }
    add(other) {
        if (!(other instanceof Point)) {
            throw new TypeError('Point#add: expected Point');
        }
        const a = this;
        const b = other;
        if (a.equals(Point.ZERO_POINT))
            return b;
        if (b.equals(Point.ZERO_POINT))
            return a;
        if (a.x === b.x) {
            if (a.y === b.y) {
                return this.double();
            }
            else {
                throw new TypeError('Point#add: cannot add points (a.x == b.x, a.y != b.y)');
            }
        }
        const lamAdd = mod((b.y - a.y) * modInverse(b.x - a.x));
        const x = mod(lamAdd * lamAdd - a.x - b.x);
        const y = mod(lamAdd * (a.x - x) - a.y);
        return new Point(x, y);
    }
    subtract(other) {
        return this.add(other.negate());
    }
    double() {
        const a = this;
        const lam = mod(3n * a.x * a.x * modInverse(2n * a.y));
        const x = mod(lam * lam - 2n * a.x);
        const y = mod(lam * (a.x - x) - a.y);
        return new Point(x, y);
    }
    equals(other) {
        return this.x === other.x && this.y === other.y;
    }
    precomputeWindow(W) {
        if (this.PRECOMPUTES)
            return this.PRECOMPUTES;
        const points = new Array((2 ** W - 1) * W);
        let currPoint = JacobianPoint.fromPoint(this);
        const winSize = 2 ** W - 1;
        for (let currWin = 0; currWin < 256 / W; currWin++) {
            let offset = currWin * winSize;
            let point = currPoint;
            for (let i = 0; i < winSize; i++) {
                points[offset + i] = point;
                point = point.add(currPoint);
            }
            currPoint = point;
        }
        const res = JacobianPoint.batchAffine(points);
        if (W !== 1) {
            this.PRECOMPUTES = res;
        }
        return res;
    }
    multiply(scalar) {
        if (typeof scalar !== 'number' && typeof scalar !== 'bigint') {
            throw new TypeError('Point#multiply: expected number or bigint');
        }
        let n = mod(BigInt(scalar), PRIME_ORDER);
        if (n <= 0) {
            throw new Error('Point#multiply: invalid scalar, expected positive integer');
        }
        if (scalar > PRIME_ORDER) {
            throw new Error('Point#multiply: invalid scalar, expected < PRIME_ORDER');
        }
        const W = this.WINDOW_SIZE || 1;
        if (256 % W) {
            throw new Error('Point#multiply: Invalid precomputation window, must be power of 2');
        }
        const precomputes = this.precomputeWindow(W);
        let winSize = 2 ** W - 1;
        let p = JacobianPoint.ZERO_POINT;
        let f = JacobianPoint.ZERO_POINT;
        for (let byte_idx = 0; byte_idx < 256 / W; byte_idx++) {
            const offset = winSize * byte_idx;
            const masked = Number(n & BigInt(winSize));
            if (masked) {
                p = p.add(JacobianPoint.fromPoint(precomputes[offset + masked - 1]));
            }
            else {
                f = f.add(JacobianPoint.fromPoint(precomputes[offset]));
            }
            n >>= BigInt(W);
        }
        return JacobianPoint.batchAffine([p, f])[0];
    }
}
exports.Point = Point;
Point.BASE_POINT = new Point(exports.CURVE_PARAMS.Gx, exports.CURVE_PARAMS.Gy);
Point.ZERO_POINT = new Point(0n, 0n);
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
function mod(a, b = P) {
    const result = a % b;
    return result >= 0 ? result : b + result;
}
function egcd(a, b) {
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
function modInverse(number, modulo = P) {
    if (number === 0n || modulo <= 0n) {
        throw new Error('modInverse: expected positive integers');
    }
    let [gcd, x] = egcd(mod(number, modulo), modulo);
    if (gcd !== 1n) {
        throw new Error('modInverse: does not exist');
    }
    return mod(x, modulo);
}
function batchInverse(elms, n) {
    let scratch = Array(elms.length);
    let acc = 1n;
    for (let i = 0; i < elms.length; i++) {
        if (!elms[i])
            continue;
        scratch[i] = acc;
        acc = mod(acc * elms[i], n);
    }
    acc = modInverse(acc, n);
    for (let i = elms.length - 1; i >= 0; i--) {
        if (!elms[i])
            continue;
        let tmp = mod(acc * elms[i], n);
        elms[i] = mod(acc * scratch[i], n);
        acc = tmp;
    }
}
function truncateHash(hash) {
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
    return 0 < privateKey && privateKey < PRIME_ORDER;
}
function calcQRSFromK(k, msg, priv) {
    const q = Point.BASE_POINT.multiply(k);
    const r = mod(q.x, PRIME_ORDER);
    const s = mod(modInverse(k, PRIME_ORDER) * (msg + r * priv), PRIME_ORDER);
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
        adjustedS = PRIME_ORDER - s;
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
    const w = modInverse(sign.s, PRIME_ORDER);
    const point1 = Point.BASE_POINT.multiply(mod(msg * w, PRIME_ORDER));
    const point2 = point.multiply(mod(sign.r * w, PRIME_ORDER));
    const point3 = point1.add(point2);
    return point3.x === sign.r;
}
exports.verify = verify;
Point.BASE_POINT.WINDOW_SIZE = 4;
exports.utils = {
    isValidPrivateKey(privateKey) {
        return isValidPrivateKey(normalizePrivateKey(privateKey));
    },
    precompute(windowSize = 4, point = Point.BASE_POINT) {
        point.WINDOW_SIZE = windowSize;
        point.multiply(1n);
        return true;
    }
};
