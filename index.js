const B256 = 2n ** 256n;
const P = B256 - 0x1000003d1n;
const N = B256 - 0x14551231950b75fc4402da1732fc9bebfn;
const _a = 0n;
const _b = 7n;
const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
export const CURVE = { P, n: N, a: _a, b: _b, Gx, Gy };
const fLen = 32;
const crv = (x) => mod(mod(x * mod(x * x)) + _a * x + _b);
const err = (m = '') => { throw new Error(m); };
const big = (n) => typeof n === 'bigint';
const str = (s) => typeof s === 'string';
const fe = (n) => big(n) && 0n < n && n < P;
const ge = (n) => big(n) && 0n < n && n < N;
const au8 = (a, l) => !(a instanceof Uint8Array) || (typeof l === 'number' && l > 0 && a.length !== l) ?
    err('Uint8Array expected') : a;
const u8n = (data) => new Uint8Array(data);
const u8fr = (arr) => Uint8Array.from(arr);
const toU8 = (a, len) => au8(str(a) ? h2b(a) : a, len);
const toPriv = (p) => {
    if (!big(p))
        p = b2n(toU8(p, fLen));
    return ge(p) ? p : err('private key out of range');
};
let Gpows = undefined;
const isPoint = (p) => (p instanceof Point ? p : err('Point expected'));
class Point {
    constructor(px, py, pz) {
        this.px = px;
        this.py = py;
        this.pz = pz;
    }
    get x() { return this.aff().x; }
    get y() { return this.aff().y; }
    equals(other) {
        const { px: X1, py: Y1, pz: Z1 } = this;
        const { px: X2, py: Y2, pz: Z2 } = isPoint(other);
        const X1Z2 = mod(X1 * Z2), X2Z1 = mod(X2 * Z1);
        const Y1Z2 = mod(Y1 * Z2), Y2Z1 = mod(Y2 * Z1);
        return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
    }
    neg() { return new Point(this.px, mod(-this.py), this.pz); }
    dbl() { return this.add(this); }
    add(other) {
        const { px: X1, py: Y1, pz: Z1 } = this;
        const { px: X2, py: Y2, pz: Z2 } = isPoint(other);
        const { a, b } = CURVE;
        let X3 = 0n, Y3 = 0n, Z3 = 0n;
        const b3 = mod(b * 3n);
        let t0 = mod(X1 * X2), t1 = mod(Y1 * Y2), t2 = mod(Z1 * Z2), t3 = mod(X1 + Y1);
        let t4 = mod(X2 + Y2);
        t3 = mod(t3 * t4);
        t4 = mod(t0 + t1);
        t3 = mod(t3 - t4);
        t4 = mod(X1 + Z1);
        let t5 = mod(X2 + Z2);
        t4 = mod(t4 * t5);
        t5 = mod(t0 + t2);
        t4 = mod(t4 - t5);
        t5 = mod(Y1 + Z1);
        X3 = mod(Y2 + Z2);
        t5 = mod(t5 * X3);
        X3 = mod(t1 + t2);
        t5 = mod(t5 - X3);
        Z3 = mod(a * t4);
        X3 = mod(b3 * t2);
        Z3 = mod(X3 + Z3);
        X3 = mod(t1 - Z3);
        Z3 = mod(t1 + Z3);
        Y3 = mod(X3 * Z3);
        t1 = mod(t0 + t0);
        t1 = mod(t1 + t0);
        t2 = mod(a * t2);
        t4 = mod(b3 * t4);
        t1 = mod(t1 + t2);
        t2 = mod(t0 - t2);
        t2 = mod(a * t2);
        t4 = mod(t4 + t2);
        t0 = mod(t1 * t4);
        Y3 = mod(Y3 + t0);
        t0 = mod(t5 * t4);
        X3 = mod(t3 * X3);
        X3 = mod(X3 - t0);
        t0 = mod(t3 * t1);
        Z3 = mod(t5 * Z3);
        Z3 = mod(Z3 + t0);
        return new Point(X3, Y3, Z3);
    }
    mul(n, safe = true) {
        if (!safe && n === 0n)
            return I;
        if (!ge(n))
            err('invalid scalar');
        if (this.equals(G))
            return wNAF(n).p;
        let p = I, f = G;
        for (let d = this; n > 0n; d = d.dbl(), n >>= 1n) {
            if (n & 1n)
                p = p.add(d);
            else if (safe)
                f = f.add(d);
        }
        return p;
    }
    mulAddQUns(R, u1, u2) {
        return this.mul(u1, false).add(R.mul(u2, false)).ok();
    }
    aff() {
        const { px: x, py: y, pz: z } = this;
        if (this.equals(I))
            return { x: 0n, y: 0n };
        if (z === 1n)
            return { x, y };
        const iz = inv(z);
        if (mod(z * iz) !== 1n)
            err('invalid inverse');
        return { x: mod(x * iz), y: mod(y * iz) };
    }
    ok() {
        const { x, y } = this.aff();
        if (!fe(x) || !fe(y))
            err('Point invalid: x or y');
        return mod(y * y) === crv(x) ?
            this : err('Point invalid: not on curve');
    }
    multiply(n) { return this.mul(n); }
    negate() { return this.neg(); }
    toAffine() { return this.aff(); }
    assertValidity() { return this.ok(); }
    static fromHex(hex) {
        hex = toU8(hex);
        let p = undefined;
        const head = hex[0], tail = hex.subarray(1);
        const x = slcNum(tail, 0, fLen), len = hex.length;
        if (len === 33 && [0x02, 0x03].includes(head)) {
            if (!fe(x))
                err('Point hex invalid: x not FE');
            let y = sqrt(crv(x));
            const isYOdd = (y & 1n) === 1n;
            const headOdd = (head & 1) === 1;
            if (headOdd !== isYOdd)
                y = mod(-y);
            p = new Point(x, y, 1n);
        }
        if (len === 65 && head === 0x04)
            p = new Point(x, slcNum(tail, fLen, 2 * fLen), 1n);
        return p ? p.ok() : err('Point is not on curve');
    }
    toHex(isCompressed = true) {
        const { x, y } = this.aff();
        const head = isCompressed ? ((y & 1n) === 0n ? '02' : '03') : '04';
        return `${head}${n2h(x)}${isCompressed ? '' : n2h(y)}`;
    }
    toRawBytes(isCompressed = true) {
        return h2b(this.toHex(isCompressed));
    }
    static fromPrivateKey(n) {
        return G.mul(toPriv(n));
    }
}
Point.BASE = new Point(Gx, Gy, 1n);
Point.ZERO = new Point(0n, 1n, 0n);
const { BASE: G, ZERO: I } = Point;
const mod = (a, b = P) => { let r = a % b; return r >= 0n ? r : b + r; };
const inv = (num, md = P) => {
    if (num === 0n || md <= 0n)
        err(`no inverse n=${num} mod=${md}`);
    let a = mod(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
    while (a !== 0n) {
        const q = b / a, r = b % a;
        const m = x - u * q, n = y - v * q;
        b = a, a = r, x = u, y = v, u = m, v = n;
    }
    return b === 1n ? mod(x, md) : err('no inverse');
};
const pow = (num, e, md = P) => {
    if (md <= 0n || e < 0n)
        err('pow invalid');
    if (md === 1n)
        return 0n;
    let res = 1n;
    for (; e > 0n; e >>= 1n) {
        if (e & 1n)
            res = (res * num) % md;
        num = (num * num) % md;
    }
    return res;
};
const sqrt = (n) => {
    const r = pow(n, (P + 1n) / 4n, P);
    return mod(r * r) === n ? r : err('sqrt invalid');
};
const padh = (num, pad) => num.toString(16).padStart(pad, '0');
const b2h = (b) => Array.from(b).map(e => padh(e, 2)).join('');
const h2n = (hex) => (str(hex) ? BigInt(`0x${hex || '0'}`) : err());
const h2b = (hex) => {
    const l = hex.length;
    if (!str(hex) || l % 2)
        err('hex invalid');
    const arr = u8n(l / 2);
    for (let i = 0; i < arr.length; i++) {
        const j = i * 2;
        const h = hex.slice(j, j + 2);
        const b = Number.parseInt(h, 16);
        if (Number.isNaN(b) || b < 0)
            err('hex invalid');
        arr[i] = b;
    }
    return arr;
};
const b2n = (b) => h2n(b2h(b));
const slcNum = (b, from, to) => b2n(b.slice(from, to));
const n2b = (num) => {
    return big(num) && num >= 0n && num < B256 ? h2b(padh(num, 2 * fLen)) : err('bigint expected');
};
const n2h = (num) => b2h(n2b(num));
const concatB = (...arrs) => {
    const r = u8n(arrs.reduce((sum, a) => sum + a.length, 0));
    let pad = 0;
    arrs.forEach(a => { r.set(au8(a), pad); pad += a.length; });
    return r;
};
const moreThanHalfN = (n) => n > (N >> 1n);
export const getPublicKey = (privKey, isCompressed = true) => {
    return Point.fromPrivateKey(privKey).toRawBytes(isCompressed);
};
export class Signature {
    constructor(r, s, recovery) {
        this.r = r;
        this.s = s;
        this.recovery = recovery;
        this.ok();
    }
    ok() { return ge(this.r) && ge(this.s) ? this : err(); }
    static fromCompact(hex) {
        hex = toU8(hex, 64);
        return new Signature(slcNum(hex, 0, fLen), slcNum(hex, fLen, 2 * fLen));
    }
    hasHighS() { return moreThanHalfN(this.s); }
    recoverPublicKey(msgh) {
        const { r, s, recovery: rec } = this;
        if (![0, 1, 2, 3].includes(rec))
            err('recovery id invalid');
        const h = bits2int_modN(toU8(msgh, 32));
        const radj = rec === 2 || rec === 3 ? r + N : r;
        if (radj >= P)
            err('q.x invalid');
        const prefix = (rec & 1) === 0 ? '02' : '03';
        const R = Point.fromHex(`${prefix}${n2h(radj)}`);
        const ir = inv(radj, N);
        const u1 = mod(-h * ir, N);
        const u2 = mod(s * ir, N);
        return G.mulAddQUns(R, u1, u2);
    }
    toCompactRawBytes() { return h2b(this.toCompactHex()); }
    toCompactHex() { return n2h(this.r) + n2h(this.s); }
}
const bits2int = (bytes) => {
    const delta = bytes.length * 8 - 256;
    const num = b2n(bytes);
    return delta > 0 ? num >> BigInt(delta) : num;
};
const bits2int_modN = (bytes) => {
    return mod(bits2int(bytes), N);
};
const i2o = (num) => n2b(num);
const cr = () => typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined;
let _hmacSync;
const stdo = { lowS: true };
const vstdo = { lowS: true };
const prepSig = (msgh, priv, opts = stdo) => {
    if (['der', 'recovered', 'canonical'].some(k => k in opts))
        err('sign() legacy options not supported');
    let { lowS } = opts;
    if (lowS == null)
        lowS = true;
    const h1i = bits2int_modN(toU8(msgh));
    const h1o = i2o(h1i);
    const d = toPriv(priv);
    const seed = [i2o(d), h1o];
    let ent = opts.extraEntropy;
    if (ent != null) {
        if (ent === true)
            ent = etc.randomBytes(fLen);
        const e = toU8(ent);
        if (e.length !== fLen)
            err();
        seed.push(e);
    }
    const m = h1i;
    const k2sig = (kBytes) => {
        const k = bits2int(kBytes);
        if (!ge(k))
            return;
        const ik = inv(k, N);
        const q = G.mul(k).aff();
        const r = mod(q.x, N);
        if (r === 0n)
            return;
        const s = mod(ik * mod(m + mod(d * r, N), N), N);
        if (s === 0n)
            return;
        let normS = s;
        let rec = (q.x === r ? 0 : 2) | Number(q.y & 1n);
        if (lowS && moreThanHalfN(s)) {
            normS = mod(-s, N);
            rec ^= 1;
        }
        return new Signature(r, normS, rec);
    };
    return { seed: concatB(...seed), k2sig };
};
function hmacDrbg(asynchronous) {
    let v = u8n(fLen);
    let k = u8n(fLen);
    let i = 0;
    const reset = () => { v.fill(1); k.fill(0); i = 0; };
    const _e = 'drbg: tried 1000 values';
    if (asynchronous) {
        const h = (...b) => etc.hmacSha256Async(k, v, ...b);
        const reseed = async (seed = u8n()) => {
            k = await h(u8fr([0x00]), seed);
            v = await h();
            if (seed.length === 0)
                return;
            k = await h(u8fr([0x01]), seed);
            v = await h();
        };
        const gen = async () => {
            if (i++ >= 1000)
                err(_e);
            v = await h();
            return v;
        };
        return async (seed, pred) => {
            reset();
            await reseed(seed);
            let res = undefined;
            while (!(res = pred(await gen())))
                await reseed();
            reset();
            return res;
        };
    }
    else {
        const h = (...b) => {
            const f = _hmacSync;
            if (!f)
                err('utils.hmacSha256Sync not set');
            return f(k, v, ...b);
        };
        const reseed = (seed = u8n()) => {
            k = h(u8fr([0x00]), seed);
            v = h();
            if (seed.length === 0)
                return;
            k = h(u8fr([0x01]), seed);
            v = h();
        };
        const gen = () => {
            if (i++ >= 1000)
                err(_e);
            v = h();
            return v;
        };
        return (seed, pred) => {
            reset();
            reseed(seed);
            let res = undefined;
            while (!(res = pred(gen())))
                reseed();
            reset();
            return res;
        };
    }
}
;
export const signAsync = async (msgh, priv, opts = stdo) => {
    const { seed, k2sig } = prepSig(msgh, priv, opts);
    const genUntil = hmacDrbg(true);
    return genUntil(seed, k2sig);
};
export const sign = (msgh, priv, opts = stdo) => {
    const { seed, k2sig } = prepSig(msgh, priv, opts);
    const genUntil = hmacDrbg(false);
    return genUntil(seed, k2sig);
};
export const verify = (sig, msgh, pub, opts = vstdo) => {
    let { lowS } = opts;
    if (lowS == null)
        lowS = true;
    if ('strict' in opts)
        err('verify() legacy options not supported');
    let sig_, h, P;
    const rs = sig && typeof sig === 'object' && 'r' in sig;
    if (!rs && (toU8(sig).length !== 2 * fLen))
        err('signature must be 64 bytes');
    try {
        sig_ = rs ? new Signature(sig.r, sig.s).ok() : Signature.fromCompact(sig);
        h = bits2int_modN(toU8(msgh, fLen));
        P = pub instanceof Point ? pub.ok() : Point.fromHex(pub);
    }
    catch (e) {
        return false;
    }
    if (!sig_)
        return false;
    const { r, s } = sig_;
    if (lowS && moreThanHalfN(s))
        return false;
    let R;
    try {
        const is = inv(s, N);
        const u1 = mod(h * is, N);
        const u2 = mod(r * is, N);
        R = G.mulAddQUns(P, u1, u2).aff();
    }
    catch (error) {
        return false;
    }
    if (!R)
        return false;
    const v = mod(R.x, N);
    return v === r;
};
export const getSharedSecret = (privA, pubB, isCompressed = true) => {
    return Point.fromHex(pubB).mul(toPriv(privA)).toRawBytes(isCompressed);
};
const hashToPrivateKey = (hash) => {
    hash = toU8(hash);
    const minLen = fLen + 8;
    if (hash.length < minLen || hash.length > 1024)
        err('expected proper params');
    const num = mod(b2n(hash), N - 1n) + 1n;
    return n2b(num);
};
export const etc = {
    hexToBytes: h2b, bytesToHex: b2h,
    concatBytes: concatB, bytesToNumberBE: b2n, numberToBytesBE: n2b,
    mod, invert: inv,
    hmacSha256Async: async (key, ...msgs) => {
        const m = concatB(...msgs);
        const crypto = cr();
        if (!crypto)
            return err('utils.hmacSha256Async not set');
        const s = crypto.subtle;
        const k = await s.importKey('raw', key, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign']);
        return u8n(await s.sign('HMAC', k, m));
    },
    hmacSha256Sync: _hmacSync,
    hashToPrivateKey,
    randomBytes: (len) => {
        const crypto = cr();
        if (!crypto)
            err('crypto.getRandomValues must be defined');
        return crypto.getRandomValues(u8n(len));
    },
};
export const utils = {
    normPrivateKeyToScalar: toPriv,
    randomPrivateKey: () => hashToPrivateKey(etc.randomBytes(fLen + 8)),
    isValidPrivateKey: (key) => { try {
        return !!toPriv(key);
    }
    catch (e) {
        return false;
    } },
    precompute(p, windowSize = 8) { return p; }
};
Object.defineProperties(etc, { hmacSha256Sync: {
        configurable: false, get() { return _hmacSync; }, set(f) { if (!_hmacSync)
            _hmacSync = f; },
    } });
const W = 8;
const precompute = () => {
    const points = [];
    const windows = 256 / W + 1;
    let p = G, b = p;
    for (let w = 0; w < windows; w++) {
        b = p;
        points.push(b);
        for (let i = 1; i < 2 ** (W - 1); i++) {
            b = b.add(p);
            points.push(b);
        }
        p = b.dbl();
    }
    return points;
};
const wNAF = (n) => {
    const comp = Gpows || (Gpows = precompute());
    const neg = (cnd, p) => { let n = p.neg(); return cnd ? n : p; };
    let p = I, f = G;
    const windows = 1 + 256 / W;
    const wsize = 2 ** (W - 1);
    const mask = BigInt(2 ** W - 1);
    const maxNum = 2 ** W;
    const shiftBy = BigInt(W);
    for (let w = 0; w < windows; w++) {
        const off = w * wsize;
        let wbits = Number(n & mask);
        n >>= shiftBy;
        if (wbits > wsize) {
            wbits -= maxNum;
            n += 1n;
        }
        const off1 = off, off2 = off + Math.abs(wbits) - 1;
        const cnd1 = w % 2 !== 0, cnd2 = wbits < 0;
        if (wbits === 0) {
            f = f.add(neg(cnd1, comp[off1]));
        }
        else {
            p = p.add(neg(cnd2, comp[off2]));
        }
    }
    return { p, f };
};
export const ProjectivePoint = Point;
