/*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
const B256 = 2n ** 256n; // secp256k1 is short weierstrass curve
const P = B256 - 0x1000003d1n; // curve's field prime
const N = B256 - 0x14551231950b75fc4402da1732fc9bebfn; // curve (group) order
const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n; // base point x
const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n; // base point y
const CURVE = { p: P, n: N, a: 0n, b: 7n, Gx, Gy }; // exported variables incl. a, b
const fLen = 32; // field / group byte length
const crv = (x) => mod(mod(x * x) * x + CURVE.b); // x³ + ax + b weierstrass formula; no a
const err = (m = '') => { throw new Error(m); }; // error helper, messes-up stack trace
const big = (n) => typeof n === 'bigint'; // is big integer
const str = (s) => typeof s === 'string'; // is string
const fe = (n) => big(n) && 0n < n && n < P; // is field element (invertible)
const ge = (n) => big(n) && 0n < n && n < N; // is group element
const au8 = (a, l) => // is Uint8Array (of specific length)
 !(a instanceof Uint8Array) || (typeof l === 'number' && l > 0 && a.length !== l) ?
    err('Uint8Array expected') : a;
const u8n = (data) => new Uint8Array(data); // creates Uint8Array
const toU8 = (a, len) => au8(str(a) ? h2b(a) : u8n(a), len); // norm(hex/u8a) to u8a
const mod = (a, b = P) => { let r = a % b; return r >= 0n ? r : b + r; }; // mod division
const isPoint = (p) => (p instanceof Point ? p : err('Point expected')); // is 3d point
let Gpows = undefined; // precomputes for base point G
class Point {
    constructor(px, py, pz) {
        this.px = px;
        this.py = py;
        this.pz = pz;
    } //3d=less inversions
    static fromAffine(p) { return new Point(p.x, p.y, 1n); }
    static fromHex(hex) {
        hex = toU8(hex); // convert hex string to Uint8Array
        let p = undefined;
        const head = hex[0], tail = hex.subarray(1); // first byte is prefix, rest is data
        const x = slcNum(tail, 0, fLen), len = hex.length; // next 32 bytes are x coordinate
        if (len === 33 && [0x02, 0x03].includes(head)) { // compressed points: 33b, start
            if (!fe(x))
                err('Point hex invalid: x not FE'); // with byte 0x02 or 0x03. Check if 0<x<P
            let y = sqrt(crv(x)); // x³ + ax + b is right side of equation
            const isYOdd = (y & 1n) === 1n; // y² is equivalent left-side. Calculate y²:
            const headOdd = (head & 1) === 1; // y = √y²; there are two solutions: y, -y
            if (headOdd !== isYOdd)
                y = mod(-y); // determine proper solution
            p = new Point(x, y, 1n); // create point
        } // Uncompressed points: 65b, start with 0x04
        if (len === 65 && head === 0x04)
            p = new Point(x, slcNum(tail, fLen, 2 * fLen), 1n);
        return p ? p.ok() : err('Point is not on curve'); // Verify the result
    }
    static fromPrivateKey(k) { return G.mul(toPriv(k)); } // Create point from a private key.
    get x() { return this.aff().x; } // .x, .y will call expensive toAffine:
    get y() { return this.aff().y; } // should be used with care.
    equals(other) {
        const { px: X1, py: Y1, pz: Z1 } = this;
        const { px: X2, py: Y2, pz: Z2 } = isPoint(other); // isPoint() checks class equality
        const X1Z2 = mod(X1 * Z2), X2Z1 = mod(X2 * Z1);
        const Y1Z2 = mod(Y1 * Z2), Y2Z1 = mod(Y2 * Z1);
        return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
    }
    negate() { return new Point(this.px, mod(-this.py), this.pz); } // Flip point over y coord
    double() { return this.add(this); } // Point doubling: P+P, complete formula.
    add(other) {
        const { px: X1, py: Y1, pz: Z1 } = this; // free formula from Renes-Costello-Batina
        const { px: X2, py: Y2, pz: Z2 } = isPoint(other); // https://eprint.iacr.org/2015/1060, algo 1
        const { a, b } = CURVE; // Cost: 12M + 0S + 3*a + 3*b3 + 23add
        let X3 = 0n, Y3 = 0n, Z3 = 0n;
        const b3 = mod(b * 3n);
        let t0 = mod(X1 * X2), t1 = mod(Y1 * Y2), t2 = mod(Z1 * Z2), t3 = mod(X1 + Y1); // step 1
        let t4 = mod(X2 + Y2); // step 5
        t3 = mod(t3 * t4);
        t4 = mod(t0 + t1);
        t3 = mod(t3 - t4);
        t4 = mod(X1 + Z1);
        let t5 = mod(X2 + Z2); // step 10
        t4 = mod(t4 * t5);
        t5 = mod(t0 + t2);
        t4 = mod(t4 - t5);
        t5 = mod(Y1 + Z1);
        X3 = mod(Y2 + Z2); // step 15
        t5 = mod(t5 * X3);
        X3 = mod(t1 + t2);
        t5 = mod(t5 - X3);
        Z3 = mod(a * t4);
        X3 = mod(b3 * t2); // step 20
        Z3 = mod(X3 + Z3);
        X3 = mod(t1 - Z3);
        Z3 = mod(t1 + Z3);
        Y3 = mod(X3 * Z3);
        t1 = mod(t0 + t0); // step 25
        t1 = mod(t1 + t0);
        t2 = mod(a * t2);
        t4 = mod(b3 * t4);
        t1 = mod(t1 + t2);
        t2 = mod(t0 - t2); // step 30
        t2 = mod(a * t2);
        t4 = mod(t4 + t2);
        t0 = mod(t1 * t4);
        Y3 = mod(Y3 + t0);
        t0 = mod(t5 * t4); // step 35
        X3 = mod(t3 * X3);
        X3 = mod(X3 - t0);
        t0 = mod(t3 * t1);
        Z3 = mod(t5 * Z3);
        Z3 = mod(Z3 + t0); // step 40
        return new Point(X3, Y3, Z3);
    }
    mul(n, safe = true) {
        if (!safe && n === 0n)
            return I; // in unsafe mode, allow zero
        if (!ge(n))
            err('invalid scalar'); // must be 0 < n < CURVE.n
        if (this.equals(G))
            return wNAF(n).p; // use precomputes for base point
        let p = I, f = G; // init result point & fake point
        for (let d = this; n > 0n; d = d.double(), n >>= 1n) { // double-and-add ladder
            if (n & 1n)
                p = p.add(d); // if bit is present, add to point
            else if (safe)
                f = f.add(d); // if not, add to fake for timing safety
        }
        return p;
    }
    mulAddQUns(R, u1, u2) {
        return this.mul(u1, false).add(R.mul(u2, false)).ok(); // Unsafe: do NOT use for stuff related
    } // to private keys. Doesn't use Shamir trick
    toAffine() {
        const { px: x, py: y, pz: z } = this; // (x, y, z) ∋ (x=x/z, y=y/z)
        if (this.equals(I))
            return { x: 0n, y: 0n }; // fast-path for zero point
        if (z === 1n)
            return { x, y }; // if z is 1, pass affine coordinates as-is
        const iz = inv(z); // z^-1: invert z
        if (mod(z * iz) !== 1n)
            err('invalid inverse'); // (z * z^-1) must be 1, otherwise bad math
        return { x: mod(x * iz), y: mod(y * iz) }; // x = x*z^-1; y = y*z^-1
    }
    assertValidity() {
        const { x, y } = this.aff(); // convert to 2d xy affine point.
        if (!fe(x) || !fe(y))
            err('Point invalid: x or y'); // x and y must be in range 0 < n < P
        return mod(y * y) === crv(x) ? // y² = x³ + ax + b, must be equal
            this : err('Point invalid: not on curve');
    }
    multiply(n) { return this.mul(n); } // Aliases to compress code
    aff() { return this.toAffine(); }
    ok() { return this.assertValidity(); }
    toHex(isCompressed = true) {
        const { x, y } = this.aff(); // convert to 2d xy affine point
        const head = isCompressed ? ((y & 1n) === 0n ? '02' : '03') : '04'; // 0x02, 0x03, 0x04 prefix
        return head + n2h(x) + (isCompressed ? '' : n2h(y)); // prefix||x and ||y
    }
    toRawBytes(isCompressed = true) {
        return h2b(this.toHex(isCompressed)); // re-use toHex(), convert hex to bytes
    }
}
Point.BASE = new Point(Gx, Gy, 1n); // Generator / base point
Point.ZERO = new Point(0n, 1n, 0n); // Identity / zero point
const { BASE: G, ZERO: I } = Point; // Generator, identity points
const padh = (n, pad) => n.toString(16).padStart(pad, '0');
const b2h = (b) => Array.from(b).map(e => padh(e, 2)).join(''); // bytes to hex
const h2b = (hex) => {
    const l = hex.length; // error if not string,
    if (!str(hex) || l % 2)
        err('hex invalid 1'); // or has odd length like 3, 5.
    const arr = u8n(l / 2); // create result array
    for (let i = 0; i < arr.length; i++) {
        const j = i * 2;
        const h = hex.slice(j, j + 2); // hexByte. slice is faster than substr
        const b = Number.parseInt(h, 16); // byte, created from string part
        if (Number.isNaN(b) || b < 0)
            err('hex invalid 2'); // byte must be valid 0 <= byte < 256
        arr[i] = b;
    }
    return arr;
};
const b2n = (b) => BigInt('0x' + (b2h(b) || '0')); // bytes to number
const slcNum = (b, from, to) => b2n(b.slice(from, to)); // slice bytes num
const n2b = (num) => {
    return big(num) && num >= 0n && num < B256 ? h2b(padh(num, 2 * fLen)) : err('bigint expected');
};
const n2h = (num) => b2h(n2b(num)); // number to 32b hex
const concatB = (...arrs) => {
    const r = u8n(arrs.reduce((sum, a) => sum + au8(a).length, 0)); // create u8a of summed length
    let pad = 0; // walk through each array,
    arrs.forEach(a => { r.set(a, pad); pad += a.length; }); // ensure they have proper type
    return r;
};
const inv = (num, md = P) => {
    if (num === 0n || md <= 0n)
        err('no inverse n=' + num + ' mod=' + md); // no neg exponent for now
    let a = mod(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
    while (a !== 0n) { // uses euclidean gcd algorithm
        const q = b / a, r = b % a; // not constant-time
        const m = x - u * q, n = y - v * q;
        b = a, a = r, x = u, y = v, u = m, v = n;
    }
    return b === 1n ? mod(x, md) : err('no inverse'); // b is gcd at this point
};
const sqrt = (n) => {
    let r = 1n; // So, a special, fast case. Paper: "Square Roots from 1;24,51,10 to Dan Shanks".
    for (let num = n, e = (P + 1n) / 4n; e > 0n; e >>= 1n) { // powMod: modular exponentiation.
        if (e & 1n)
            r = (r * num) % P; // Uses exponentiation by squaring.
        num = (num * num) % P; // Not constant-time.
    }
    return mod(r * r) === n ? r : err('sqrt invalid'); // check if result is valid
};
const toPriv = (p) => {
    if (!big(p))
        p = b2n(toU8(p, fLen)); // convert to bigint when bytes
    return ge(p) ? p : err('private key out of range'); // check if bigint is in range
};
const moreThanHalfN = (n) => n > (N >> 1n); // if a number is bigger than CURVE.n/2
function getPublicKey(privKey, isCompressed = true) {
    return Point.fromPrivateKey(privKey).toRawBytes(isCompressed); // 33b or 65b output
}
class Signature {
    constructor(r, s, recovery) {
        this.r = r;
        this.s = s;
        this.recovery = recovery;
        this.assertValidity(); // recovery bit is optional when
    } // constructed outside.
    static fromCompact(hex) {
        hex = toU8(hex, 64); // compact repr is (32b r)||(32b s)
        return new Signature(slcNum(hex, 0, fLen), slcNum(hex, fLen, 2 * fLen));
    }
    assertValidity() { return ge(this.r) && ge(this.s) ? this : err(); } // 0 < r or s < CURVE.n
    addRecoveryBit(rec) { return new Signature(this.r, this.s, rec); }
    hasHighS() { return moreThanHalfN(this.s); }
    recoverPublicKey(msgh) {
        const { r, s, recovery: rec } = this; // secg.org/sec1-v2.pdf 4.1.6
        if (![0, 1, 2, 3].includes(rec))
            err('recovery id invalid'); // check recovery id
        const h = bits2int_modN(toU8(msgh, 32)); // Truncate hash
        const radj = rec === 2 || rec === 3 ? r + N : r; // If rec was 2 or 3, q.x is bigger than n
        if (radj >= P)
            err('q.x invalid'); // ensure q.x is still a field element
        const head = (rec & 1) === 0 ? '02' : '03'; // head is 0x02 or 0x03
        const R = Point.fromHex(head + n2h(radj)); // concat head + hex repr of r
        const ir = inv(radj, N); // r^-1
        const u1 = mod(-h * ir, N); // -hr^-1
        const u2 = mod(s * ir, N); // sr^-1
        return G.mulAddQUns(R, u1, u2); // (sr^-1)R-(hr^-1)G = -(hr^-1)G + (sr^-1)
    }
    toCompactRawBytes() { return h2b(this.toCompactHex()); } // Uint8Array 64b compact repr
    toCompactHex() { return n2h(this.r) + n2h(this.s); } // hex 64b compact repr
}
const bits2int = (bytes) => {
    const delta = bytes.length * 8 - 256; // RFC suggests optional truncating via bits2octets
    const num = b2n(bytes); // FIPS 186-4 4.6 suggests the leftmost min(nBitLen, outLen) bits, which
    return delta > 0 ? num >> BigInt(delta) : num; // matches bits2int. bits2int can produce res>N.
};
const bits2int_modN = (bytes) => {
    return mod(bits2int(bytes), N); // with 0: BAD for trunc as per RFC vectors
};
const i2o = (num) => n2b(num); // int to octets
const cr = () => // We support: 1) browsers 2) node.js 19+ 3) deno, other envs with crypto
 typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined;
let _hmacSync; // Can be redefined by use in utils; built-ins don't provide it
const optS = { lowS: true }; // opts for sign()
const optV = { lowS: true }; // standard opts for verify()
function prepSig(msgh, priv, opts = optS) {
    if (['der', 'recovered', 'canonical'].some(k => k in opts)) // Ban legacy options
        err('sign() legacy options not supported');
    let { lowS } = opts; // generates low-s sigs by default
    if (lowS == null)
        lowS = true; // RFC6979 3.2: we skip step A
    const h1i = bits2int_modN(toU8(msgh)); // msg bigint
    const h1o = i2o(h1i); // msg octets
    const d = toPriv(priv); // validate private key, convert to bigint
    const seed = [i2o(d), h1o]; // Step D of RFC6979 3.2
    let ent = opts.extraEntropy; // RFC6979 3.6: additional k' (optional)
    if (ent) { // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1) || k')
        if (ent === true)
            ent = etc.randomBytes(fLen); // if true, use CSPRNG to generate data
        const e = toU8(ent); // convert Hex|Bytes to Bytes
        if (e.length !== fLen)
            err(); // Expected 32 bytes of extra data
        seed.push(e);
    }
    const m = h1i; // convert msg to bigint
    const k2sig = (kBytes) => {
        const k = bits2int(kBytes); // RFC6979 method.
        if (!ge(k))
            return; // Check 0 < k < CURVE.n
        const ik = inv(k, N); // k^-1 mod n, NOT mod P
        const q = G.mul(k).aff(); // q = Gk
        const r = mod(q.x, N); // r = q.x mod n
        if (r === 0n)
            return; // r=0 invalid
        const s = mod(ik * mod(m + mod(d * r, N), N), N); // s = k^-1(m + rd) mod n
        if (s === 0n)
            return; // s=0 invalid
        let normS = s; // normalized S
        let rec = (q.x === r ? 0 : 2) | Number(q.y & 1n); // recovery bit
        if (lowS && moreThanHalfN(s)) { // if lowS was passed, ensure s is always
            normS = mod(-s, N); // in the bottom half of CURVE.n
            rec ^= 1;
        }
        return new Signature(r, normS, rec); // use normS, not s
    };
    return { seed: concatB(...seed), k2sig };
}
function hmacDrbg(asynchronous) {
    let v = u8n(fLen); // Minimal non-full-spec HMAC-DRBG from NIST 800-90 for RFC6979 sigs.
    let k = u8n(fLen); // Steps B, C of RFC6979 3.2: set hashLen, in our case always same
    let i = 0; // Iterations counter, will throw when over 1000
    const reset = () => { v.fill(1); k.fill(0); i = 0; };
    const _e = 'drbg: tried 1000 values';
    if (asynchronous) { // asynchronous=true
        const h = (...b) => etc.hmacSha256Async(k, v, ...b); // hmac(k)(v, ...values)
        const reseed = async (seed = u8n()) => {
            k = await h(u8n([0x00]), seed); // k = hmac(K || V || 0x00 || seed)
            v = await h(); // v = hmac(K || V)
            if (seed.length === 0)
                return;
            k = await h(u8n([0x01]), seed); // k = hmac(K || V || 0x01 || seed)
            v = await h(); // v = hmac(K || V)
        };
        const gen = async () => {
            if (i++ >= 1000)
                err(_e);
            v = await h(); // v = hmac(K || V)
            return v;
        };
        return async (seed, pred) => {
            reset(); // the returned fn, don't, it's: 1. slower (JIT). 2. unsafe (async race conditions)
            await reseed(seed); // Steps D-G
            let res = undefined; // Step H: grind until k is in [1..n-1]
            while (!(res = pred(await gen())))
                await reseed(); // test predicate until it returns ok
            reset();
            return res;
        };
    }
    else {
        const h = (...b) => {
            const f = _hmacSync;
            if (!f)
                err('etc.hmacSha256Sync not set');
            return f(k, v, ...b); // hmac(k)(v, ...values)
        };
        const reseed = (seed = u8n()) => {
            k = h(u8n([0x00]), seed); // k = hmac(k || v || 0x00 || seed)
            v = h(); // v = hmac(k || v)
            if (seed.length === 0)
                return;
            k = h(u8n([0x01]), seed); // k = hmac(k || v || 0x01 || seed)
            v = h(); // v = hmac(k || v)
        };
        const gen = () => {
            if (i++ >= 1000)
                err(_e);
            v = h(); // v = hmac(k || v)
            return v;
        };
        return (seed, pred) => {
            reset();
            reseed(seed); // Steps D-G
            let res = undefined; // Step H: grind until k is in [1..n-1]
            while (!(res = pred(gen())))
                reseed(); // test predicate until it returns ok
            reset();
            return res;
        };
    }
}
// ECDSA signature generation. via secg.org/sec1-v2.pdf 4.1.2 + RFC6979 deterministic k
async function signAsync(msgh, priv, opts = optS) {
    const { seed, k2sig } = prepSig(msgh, priv, opts); // Extract arguments for hmac-drbg
    return hmacDrbg(true)(seed, k2sig); // Re-run hmac-drbg until k2sig returns ok
}
function sign(msgh, priv, opts = optS) {
    const { seed, k2sig } = prepSig(msgh, priv, opts); // Extract arguments for hmac-drbg
    return hmacDrbg(false)(seed, k2sig); // Re-run hmac-drbg until k2sig returns ok
}
function verify(sig, msgh, pub, opts = optV) {
    let { lowS } = opts; // ECDSA signature verification
    if (lowS == null)
        lowS = true; // Default lowS=true
    if ('strict' in opts)
        err('verify() legacy options not supported'); // legacy param
    let sig_, h, P; // secg.org/sec1-v2.pdf 4.1.4
    const rs = sig && typeof sig === 'object' && 'r' in sig; // Previous ver supported DER sigs. We
    if (!rs && (toU8(sig).length !== 2 * fLen)) // throw error when DER is suspected now.
        err('signature must be 64 bytes');
    try {
        sig_ = rs ? new Signature(sig.r, sig.s).assertValidity() : Signature.fromCompact(sig);
        h = bits2int_modN(toU8(msgh, fLen)); // Truncate hash
        P = pub instanceof Point ? pub.ok() : Point.fromHex(pub); // Validate public key
    }
    catch (e) {
        return false;
    } // Check sig for validity in both cases
    if (!sig_)
        return false;
    const { r, s } = sig_;
    if (lowS && moreThanHalfN(s))
        return false; // lowS bans sig.s >= CURVE.n/2
    let R;
    try {
        const is = inv(s, N); // s^-1
        const u1 = mod(h * is, N); // u1 = hs^-1 mod n
        const u2 = mod(r * is, N); // u2 = rs^-1 mod n
        R = G.mulAddQUns(P, u1, u2).aff(); // R = u1⋅G + u2⋅P
    }
    catch (error) {
        return false;
    }
    if (!R)
        return false; // stop if R is identity / zero point
    const v = mod(R.x, N); // <== The weird ECDSA part. R.x must be in N's field, not P's
    return v === r; // mod(R.x, n) == r
}
function getSharedSecret(privA, pubB, isCompressed = true) {
    return Point.fromHex(pubB).mul(toPriv(privA)).toRawBytes(isCompressed); // ECDH
}
function hashToPrivateKey(hash) {
    hash = toU8(hash); // produces private keys with modulo bias
    const minLen = fLen + 8; // being neglible.
    if (hash.length < minLen || hash.length > 1024)
        err('expected proper params');
    const num = mod(b2n(hash), N - 1n) + 1n; // takes at least n+8 bytes
    return n2b(num);
}
const etc = {
    hexToBytes: h2b, bytesToHex: b2h,
    concatBytes: concatB, bytesToNumberBE: b2n, numberToBytesBE: n2b,
    mod, invert: inv,
    hmacSha256Async: async (key, ...msgs) => {
        const crypto = cr(); // HMAC-SHA256 async. No sync built-in!
        if (!crypto)
            return err('etc.hmacSha256Async not set'); // Uses webcrypto: native cryptography.
        const s = crypto.subtle;
        const k = await s.importKey('raw', key, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign']);
        return u8n(await s.sign('HMAC', k, concatB(...msgs)));
    },
    hmacSha256Sync: _hmacSync,
    hashToPrivateKey,
    randomBytes: (len) => {
        const crypto = cr(); // Can be shimmed in node.js <= 18 to prevent error:
        // import { webcrypto } from 'node:crypto';
        // if (!globalThis.crypto) globalThis.crypto = webcrypto;
        if (!crypto)
            err('crypto.getRandomValues must be defined');
        return crypto.getRandomValues(u8n(len));
    },
};
const utils = {
    normPrivateKeyToScalar: toPriv,
    isValidPrivateKey: (key) => { try {
        return !!toPriv(key);
    }
    catch (e) {
        return false;
    } },
    randomPrivateKey: () => hashToPrivateKey(etc.randomBytes(fLen + 8)),
    precompute(w = 8, p = G) { p.multiply(3n); return p; }, // no-op
};
Object.defineProperties(etc, { hmacSha256Sync: {
        configurable: false, get() { return _hmacSync; }, set(f) { if (!_hmacSync)
            _hmacSync = f; },
    } });
const W = 8; // Precomputes-related code. W = window size
const precompute = () => {
    const points = []; // 10x sign(), 2x verify(). To achieve this,
    const windows = 256 / W + 1; // app needs to spend 40ms+ to calculate
    let p = G, b = p; // a lot of points related to base point G.
    for (let w = 0; w < windows; w++) { // Points are stored in array and used
        b = p; // any time Gx multiplication is done.
        points.push(b); // They consume 16-32 MiB of RAM.
        for (let i = 1; i < 2 ** (W - 1); i++) {
            b = b.add(p);
            points.push(b);
        }
        p = b.double(); // Precomputes don't speed-up getSharedKey,
    } // which multiplies user point by scalar,
    return points; // when precomputes are using base point
};
const wNAF = (n) => {
    // Compared to other point mult methods,
    const comp = Gpows || (Gpows = precompute()); // stores 2x less points using subtraction
    const neg = (cnd, p) => { let n = p.negate(); return cnd ? n : p; }; // negate
    let p = I, f = G; // f must be G, or could become I in the end
    const windows = 1 + 256 / W; // W=8 17 windows
    const wsize = 2 ** (W - 1); // W=8 128 window size
    const mask = BigInt(2 ** W - 1); // W=8 will create mask 0b11111111
    const maxNum = 2 ** W; // W=8 256
    const shiftBy = BigInt(W); // W=8 8
    for (let w = 0; w < windows; w++) {
        const off = w * wsize;
        let wbits = Number(n & mask); // extract W bits.
        n >>= shiftBy; // shift number by W bits.
        if (wbits > wsize) {
            wbits -= maxNum;
            n += 1n;
        } // split if bits > max: +224 => 256-32
        const off1 = off, off2 = off + Math.abs(wbits) - 1; // offsets, evaluate both
        const cnd1 = w % 2 !== 0, cnd2 = wbits < 0; // conditions, evaluate both
        if (wbits === 0) {
            f = f.add(neg(cnd1, comp[off1])); // bits are 0: add garbage to fake point
        }
        else { //          ^ can't add off2, off2 = I
            p = p.add(neg(cnd2, comp[off2])); // bits are 1: add to result point
        }
    }
    return { p, f }; // return both real and fake points for JIT
}; // !! you can disable precomputes by commenting-out call of the wNAF() inside Point#mul()
export { getPublicKey, sign, signAsync, verify, CURVE, // Remove the export to easily use in REPL
getSharedSecret, etc, utils, Point as ProjectivePoint, Signature }; // envs like browser console
