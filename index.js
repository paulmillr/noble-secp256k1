/*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
/**
 * 4KB JS implementation of secp256k1 ECDSA / Schnorr signatures & ECDH.
 * Compliant with RFC6979 & BIP340.
 * @module
 */
/**
 * Curve params. secp256k1 is short weierstrass / koblitz curve. Equation is y² == x³ + ax + b.
 * * P = `2n**256n-2n**32n-2n**977n` // field over which calculations are done
 * * N = `2n**256n - 0x14551231950b75fc4402da1732fc9bebfn` // group order, amount of curve points
 * * h = `1n` // cofactor
 * * a = `0n` // equation param
 * * b = `7n` // equation param
 * * Gx, Gy are coordinates of Generator / base point
 */
const secp256k1_CURVE = {
    p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
    n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
    h: 1n,
    a: 0n,
    b: 7n,
    Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
    Gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
};
const { p: P, n: N, Gx, Gy, b: _b } = secp256k1_CURVE;
const L = 32; // field / group byte length
const L2 = 64;
// Helpers and Precomputes sections are reused between libraries
// ## Helpers
// ----------
// error helper, messes-up stack trace
const err = (m = '') => {
    throw new Error(m);
};
const isBig = (n) => typeof n === 'bigint'; // is big integer
const isStr = (s) => typeof s === 'string'; // is string
const isBytes = (a) => a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
/** assert is Uint8Array (of specific length) */
const abytes = (a, l) => !isBytes(a) || (typeof l === 'number' && l > 0 && a.length !== l)
    ? err('Uint8Array expected')
    : a;
/** create Uint8Array */
const u8n = (len) => new Uint8Array(len);
const u8fr = (buf) => Uint8Array.from(buf);
const padh = (n, pad) => n.toString(16).padStart(pad, '0');
const bytesToHex = (b) => Array.from(abytes(b))
    .map((e) => padh(e, 2))
    .join('');
const C = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 }; // ASCII characters
const _ch = (ch) => {
    if (ch >= C._0 && ch <= C._9)
        return ch - C._0; // '2' => 50-48
    if (ch >= C.A && ch <= C.F)
        return ch - (C.A - 10); // 'B' => 66-(65-10)
    if (ch >= C.a && ch <= C.f)
        return ch - (C.a - 10); // 'b' => 98-(97-10)
    return;
};
const hexToBytes = (hex) => {
    const e = 'hex invalid';
    if (!isStr(hex))
        return err(e);
    const hl = hex.length;
    const al = hl / 2;
    if (hl % 2)
        return err(e);
    const array = u8n(al);
    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
        // treat each char as ASCII
        const n1 = _ch(hex.charCodeAt(hi)); // parse first char, multiply it by 16
        const n2 = _ch(hex.charCodeAt(hi + 1)); // parse second char
        if (n1 === undefined || n2 === undefined)
            return err(e);
        array[ai] = n1 * 16 + n2; // example: 'A9' => 10*16 + 9
    }
    return array;
};
/** normalize hex or ui8a to ui8a */
const toU8 = (a, len) => abytes(isStr(a) ? hexToBytes(a) : u8fr(abytes(a)), len);
const cr = () => globalThis?.crypto; // WebCrypto is available in all modern environments
const subtle = () => cr()?.subtle ?? err('crypto.subtle must be defined');
// prettier-ignore
const concatBytes = (...arrs) => {
    const r = u8n(arrs.reduce((sum, a) => sum + abytes(a).length, 0)); // create u8a of summed length
    let pad = 0; // walk through each array,
    arrs.forEach(a => { r.set(a, pad); pad += a.length; }); // ensure they have proper type
    return r;
};
/** WebCrypto OS-level CSPRNG (random number generator). Will throw when not available. */
const randomBytes = (len = L) => {
    const c = cr();
    return c.getRandomValues(u8n(len));
};
const big = BigInt;
const arange = (n, min, max, msg = 'bad number: out of range') => isBig(n) && min <= n && n < max ? n : err(msg);
/** modular division */
const M = (a, b = P) => {
    const r = a % b;
    return r >= 0n ? r : b + r;
};
const modN = (a) => M(a, N);
/** Modular inversion using eucledian GCD (non-CT). No negative exponent for now. */
// prettier-ignore
const invert = (num, md) => {
    if (num === 0n || md <= 0n)
        err('no inverse n=' + num + ' mod=' + md);
    let a = M(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
    while (a !== 0n) {
        const q = b / a, r = b % a;
        const m = x - u * q, n = y - v * q;
        b = a, a = r, x = u, y = v, u = m, v = n;
    }
    return b === 1n ? M(x, md) : err('no inverse'); // b is gcd at this point
};
const callHash = (name) => {
    // @ts-ignore
    const fn = etc[name];
    if (typeof fn !== 'function')
        err('hashes.' + name + ' not set');
    return fn;
};
const apoint = (p) => (p instanceof Point ? p : err('Point expected'));
// ## End of Helpers
// -----------------
/** secp256k1 formula. Koblitz curves are subclass of weierstrass curves with a=0, making it x³+b */
const koblitz = (x) => M(M(x * x) * x + _b);
/** assert is field element or 0 */
const afield0 = (n) => arange(n, 0n, P);
/** assert is field element */
const afield = (n) => arange(n, 1n, P);
/** assert is group elem */
const agroup = (n) => arange(n, 1n, N);
const isEven = (y) => (y & 1n) === 0n;
/** create Uint8Array of byte n */
const u8of = (n) => Uint8Array.of(n);
const getPrefix = (y) => u8of(isEven(y) ? 0x02 : 0x03);
/** lift_x from BIP340 calculates square root. Validates x, then validates root*root. */
const lift_x = (x) => {
    // Let c = x³ + 7 mod p. Fail if x ≥ p. (also fail if x < 1)
    const c = koblitz(afield(x));
    // c = √y
    // y = c^((p+1)/4) mod p
    // This formula works for fields p = 3 mod 4 -- a special, fast case.
    // Paper: "Square Roots from 1;24,51,10 to Dan Shanks".
    let r = 1n;
    for (let num = c, e = (P + 1n) / 4n; e > 0n; e >>= 1n) {
        // powMod: modular exponentiation.
        if (e & 1n)
            r = (r * num) % P; // Uses exponentiation by squaring.
        num = (num * num) % P; // Not constant-time.
    }
    return M(r * r) === c ? r : err('sqrt invalid'); // check if result is valid
};
/** Point in 3d xyz projective coordinates. 3d takes less inversions than 2d. */
class Point {
    static BASE;
    static ZERO;
    px;
    py;
    pz;
    constructor(px, py, pz) {
        this.px = afield0(px);
        this.py = afield(py); // y can't be 0 in Projective
        this.pz = afield0(pz);
        Object.freeze(this);
    }
    /** Convert Uint8Array or hex string to Point. */
    static fromBytes(bytes) {
        abytes(bytes);
        let p = undefined;
        // First byte is prefix, rest is data. There are 2 kinds: compressed & uncompressed:
        // * [0x02 or 0x03][32-byte x coordinate]
        // * [0x04]        [32-byte x coordinate][32-byte y coordinate]
        const head = bytes[0];
        const tail = bytes.subarray(1);
        const x = sliceBytesNumBE(tail, 0, L);
        const len = bytes.length;
        // Compressed 33-byte point, 0x02 or 0x03 prefix
        if (len === L + 1 && [0x02, 0x03].includes(head)) {
            // Equation is y² == x³ + ax + b. We calculate y from x.
            // y = √y²; there are two solutions: y, -y. Determine proper solution based on prefix
            let y = lift_x(x);
            const evenY = isEven(y);
            const evenH = isEven(big(head));
            if (evenH !== evenY)
                y = M(-y);
            p = new Point(x, y, 1n);
        }
        // Uncompressed 65-byte point, 0x04 prefix
        if (len === L2 + 1 && head === 0x04)
            p = new Point(x, sliceBytesNumBE(tail, L, L2), 1n);
        // Validate point
        return p ? p.assertValidity() : err('bad point: not on curve');
    }
    /** Equality check: compare points P&Q. */
    equals(other) {
        const { px: X1, py: Y1, pz: Z1 } = this;
        const { px: X2, py: Y2, pz: Z2 } = apoint(other); // checks class equality
        const X1Z2 = M(X1 * Z2);
        const X2Z1 = M(X2 * Z1);
        const Y1Z2 = M(Y1 * Z2);
        const Y2Z1 = M(Y2 * Z1);
        return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
    }
    is0() {
        return this.equals(I);
    }
    /** Flip point over y coordinate. */
    negate() {
        return new Point(this.px, M(-this.py), this.pz);
    }
    /** Point doubling: P+P, complete formula. */
    double() {
        return this.add(this);
    }
    /**
     * Point addition: P+Q, complete, exception-free formula
     * (Renes-Costello-Batina, algo 1 of [2015/1060](https://eprint.iacr.org/2015/1060)).
     * Cost: `12M + 0S + 3*a + 3*b3 + 23add`.
     */
    // prettier-ignore
    add(other) {
        const { px: X1, py: Y1, pz: Z1 } = this;
        const { px: X2, py: Y2, pz: Z2 } = apoint(other);
        const a = 0n;
        const b = _b;
        let X3 = 0n, Y3 = 0n, Z3 = 0n;
        const b3 = M(b * 3n);
        let t0 = M(X1 * X2), t1 = M(Y1 * Y2), t2 = M(Z1 * Z2), t3 = M(X1 + Y1); // step 1
        let t4 = M(X2 + Y2); // step 5
        t3 = M(t3 * t4);
        t4 = M(t0 + t1);
        t3 = M(t3 - t4);
        t4 = M(X1 + Z1);
        let t5 = M(X2 + Z2); // step 10
        t4 = M(t4 * t5);
        t5 = M(t0 + t2);
        t4 = M(t4 - t5);
        t5 = M(Y1 + Z1);
        X3 = M(Y2 + Z2); // step 15
        t5 = M(t5 * X3);
        X3 = M(t1 + t2);
        t5 = M(t5 - X3);
        Z3 = M(a * t4);
        X3 = M(b3 * t2); // step 20
        Z3 = M(X3 + Z3);
        X3 = M(t1 - Z3);
        Z3 = M(t1 + Z3);
        Y3 = M(X3 * Z3);
        t1 = M(t0 + t0); // step 25
        t1 = M(t1 + t0);
        t2 = M(a * t2);
        t4 = M(b3 * t4);
        t1 = M(t1 + t2);
        t2 = M(t0 - t2); // step 30
        t2 = M(a * t2);
        t4 = M(t4 + t2);
        t0 = M(t1 * t4);
        Y3 = M(Y3 + t0);
        t0 = M(t5 * t4); // step 35
        X3 = M(t3 * X3);
        X3 = M(X3 - t0);
        t0 = M(t3 * t1);
        Z3 = M(t5 * Z3);
        Z3 = M(Z3 + t0); // step 40
        return new Point(X3, Y3, Z3);
    }
    /**
     * Point-by-scalar multiplication. Scalar must be in range 1 <= n < CURVE.n.
     * Uses {@link wNAF} for base point.
     * Uses fake point to mitigate side-channel leakage.
     * @param n scalar by which point is multiplied
     * @param safe safe mode guards against timing attacks; unsafe mode is faster
     */
    multiply(n, safe = true) {
        if (!safe && n === 0n)
            return I;
        agroup(n);
        if (n === 1n)
            return this;
        if (this.equals(G))
            return wNAF(n).p;
        // init result point & fake point
        let p = I;
        let f = G;
        for (let d = this; n > 0n; d = d.double(), n >>= 1n) {
            // if bit is present, add to point
            // if not present, add to fake, for timing safety
            if (n & 1n)
                p = p.add(d);
            else if (safe)
                f = f.add(d);
        }
        return p;
    }
    /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
    toAffine() {
        const { px: x, py: y, pz: z } = this;
        // fast-paths for ZERO point OR Z=1
        if (this.equals(I))
            return { x: 0n, y: 0n };
        if (z === 1n)
            return { x, y };
        const iz = invert(z, P);
        // (Z * Z^-1) must be 1, otherwise bad math
        if (M(z * iz) !== 1n)
            err('inverse invalid');
        // x = X*Z^-1; y = Y*Z^-1
        return { x: M(x * iz), y: M(y * iz) };
    }
    /** Checks if the point is valid and on-curve. */
    assertValidity() {
        const { x, y } = this.toAffine(); // convert to 2d xy affine point.
        afield(x); // must be in range 1 <= x,y < P
        afield(y);
        // y² == x³ + ax + b, equation sides must be equal
        return M(y * y) === koblitz(x) ? this : err('bad point: not on curve');
    }
    /** Converts point to 33/65-byte Uint8Array. */
    toBytes(isCompressed = true) {
        const { x, y } = this.assertValidity().toAffine();
        const x32b = numTo32b(x);
        if (isCompressed)
            return concatBytes(getPrefix(y), x32b);
        return concatBytes(u8of(0x04), x32b, numTo32b(y));
    }
    /** Create 3d xyz point from 2d xy. (0, 0) => (0, 1, 0), not (0, 0, 1) */
    static fromAffine(ap) {
        const { x, y } = ap;
        return x === 0n && y === 0n ? I : new Point(x, y, 1n);
    }
    toHex(isCompressed) {
        return bytesToHex(this.toBytes(isCompressed));
    }
    static fromPrivateKey(k) {
        return G.multiply(toPrivScalar(k));
    }
    static fromHex(hex) {
        return Point.fromBytes(toU8(hex));
    }
    get x() {
        return this.toAffine().x;
    }
    get y() {
        return this.toAffine().y;
    }
    toRawBytes(isCompressed) {
        return this.toBytes(isCompressed);
    }
}
/** Generator / base point */
const G = new Point(Gx, Gy, 1n);
/** Identity / zero point */
const I = new Point(0n, 1n, 0n);
// Static aliases
Point.BASE = G;
Point.ZERO = I;
/** `Q = u1⋅G + u2⋅R`. Verifies Q is not ZERO. Unsafe: non-CT. */
const doubleScalarMulUns = (R, u1, u2) => {
    return G.multiply(u1, false).add(R.multiply(u2, false)).assertValidity();
};
const bytesToNumBE = (b) => big('0x' + (bytesToHex(b) || '0'));
const sliceBytesNumBE = (b, from, to) => bytesToNumBE(b.subarray(from, to));
const B256 = 2n ** 256n; // secp256k1 is weierstrass curve. Equation is x³ + ax + b.
/** Number to 32b. Must be 0 <= num < B256. validate, pad, to bytes. */
const numTo32b = (num) => hexToBytes(padh(arange(num, 0n, B256), L2));
/** Normalize private key to scalar (bigint). Verifies scalar is in range 1<s<N */
const toPrivScalar = (pr) => {
    const num = isBig(pr) ? pr : bytesToNumBE(toU8(pr, L));
    return arange(num, 1n, N, 'private key invalid 3');
};
/** For Signature malleability, validates sig.s is bigger than N/2. */
const highS = (n) => n > N >> 1n;
/** Creates 33/65-byte public key from 32-byte private key. */
const getPublicKey = (privKey, isCompressed = true) => {
    return G.multiply(toPrivScalar(privKey)).toBytes(isCompressed);
};
/** ECDSA Signature class. Supports only compact 64-byte representation, not DER. */
class Signature {
    r;
    s;
    recovery;
    constructor(r, s, recovery) {
        this.r = agroup(r); // 1 <= r < N
        this.s = agroup(s); // 1 <= s < N
        if (recovery != null)
            this.recovery = recovery;
        Object.freeze(this);
    }
    /** Create signature from 64b compact (r || s) representation. */
    static fromBytes(b) {
        abytes(b, L2);
        const r = sliceBytesNumBE(b, 0, L);
        const s = sliceBytesNumBE(b, L, L2);
        return new Signature(r, s);
    }
    toBytes() {
        const { r, s } = this;
        return concatBytes(numTo32b(r), numTo32b(s));
    }
    /** Copy signature, with newly added recovery bit. */
    addRecoveryBit(bit) {
        return new Signature(this.r, this.s, bit);
    }
    hasHighS() {
        return highS(this.s);
    }
    toCompactRawBytes() {
        return this.toBytes();
    }
    toCompactHex() {
        return bytesToHex(this.toBytes());
    }
    recoverPublicKey(msg) {
        return recoverPublicKey(this, msg);
    }
    static fromCompact(hex) {
        return Signature.fromBytes(toU8(hex, L2));
    }
    assertValidity() {
        return this;
    }
    normalizeS() {
        const { r, s, recovery } = this;
        return highS(s) ? new Signature(r, modN(-s), recovery) : this;
    }
}
/**
 * RFC6979: ensure ECDSA msg is X bytes, convert to BigInt.
 * RFC suggests optional truncating via bits2octets.
 * FIPS 186-4 4.6 suggests the leftmost min(nBitLen, outLen) bits,
 * which matches bits2int. bits2int can produce res>N.
 */
const bits2int = (bytes) => {
    const delta = bytes.length * 8 - 256;
    if (delta > 1024)
        err('msg invalid'); // our CUSTOM check, "just-in-case": prohibit long inputs
    const num = bytesToNumBE(bytes);
    return delta > 0 ? num >> big(delta) : num;
};
/** int2octets can't be used; pads small msgs with 0: BAD for truncation as per RFC vectors */
const bits2int_modN = (bytes) => modN(bits2int(abytes(bytes)));
const signOpts = { lowS: true };
const veriOpts = { lowS: true };
// RFC6979 signature generation, preparation step.
const prepSig = (msgh, priv, opts = signOpts) => {
    if (['der', 'recovered', 'canonical'].some((k) => k in opts))
        // legacy opts
        err('option not supported');
    let { lowS, extraEntropy } = opts; // generates low-s sigs by default
    if (lowS == null)
        lowS = true; // RFC6979 3.2: we skip step A
    const i2o = numTo32b; // int to octets
    const h1i = bits2int_modN(toU8(msgh)); // msg bigint
    const h1o = i2o(h1i); // msg octets
    const d = toPrivScalar(priv); // validate private key, convert to bigint
    const seed = [i2o(d), h1o]; // Step D of RFC6979 3.2
    /** RFC6979 3.6: additional k' (optional). See {@link ExtraEntropy}. */
    // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1) || k')
    if (extraEntropy)
        seed.push(extraEntropy === true ? randomBytes(L) : toU8(extraEntropy));
    const m = h1i; // convert msg to bigint
    // Converts signature params into point w r/s, checks result for validity.
    // To transform k => Signature:
    // q = k⋅G
    // r = q.x mod n
    // s = k^-1(m + rd) mod n
    const k2sig = (kBytes) => {
        // RFC 6979 Section 3.2, step 3: k = bits2int(T)
        // Important: all mod() calls here must be done over N
        const k = bits2int(kBytes);
        if (!(1n <= k && k < N))
            return; // Check 0 < k < CURVE.n
        const q = G.multiply(k).toAffine(); // q = k⋅G
        const r = modN(q.x); // r = q.x mod n
        if (r === 0n)
            return;
        const ik = invert(k, N); // k^-1 mod n, NOT mod P
        const s = modN(ik * modN(m + modN(d * r))); // s = k^-1(m + rd) mod n
        if (s === 0n)
            return;
        let normS = s; // normalized S
        let recovery = (q.x === r ? 0 : 2) | Number(q.y & 1n); // recovery bit (2 or 3, when q.x > n)
        if (lowS && highS(s)) {
            // if lowS was passed, ensure s is always
            normS = modN(-s); // in the bottom half of CURVE.n
            recovery ^= 1;
        }
        return new Signature(r, normS, recovery); // use normS, not s
    };
    return { seed: concatBytes(...seed), k2sig };
};
// HMAC-DRBG from NIST 800-90. Minimal, non-full-spec - used for RFC6979 signatures.
const hmacDrbg = (asynchronous) => {
    let v = u8n(L); // Steps B, C of RFC6979 3.2: set hashLen
    let k = u8n(L); // In our case, it's always equal to L
    let i = 0; // Iterations counter, will throw when over max
    const NULL = u8n(0);
    const reset = () => {
        v.fill(1);
        k.fill(0);
        i = 0;
    };
    const max = 1000;
    const _e = 'drbg: tried 1000 values';
    if (asynchronous) {
        // asynchronous=true
        // h = hmac(K || V || ...)
        const h = (...b) => etc.hmacSha256Async(k, v, ...b);
        const reseed = async (seed = NULL) => {
            // HMAC-DRBG reseed() function. Steps D-G
            k = await h(u8of(0x00), seed); // k = hmac(K || V || 0x00 || seed)
            v = await h(); // v = hmac(K || V)
            if (seed.length === 0)
                return;
            k = await h(u8of(0x01), seed); // k = hmac(K || V || 0x01 || seed)
            v = await h(); // v = hmac(K || V)
        };
        // HMAC-DRBG generate() function
        const gen = async () => {
            if (i++ >= max)
                err(_e);
            v = await h(); // v = hmac(K || V)
            return v; // this diverges from noble-curves: we don't allow arbitrary output len!
        };
        // Do not reuse returned fn for more than 1 sig:
        // 1) it's slower (JIT screws up). 2. unsafe (async race conditions)
        return async (seed, pred) => {
            reset();
            await reseed(seed); // Steps D-G
            let res = undefined; // Step H: grind until k is in [1..n-1]
            while (!(res = pred(await gen())))
                await reseed(); // test predicate until it returns ok
            reset();
            return res;
        };
    }
    else {
        // asynchronous=false; same as above, but synchronous
        // h = hmac(K || V || ...)
        const h = (...b) => callHash('hmacSha256Sync')(k, v, ...b);
        const reseed = (seed = NULL) => {
            // HMAC-DRBG reseed() function. Steps D-G
            k = h(u8of(0x00), seed); // k = hmac(k || v || 0x00 || seed)
            v = h(); // v = hmac(k || v)
            if (seed.length === 0)
                return;
            k = h(u8of(0x01), seed); // k = hmac(k || v || 0x01 || seed)
            v = h(); // v = hmac(k || v)
        };
        // HMAC-DRBG generate() function
        const gen = () => {
            if (i++ >= max)
                err(_e);
            v = h(); // v = hmac(k || v)
            return v; // this diverges from noble-curves: we don't allow arbitrary output len!
        };
        // Do not reuse returned fn for more than 1 sig:
        // 1) it's slower (JIT screws up). 2. unsafe (async race conditions)
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
};
/**
 * Sign a msg hash using secp256k1. Async.
 * Follows [SEC1](https://secg.org/sec1-v2.pdf) 4.1.2 & RFC6979.
 * It's suggested to enable hedging ({@link ExtraEntropy}) to prevent fault attacks.
 * @param msgh - message HASH, not message itself e.g. sha256(message)
 * @param priv - private key
 * @param opts - `lowS: true` prevents malleability, `extraEntropy: true` enables hedging
 */
const signAsync = async (msgh, priv, opts = signOpts) => {
    // Re-run drbg until k2sig returns ok
    const { seed, k2sig } = prepSig(msgh, priv, opts);
    const sig = await hmacDrbg(true)(seed, k2sig);
    return sig;
};
/**
 * Sign a msg hash using secp256k1.
 * Follows [SEC1](https://secg.org/sec1-v2.pdf) 4.1.2 & RFC6979.
 * It's suggested to enable hedging ({@link ExtraEntropy}) to prevent fault attacks.
 * @param msgh - message HASH, not message itself e.g. sha256(message)
 * @param priv - private key
 * @param opts - `lowS: true` prevents malleability, `extraEntropy: true` enables hedging
 * @example
 * const sig = sign(sha256('hello'), privKey, { extraEntropy: true }).toBytes();
 */
const sign = (msgh, priv, opts = signOpts) => {
    // Re-run drbg until k2sig returns ok
    const { seed, k2sig } = prepSig(msgh, priv, opts);
    const sig = hmacDrbg(false)(seed, k2sig);
    return sig;
};
/**
 * Verify a signature using secp256k1.
 * Follows [SEC1](https://secg.org/sec1-v2.pdf) 4.1.4.
 * Default lowS=true, prevents malleability.
 * @param sig - signature, 64-byte or Signature instance
 * @param msgh - message HASH, not message itself e.g. sha256(message)
 * @param pub - public key
 * @param opts - { lowS: true } is default, prohibits s >= CURVE.n/2 to prevent malleability
 */
const verify = (sig, msgh, pub, opts = veriOpts) => {
    let { lowS } = opts;
    if (lowS == null)
        lowS = true;
    if ('strict' in opts)
        err('option not supported');
    let sigg;
    // Previous ver supported DER sigs.
    // We throw error when DER is suspected now.
    const rs = sig && typeof sig === 'object' && 'r' in sig;
    if (!rs && toU8(sig).length !== L2)
        err('signature must be 64 bytes');
    try {
        sigg = rs ? new Signature(sig.r, sig.s) : Signature.fromCompact(sig);
        const h = bits2int_modN(toU8(msgh)); // Truncate hash
        const P = Point.fromBytes(toU8(pub)); // Validate public key
        const { r, s } = sigg;
        if (lowS && highS(s))
            return false; // lowS bans sig.s >= CURVE.n/2
        const is = invert(s, N); // s^-1
        const u1 = modN(h * is); // u1 = hs^-1 mod n
        const u2 = modN(r * is); // u2 = rs^-1 mod n
        const R = doubleScalarMulUns(P, u1, u2).toAffine(); // R = u1⋅G + u2⋅P
        // Stop if R is identity / zero point. Check is done inside `doubleScalarMulUns`
        const v = modN(R.x); // R.x must be in N's field, not P's
        return v === r; // mod(R.x, n) == r
    }
    catch (error) {
        return false;
    }
};
/**
 * ECDSA public key recovery. Requires msg hash and recovery id.
 * Follows [SEC1](https://secg.org/sec1-v2.pdf) 4.1.6.
 */
const recoverPublicKey = (sig, msgh) => {
    const { r, s, recovery } = sig;
    // 0 or 1 recovery id determines sign of "y" coordinate.
    // 2 or 3 means q.x was >N.
    if (![0, 1, 2, 3].includes(recovery))
        err('recovery id invalid');
    const h = bits2int_modN(toU8(msgh, L)); // Truncate hash
    const radj = recovery === 2 || recovery === 3 ? r + N : r;
    afield(radj); // ensure q.x is still a field element
    const head = getPrefix(big(recovery)); // head is 0x02 or 0x03
    const Rb = concatBytes(head, numTo32b(radj)); // concat head + r
    const R = Point.fromBytes(Rb);
    const ir = invert(radj, N); // r^-1
    const u1 = modN(-h * ir); // -hr^-1
    const u2 = modN(s * ir); // sr^-1
    return doubleScalarMulUns(R, u1, u2); // (sr^-1)R-(hr^-1)G = -(hr^-1)G + (sr^-1)
};
/**
 * Elliptic Curve Diffie-Hellman (ECDH) on secp256k1.
 * Result is **NOT hashed**. Use hash or KDF on it if you need.
 * @param privA private key A
 * @param pubB public key B
 * @param isCompressed 33-byte (true) or 65-byte (false) output
 * @returns public key C
 */
const getSharedSecret = (privA, pubB, isCompressed = true) => {
    return Point.fromBytes(toU8(pubB)).multiply(toPrivScalar(privA)).toBytes(isCompressed);
};
// FIPS 186 B.4.1 compliant key generation produces private keys with modulo bias being neglible.
// takes >N+8 bytes, returns (hash mod n-1)+1
const hashToPrivateKey = (hash) => {
    hash = toU8(hash);
    if (hash.length < L + 8 || hash.length > 1024)
        err('expected 40-1024b');
    const num = M(bytesToNumBE(hash), N - 1n);
    return numTo32b(num + 1n);
};
const randomPrivateKey = () => hashToPrivateKey(randomBytes(L + 16)); // FIPS 186 B.4.1.
const _sha = 'SHA-256';
/** Math, hex, byte helpers. Not in `utils` because utils share API with noble-curves. */
const etc = {
    hexToBytes: hexToBytes,
    bytesToHex: bytesToHex,
    concatBytes: concatBytes,
    bytesToNumberBE: bytesToNumBE,
    numberToBytesBE: numTo32b,
    mod: M,
    invert: invert, // math utilities
    hmacSha256Async: async (key, ...msgs) => {
        const s = subtle();
        const name = 'HMAC';
        const k = await s.importKey('raw', key, { name, hash: { name: _sha } }, false, ['sign']);
        return u8n(await s.sign(name, k, concatBytes(...msgs)));
    },
    hmacSha256Sync: undefined, // For TypeScript. Actual logic is below
    hashToPrivateKey: hashToPrivateKey,
    randomBytes: randomBytes,
};
/** Curve-specific utilities for private keys. */
const utils = {
    normPrivateKeyToScalar: toPrivScalar,
    isValidPrivateKey: (key) => {
        try {
            return !!toPrivScalar(key);
        }
        catch (e) {
            return false;
        }
    },
    randomPrivateKey: randomPrivateKey,
    precompute: (w = 8, p = G) => {
        p.multiply(3n);
        w;
        return p;
    },
};
// ## Precomputes
// --------------
const W = 8; // W is window size
const scalarBits = 256;
const pwindows = Math.ceil(scalarBits / W) + 1; // 33 for W=8
const pwindowSize = 2 ** (W - 1); // 128 for W=8
const precompute = () => {
    const points = [];
    let p = G;
    let b = p;
    for (let w = 0; w < pwindows; w++) {
        b = p;
        points.push(b);
        for (let i = 1; i < pwindowSize; i++) {
            b = b.add(p);
            points.push(b);
        } // i=1, bc we skip 0
        p = b.double();
    }
    return points;
};
let Gpows = undefined; // precomputes for base point G
// const-time negate
const ctneg = (cnd, p) => {
    const n = p.negate();
    return cnd ? n : p;
};
/**
 * Precomputes give 12x faster getPublicKey(), 10x sign(), 2x verify() by
 * caching multiples of G (base point). Cache is stored in 32MB of RAM.
 * Any time `G.multiply` is done, precomputes are used.
 * Not used for getSharedSecret, which instead multiplies random pubkey `P.multiply`.
 *
 * w-ary non-adjacent form (wNAF) precomputation method is 10% slower than windowed method,
 * but takes 2x less RAM. RAM reduction is possible by utilizing `.subtract`.
 *
 * !! Precomputes can be disabled by commenting-out call of the wNAF() inside Point#multiply().
 */
const wNAF = (n) => {
    const comp = Gpows || (Gpows = precompute());
    let p = I;
    let f = G; // f must be G, or could become I in the end
    const pow_2_w = 2 ** W; // 256 for W=8
    const maxNum = pow_2_w; // 256 for W=8
    const mask = big(pow_2_w - 1); // 255 for W=8 == mask 0b11111111
    const shiftBy = big(W); // 8 for W=8
    for (let w = 0; w < pwindows; w++) {
        let wbits = Number(n & mask); // extract W bits.
        n >>= shiftBy; // shift number by W bits.
        if (wbits > pwindowSize) {
            wbits -= maxNum;
            n += 1n;
        } // split if bits > max: +224 => 256-32
        const off = w * pwindowSize;
        const offF = off; // offsets, evaluate both
        const offP = off + Math.abs(wbits) - 1;
        const isEven = w % 2 !== 0; // conditions, evaluate both
        const isNeg = wbits < 0;
        if (wbits === 0) {
            // off == I: can't add it. Adding random offF instead.
            f = f.add(ctneg(isEven, comp[offF])); // bits are 0: add garbage to fake point
        }
        else {
            p = p.add(ctneg(isNeg, comp[offP])); // bits are 1: add to result point
        }
    }
    return { p, f }; // return both real and fake points for JIT
};
// !! Remove the export below to easily use in REPL / browser console
export { secp256k1_CURVE as CURVE, etc, getPublicKey, getSharedSecret, Point, Point as ProjectivePoint, sign, signAsync, Signature, utils, verify, };
