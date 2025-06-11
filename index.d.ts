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
declare const secp256k1_CURVE: WeierstrassOpts<bigint>;
/** Alias to Uint8Array. */
export type Bytes = Uint8Array;
/** Hex-encoded string or Uint8Array. */
export type Hex = Bytes | string;
/** Hex-encoded string, Uint8Array or bigint. */
export type PrivKey = Hex | bigint;
/** Signature instance. Has properties r and s. */
export type SigLike = {
    r: bigint;
    s: bigint;
};
/** Signature instance, which allows recovering pubkey from it. */
export type RecoveredSignature = Signature & {
    recovery: number;
};
export type SignatureWithRecovery = RecoveredSignature;
/** Weierstrass elliptic curve options. */
export type WeierstrassOpts<T> = Readonly<{
    p: bigint;
    n: bigint;
    h: bigint;
    a: T;
    b: T;
    Gx: T;
    Gy: T;
}>;
/** Point in 2d xy affine coordinates. */
export interface AffinePoint {
    x: bigint;
    y: bigint;
}
/** Point in 3d xyz projective coordinates. 3d takes less inversions than 2d. */
declare class Point {
    static BASE: Point;
    static ZERO: Point;
    readonly px: bigint;
    readonly py: bigint;
    readonly pz: bigint;
    constructor(px: bigint, py: bigint, pz: bigint);
    /** Convert Uint8Array or hex string to Point. */
    static fromBytes(bytes: Bytes): Point;
    /** Equality check: compare points P&Q. */
    equals(other: Point): boolean;
    is0(): boolean;
    /** Flip point over y coordinate. */
    negate(): Point;
    /** Point doubling: P+P, complete formula. */
    double(): Point;
    /**
     * Point addition: P+Q, complete, exception-free formula
     * (Renes-Costello-Batina, algo 1 of [2015/1060](https://eprint.iacr.org/2015/1060)).
     * Cost: `12M + 0S + 3*a + 3*b3 + 23add`.
     */
    add(other: Point): Point;
    /**
     * Point-by-scalar multiplication. Scalar must be in range 1 <= n < CURVE.n.
     * Uses {@link wNAF} for base point.
     * Uses fake point to mitigate side-channel leakage.
     * @param n scalar by which point is multiplied
     * @param safe safe mode guards against timing attacks; unsafe mode is faster
     */
    multiply(n: bigint, safe?: boolean): Point;
    /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
    toAffine(): AffinePoint;
    /** Checks if the point is valid and on-curve. */
    assertValidity(): Point;
    /** Converts point to 33/65-byte Uint8Array. */
    toBytes(isCompressed?: boolean): Bytes;
    /** Create 3d xyz point from 2d xy. (0, 0) => (0, 1, 0), not (0, 0, 1) */
    static fromAffine(ap: AffinePoint): Point;
    toHex(isCompressed?: boolean): string;
    static fromPrivateKey(k: Bytes): Point;
    static fromHex(hex: Hex): Point;
    get x(): bigint;
    get y(): bigint;
    toRawBytes(isCompressed?: boolean): Bytes;
}
/** Creates 33/65-byte public key from 32-byte private key. */
declare const getPublicKey: (privKey: PrivKey, isCompressed?: boolean) => Bytes;
/** ECDSA Signature class. Supports only compact 64-byte representation, not DER. */
declare class Signature {
    readonly r: bigint;
    readonly s: bigint;
    readonly recovery?: number;
    constructor(r: bigint, s: bigint, recovery?: number);
    /** Create signature from 64b compact (r || s) representation. */
    static fromBytes(b: Bytes): Signature;
    toBytes(): Bytes;
    /** Copy signature, with newly added recovery bit. */
    addRecoveryBit(bit: number): RecoveredSignature;
    hasHighS(): boolean;
    toCompactRawBytes(): Bytes;
    toCompactHex(): string;
    recoverPublicKey(msg: Bytes): Point;
    static fromCompact(hex: Hex): Signature;
    assertValidity(): Signature;
    normalizeS(): Signature;
}
type HmacFnSync = undefined | ((key: Bytes, ...msgs: Bytes[]) => Bytes);
/**
 * Option to enable hedged signatures with improved security.
 *
 * * Randomly generated k is bad, because broken CSPRNG would leak private keys.
 * * Deterministic k (RFC6979) is better; but is suspectible to fault attacks.
 *
 * We allow using technique described in RFC6979 3.6: additional k', a.k.a. adding randomness
 * to deterministic sig. If CSPRNG is broken & randomness is weak, it would STILL be as secure
 * as ordinary sig without ExtraEntropy.
 *
 * * `true` means "fetch data, from CSPRNG, incorporate it into k generation"
 * * `false` means "disable extra entropy, use purely deterministic k"
 * * `Uint8Array` passed means "incorporate following data into k generation"
 *
 * https://paulmillr.com/posts/deterministic-signatures/
 */
export type ExtraEntropy = boolean | Hex;
type OptS = {
    lowS?: boolean;
    extraEntropy?: ExtraEntropy;
};
type OptV = {
    lowS?: boolean;
};
/**
 * Sign a msg hash using secp256k1. Async.
 * Follows [SEC1](https://secg.org/sec1-v2.pdf) 4.1.2 & RFC6979.
 * It's suggested to enable hedging ({@link ExtraEntropy}) to prevent fault attacks.
 * @param msgh - message HASH, not message itself e.g. sha256(message)
 * @param priv - private key
 * @param opts - `lowS: true` prevents malleability, `extraEntropy: true` enables hedging
 */
declare const signAsync: (msgh: Hex, priv: PrivKey, opts?: OptS) => Promise<RecoveredSignature>;
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
declare const sign: (msgh: Hex, priv: PrivKey, opts?: OptS) => RecoveredSignature;
/**
 * Verify a signature using secp256k1.
 * Follows [SEC1](https://secg.org/sec1-v2.pdf) 4.1.4.
 * Default lowS=true, prevents malleability.
 * @param sig - signature, 64-byte or Signature instance
 * @param msgh - message HASH, not message itself e.g. sha256(message)
 * @param pub - public key
 * @param opts - { lowS: true } is default, prohibits s >= CURVE.n/2 to prevent malleability
 */
declare const verify: (sig: Hex | SigLike, msgh: Hex, pub: Hex, opts?: OptV) => boolean;
/**
 * Elliptic Curve Diffie-Hellman (ECDH) on secp256k1.
 * Result is **NOT hashed**. Use hash or KDF on it if you need.
 * @param privA private key A
 * @param pubB public key B
 * @param isCompressed 33-byte (true) or 65-byte (false) output
 * @returns public key C
 */
declare const getSharedSecret: (privA: Hex, pubB: Hex, isCompressed?: boolean) => Bytes;
/** Math, hex, byte helpers. Not in `utils` because utils share API with noble-curves. */
declare const etc: {
    hexToBytes: (hex: string) => Bytes;
    bytesToHex: (bytes: Bytes) => string;
    concatBytes: (...arrs: Bytes[]) => Bytes;
    bytesToNumberBE: (a: Bytes) => bigint;
    numberToBytesBE: (n: bigint) => Bytes;
    mod: (a: bigint, md?: bigint) => bigint;
    invert: (num: bigint, md?: bigint) => bigint;
    hmacSha256Async: (key: Bytes, ...msgs: Bytes[]) => Promise<Bytes>;
    hmacSha256Sync: HmacFnSync;
    hashToPrivateKey: (hash: Hex) => Bytes;
    randomBytes: (len?: number) => Bytes;
};
/** Curve-specific utilities for private keys. */
declare const utils: {
    normPrivateKeyToScalar: (p: PrivKey) => bigint;
    isValidPrivateKey: (key: Hex) => boolean;
    randomPrivateKey: () => Bytes;
    precompute: (w?: number, p?: Point) => Point;
};
export { secp256k1_CURVE as CURVE, etc, getPublicKey, getSharedSecret, Point, Point as ProjectivePoint, sign, signAsync, Signature, utils, verify, };
