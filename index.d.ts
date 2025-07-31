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
/** Signature instance, which allows recovering pubkey from it. */
export type RecoveredSignature = Signature & {
    recovery: number;
};
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
/** Asserts something is Uint8Array. */
declare const abytes: (value: Bytes, length?: number, title?: string) => Bytes;
/** Point in 2d xy affine coordinates. */
export interface AffinePoint {
    x: bigint;
    y: bigint;
}
/** Point in 3d xyz projective coordinates. 3d takes less inversions than 2d. */
declare class Point {
    static BASE: Point;
    static ZERO: Point;
    readonly X: bigint;
    readonly Y: bigint;
    readonly Z: bigint;
    constructor(X: bigint, Y: bigint, Z: bigint);
    static CURVE(): WeierstrassOpts<bigint>;
    /** Create 3d xyz point from 2d xy. (0, 0) => (0, 1, 0), not (0, 0, 1) */
    static fromAffine(ap: AffinePoint): Point;
    /** Convert Uint8Array or hex string to Point. */
    static fromBytes(bytes: Bytes): Point;
    static fromHex(hex: string): Point;
    get x(): bigint;
    get y(): bigint;
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
    subtract(other: Point): Point;
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
    toHex(isCompressed?: boolean): string;
}
/** Creates 33/65-byte public key from 32-byte private key. */
declare const getPublicKey: (privKey: Bytes, isCompressed?: boolean) => Bytes;
declare const isValidSecretKey: (secretKey: Bytes) => boolean;
declare const isValidPublicKey: (publicKey: Bytes, isCompressed?: boolean) => boolean;
/** ECDSA Signature class. Supports only compact 64-byte representation, not DER. */
declare class Signature {
    readonly r: bigint;
    readonly s: bigint;
    readonly recovery?: number;
    constructor(r: bigint, s: bigint, recovery?: number);
    static fromBytes(b: Bytes, format?: ECDSASigFormat): Signature;
    addRecoveryBit(bit: number): RecoveredSignature;
    hasHighS(): boolean;
    normalizeS(): Signature;
    toBytes(format?: ECDSASigFormat): Bytes;
}
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
export type ExtraEntropy = boolean | Bytes;
export type ECDSASigFormat = 'compact' | 'recovered' | 'der';
export type ECDSARecoverOpts = {
    prehash?: boolean;
};
export type ECDSAVerifyOpts = {
    prehash?: boolean;
    lowS?: boolean;
    format?: ECDSASigFormat;
};
export type ECDSASignOpts = {
    prehash?: boolean;
    lowS?: boolean;
    format?: ECDSASigFormat;
    extraEntropy?: Uint8Array | boolean;
};
/**
 * Sign a message using secp256k1. Sync: uses `hashes.sha256` and `hashes.hmacSha256`.
 * Prehashes message with sha256, disable using `prehash: false`.
 * @param opts - see {@link ECDSASignOpts} for details. Enabling {@link ExtraEntropy} will improve security.
 * @example
 * ```js
 * const msg = new TextEncoder().encode('hello');
 * sign(msg, secretKey);
 * sign(sha256(msg), secretKey, { prehash: false });
 * sign(msg, secretKey, { extraEntropy: true });
 * sign(msg, secretKey, { format: 'recovered' });
 * ```
 */
declare const sign: (message: Bytes, secretKey: Bytes, opts?: ECDSASignOpts) => Bytes;
/**
 * Sign a message using secp256k1. Async: uses built-in WebCrypto hashes.
 * Prehashes message with sha256, disable using `prehash: false`.
 * @param opts - see {@link ECDSASignOpts} for details. Enabling {@link ExtraEntropy} will improve security.
 * @example
 * ```js
 * const msg = new TextEncoder().encode('hello');
 * await signAsync(msg, secretKey);
 * await signAsync(sha256(msg), secretKey, { prehash: false });
 * await signAsync(msg, secretKey, { extraEntropy: true });
 * await signAsync(msg, secretKey, { format: 'recovered' });
 * ```
 */
declare const signAsync: (message: Bytes, secretKey: Bytes, opts?: ECDSASignOpts) => Promise<Bytes>;
/**
 * Verify a signature using secp256k1. Sync: uses `hashes.sha256` and `hashes.hmacSha256`.
 * @param signature - signature, default is 64-byte "compact" format
 * @param message - message which has been signed
 * @param publicKey - public key
 * @param opts - see {@link ECDSAVerifyOpts} for details.
 * @example
 * ```js
 * const msg = new TextEncoder().encode('hello');
 * verify(sig, msg, publicKey);
 * verify(sig, sha256(msg), publicKey, { prehash: false });
 * verify(sig, msg, publicKey, { lowS: false });
 * verify(sigr, msg, publicKey, { format: 'recovered' });
 * ```
 */
declare const verify: (signature: Bytes, message: Bytes, publicKey: Bytes, opts?: ECDSAVerifyOpts) => boolean;
/**
 * Verify a signature using secp256k1. Async: uses built-in WebCrypto hashes.
 * @param signature - signature, default is 64-byte "compact" format
 * @param message - message which has been signed
 * @param publicKey - public key
 * @param opts - see {@link ECDSAVerifyOpts} for details.
 * @example
 * ```js
 * const msg = new TextEncoder().encode('hello');
 * verify(sig, msg, publicKey);
 * verify(sig, sha256(msg), publicKey, { prehash: false });
 * verify(sig, msg, publicKey, { lowS: false });
 * verify(sigr, msg, publicKey, { format: 'recovered' });
 * ```
 */
declare const verifyAsync: (sig: Bytes, message: Bytes, publicKey: Bytes, opts?: ECDSAVerifyOpts) => Promise<boolean>;
/**
 * ECDSA public key recovery. Requires msg hash and recovery id.
 * Follows [SEC1](https://secg.org/sec1-v2.pdf) 4.1.6.
 */
declare const recoverPublicKey: (signature: Bytes, message: Bytes, opts?: ECDSARecoverOpts) => Bytes;
declare const recoverPublicKeyAsync: (signature: Bytes, message: Bytes, opts?: ECDSARecoverOpts) => Promise<Bytes>;
/**
 * Elliptic Curve Diffie-Hellman (ECDH) on secp256k1.
 * Result is **NOT hashed**. Use hash or KDF on it if you need.
 * @param isCompressed 33-byte (true) or 65-byte (false) output
 * @returns public key C
 */
declare const getSharedSecret: (secretKeyA: Bytes, publicKeyB: Bytes, isCompressed?: boolean) => Bytes;
type KeysSecPub = {
    secretKey: Bytes;
    publicKey: Bytes;
};
declare const keygen: (seed?: Bytes) => KeysSecPub;
/** Math, hex, byte helpers. Not in `utils` because utils share API with noble-curves. */
declare const etc: {
    hexToBytes: (hex: string) => Bytes;
    bytesToHex: (bytes: Bytes) => string;
    concatBytes: (...arrs: Bytes[]) => Bytes;
    bytesToNumberBE: (a: Bytes) => bigint;
    numberToBytesBE: (n: bigint) => Bytes;
    mod: (a: bigint, md?: bigint) => bigint;
    invert: (num: bigint, md?: bigint) => bigint;
    randomBytes: (len?: number) => Bytes;
    abytes: typeof abytes;
};
/** Curve-specific utilities for private keys. */
declare const utils: {
    isValidSecretKey: typeof isValidSecretKey;
    isValidPublicKey: typeof isValidPublicKey;
    randomSecretKey: () => Bytes;
};
export type Sha256FnSync = undefined | ((msg: Bytes) => Bytes);
export type HmacFnSync = undefined | ((key: Bytes, msg: Bytes) => Bytes);
export declare const hashes: {
    hmacSha256Async: (key: Bytes, msg: Bytes) => Promise<Bytes>;
    hmacSha256: HmacFnSync;
    sha256Async: (msg: Bytes) => Promise<Bytes>;
    sha256: Sha256FnSync;
};
/**
 * Schnorr public key is just `x` coordinate of Point as per BIP340.
 */
declare const pubSchnorr: (secretKey: Bytes) => Bytes;
/**
 * Creates Schnorr signature as per BIP340. Verifies itself before returning anything.
 * auxRand is optional and is not the sole source of k generation: bad CSPRNG won't be dangerous.
 */
declare const signSchnorr: (message: Bytes, secretKey: Bytes, auxRand?: Bytes) => Bytes;
declare const signAsyncSchnorr: (message: Bytes, secretKey: Bytes, auxRand?: Bytes) => Promise<Bytes>;
/**
 * Verifies Schnorr signature.
 * Will swallow errors & return false except for initial type validation of arguments.
 */
declare const verifySchnorr: (s: Bytes, m: Bytes, p: Bytes) => boolean;
declare const verifyAsyncSchnorr: (s: Bytes, m: Bytes, p: Bytes) => Promise<boolean>;
declare const schnorr: {
    getPublicKey: typeof pubSchnorr;
    sign: typeof signSchnorr;
    verify: typeof verifySchnorr;
    signAsync: typeof signAsyncSchnorr;
    verifyAsync: typeof verifyAsyncSchnorr;
};
export { secp256k1_CURVE as CURVE, etc, getPublicKey, getSharedSecret, keygen, Point, recoverPublicKey, recoverPublicKeyAsync, schnorr, sign, signAsync, Signature, utils, verify, verifyAsync };
