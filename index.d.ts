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
declare const hash: (msg: Bytes) => Bytes;
/** Point in 2d xy affine coordinates. */
export type AffinePoint = {
    x: bigint;
    y: bigint;
};
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
    multiplyUnsafe(scalar: bigint): Point;
    /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
    toAffine(): AffinePoint;
    /** Checks if the point is valid and on-curve. */
    assertValidity(): Point;
    /** Converts point to 33/65-byte Uint8Array. */
    toBytes(isCompressed?: boolean): Bytes;
    toHex(isCompressed?: boolean): string;
}
/** Normalize private key to scalar (bigint). Verifies scalar is in range 1<s<N */
declare const secretKeyToScalar: (secretKey: Bytes) => bigint;
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
    static fromBytes(b: Bytes, format?: ECDSASignatureFormat): Signature;
    addRecoveryBit(bit: number): RecoveredSignature;
    hasHighS(): boolean;
    toBytes(format?: ECDSASignatureFormat): Bytes;
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
export type ECDSAExtraEntropy = boolean | Bytes;
/**
 * - `compact` is the default format
 * - `recovered` is the same as compact, but with an extra byte indicating recovery byte
 * - `der` is not supported; and provided for consistency.
 *   Switch to noble-curves if you need der.
 */
export type ECDSASignatureFormat = 'compact' | 'recovered' | 'der';
/**
 * - `prehash`: (default: true) indicates whether to do sha256(message).
 *   When a custom hash is used, it must be set to `false`.
 */
export type ECDSARecoverOpts = {
    prehash?: boolean;
};
/**
 * - `prehash`: (default: true) indicates whether to do sha256(message).
 *   When a custom hash is used, it must be set to `false`.
 * - `lowS`: (default: true) prohibits signatures which have (sig.s >= CURVE.n/2n).
 *   Compatible with BTC/ETH. Setting `lowS: false` allows to create malleable signatures,
 *   which is default openssl behavior.
 *   Non-malleable signatures can still be successfully verified in openssl.
 * - `format`: (default: 'compact') 'compact' or 'recovered' with recovery byte
 */
export type ECDSAVerifyOpts = {
    prehash?: boolean;
    lowS?: boolean;
    format?: ECDSASignatureFormat;
};
/**
 * - `prehash`: (default: true) indicates whether to do sha256(message).
 *   When a custom hash is used, it must be set to `false`.
 * - `lowS`: (default: true) prohibits signatures which have (sig.s >= CURVE.n/2n).
 *   Compatible with BTC/ETH. Setting `lowS: false` allows to create malleable signatures,
 *   which is default openssl behavior.
 *   Non-malleable signatures can still be successfully verified in openssl.
 * - `format`: (default: 'compact') 'compact' or 'recovered' with recovery byte
 * - `extraEntropy`: (default: false) creates sigs with increased security, see {@link ECDSAExtraEntropy}
 */
export type ECDSASignOpts = {
    prehash?: boolean;
    lowS?: boolean;
    format?: ECDSASignatureFormat;
    extraEntropy?: ECDSAExtraEntropy;
};
declare const hashes: {
    hmacSha256Async: (key: Bytes, message: Bytes) => Promise<Bytes>;
    hmacSha256: undefined | ((key: Bytes, message: Bytes) => Bytes);
    sha256Async: (msg: Bytes) => Promise<Bytes>;
    sha256: undefined | ((message: Bytes) => Bytes);
};
/**
 * Sign a message using secp256k1. Sync: uses `hashes.sha256` and `hashes.hmacSha256`.
 * Prehashes message with sha256, disable using `prehash: false`.
 * @param opts - see {@link ECDSASignOpts} for details. Enabling {@link ECDSAExtraEntropy} will improve security.
 * @example
 * ```js
 * const msg = new TextEncoder().encode('hello noble');
 * sign(msg, secretKey);
 * sign(keccak256(msg), secretKey, { prehash: false });
 * sign(msg, secretKey, { extraEntropy: true });
 * sign(msg, secretKey, { format: 'recovered' });
 * ```
 */
declare const sign: (message: Bytes, secretKey: Bytes, opts?: ECDSASignOpts) => Bytes;
/**
 * Sign a message using secp256k1. Async: uses built-in WebCrypto hashes.
 * Prehashes message with sha256, disable using `prehash: false`.
 * @param opts - see {@link ECDSASignOpts} for details. Enabling {@link ECDSAExtraEntropy} will improve security.
 * @example
 * ```js
 * const msg = new TextEncoder().encode('hello noble');
 * await signAsync(msg, secretKey);
 * await signAsync(keccak256(msg), secretKey, { prehash: false });
 * await signAsync(msg, secretKey, { extraEntropy: true });
 * await signAsync(msg, secretKey, { format: 'recovered' });
 * ```
 */
declare const signAsync: (message: Bytes, secretKey: Bytes, opts?: ECDSASignOpts) => Promise<Bytes>;
/**
 * Verify a signature using secp256k1. Sync: uses `hashes.sha256` and `hashes.hmacSha256`.
 * @param signature - default is 64-byte 'compact' format, also see {@link ECDSASignatureFormat}
 * @param message - message which was signed. Keep in mind `prehash` from opts.
 * @param publicKey - public key which
 * @param opts - see {@link ECDSAVerifyOpts} for details.
 * @example
 * ```js
 * const msg = new TextEncoder().encode('hello noble');
 * verify(sig, msg, publicKey);
 * verify(sig, keccak256(msg), publicKey, { prehash: false });
 * verify(sig, msg, publicKey, { lowS: false });
 * verify(sigr, msg, publicKey, { format: 'recovered' });
 * ```
 */
declare const verify: (signature: Bytes, message: Bytes, publicKey: Bytes, opts?: ECDSAVerifyOpts) => boolean;
/**
 * Verify a signature using secp256k1. Async: uses built-in WebCrypto hashes.
 * @param signature - default is 64-byte 'compact' format, also see {@link ECDSASignatureFormat}
 * @param message - message which was signed. Keep in mind `prehash` from opts.
 * @param publicKey - public key which
 * @param opts - see {@link ECDSAVerifyOpts} for details.
 * @example
 * ```js
 * const msg = new TextEncoder().encode('hello noble');
 * verify(sig, msg, publicKey);
 * verify(sig, keccak256(msg), publicKey, { prehash: false });
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
type KeygenFn = (seed?: Bytes) => KeysSecPub;
declare const keygen: KeygenFn;
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
    secretKeyToScalar: typeof secretKeyToScalar;
    abytes: typeof abytes;
};
/** Curve-specific utilities for private keys. */
declare const utils: {
    isValidSecretKey: typeof isValidSecretKey;
    isValidPublicKey: typeof isValidPublicKey;
    randomSecretKey: () => Bytes;
};
/**
 * Schnorr public key is just `x` coordinate of Point as per BIP340.
 */
declare const pubSchnorr: (secretKey: Bytes) => Bytes;
declare const keygenSchnorr: KeygenFn;
/**
 * Creates Schnorr signature as per BIP340. Verifies itself before returning anything.
 * auxRand is optional and is not the sole source of k generation: bad CSPRNG won't be dangerous.
 */
declare const signSchnorr: (message: Bytes, secretKey: Bytes, auxRand?: Bytes) => Bytes;
declare const signSchnorrAsync: (message: Bytes, secretKey: Bytes, auxRand?: Bytes) => Promise<Bytes>;
/**
 * Verifies Schnorr signature.
 * Will swallow errors & return false except for initial type validation of arguments.
 */
declare const verifySchnorr: (s: Bytes, m: Bytes, p: Bytes) => boolean;
declare const verifySchnorrAsync: (s: Bytes, m: Bytes, p: Bytes) => Promise<boolean>;
declare const schnorr: {
    keygen: typeof keygenSchnorr;
    getPublicKey: typeof pubSchnorr;
    sign: typeof signSchnorr;
    verify: typeof verifySchnorr;
    signAsync: typeof signSchnorrAsync;
    verifyAsync: typeof verifySchnorrAsync;
};
export { etc, getPublicKey, getSharedSecret, hash, hashes, keygen, Point, recoverPublicKey, recoverPublicKeyAsync, schnorr, sign, signAsync, Signature, utils, verify, verifyAsync };
