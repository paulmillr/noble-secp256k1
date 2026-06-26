/** Alias to Uint8Array. */
export type Bytes = Uint8Array;
/**
 * Bytes API type helpers for old + new TypeScript.
 *
 * TS 5.6 has `Uint8Array`, while TS 5.9+ made it generic `Uint8Array<ArrayBuffer>`.
 * We can't use specific return type, because TS 5.6 will error.
 * We can't use generic return type, because most TS 5.9 software will expect specific type.
 *
 * Maps typed-array input leaves to broad forms.
 * These are compatibility adapters, not ownership guarantees.
 *
 * - `TArg` keeps byte inputs broad.
 * - `TRet` marks byte outputs for TS 5.6 and TS 5.9+ compatibility.
 */
export type TypedArg<T> = T extends BigInt64Array ? BigInt64Array : T extends BigUint64Array ? BigUint64Array : T extends Float32Array ? Float32Array : T extends Float64Array ? Float64Array : T extends Int16Array ? Int16Array : T extends Int32Array ? Int32Array : T extends Int8Array ? Int8Array : T extends Uint16Array ? Uint16Array : T extends Uint32Array ? Uint32Array : T extends Uint8ClampedArray ? Uint8ClampedArray : T extends Uint8Array ? Uint8Array : never;
/** Maps typed-array output leaves to narrow TS-compatible forms. */
export type TypedRet<T> = T extends BigInt64Array ? ReturnType<typeof BigInt64Array.of> : T extends BigUint64Array ? ReturnType<typeof BigUint64Array.of> : T extends Float32Array ? ReturnType<typeof Float32Array.of> : T extends Float64Array ? ReturnType<typeof Float64Array.of> : T extends Int16Array ? ReturnType<typeof Int16Array.of> : T extends Int32Array ? ReturnType<typeof Int32Array.of> : T extends Int8Array ? ReturnType<typeof Int8Array.of> : T extends Uint16Array ? ReturnType<typeof Uint16Array.of> : T extends Uint32Array ? ReturnType<typeof Uint32Array.of> : T extends Uint8ClampedArray ? ReturnType<typeof Uint8ClampedArray.of> : T extends Uint8Array ? ReturnType<typeof Uint8Array.of> : never;
/** Recursively adapts byte-carrying API input types. See {@link TypedArg}. */
export type TArg<T> = T | ([TypedArg<T>] extends [never] ? T extends (...args: infer A) => infer R ? ((...args: {
    [K in keyof A]: TRet<A[K]>;
}) => TArg<R>) & {
    [K in keyof T]: T[K] extends (...args: any) => any ? T[K] : TArg<T[K]>;
} : T extends [infer A, ...infer R] ? [TArg<A>, ...{
    [K in keyof R]: TArg<R[K]>;
}] : T extends readonly [infer A, ...infer R] ? readonly [TArg<A>, ...{
    [K in keyof R]: TArg<R[K]>;
}] : T extends (infer A)[] ? TArg<A>[] : T extends readonly (infer A)[] ? readonly TArg<A>[] : T extends Promise<infer A> ? Promise<TArg<A>> : T extends object ? {
    [K in keyof T]: TArg<T[K]>;
} : T : TypedArg<T>);
/** Recursively adapts byte-carrying API output types. See {@link TypedArg}. */
export type TRet<T> = T extends unknown ? T & ([TypedRet<T>] extends [never] ? T extends (...args: infer A) => infer R ? ((...args: {
    [K in keyof A]: TArg<A[K]>;
}) => TRet<R>) & {
    [K in keyof T]: T[K] extends (...args: any) => any ? T[K] : TRet<T[K]>;
} : T extends [infer A, ...infer R] ? [TRet<A>, ...{
    [K in keyof R]: TRet<R[K]>;
}] : T extends readonly [infer A, ...infer R] ? readonly [TRet<A>, ...{
    [K in keyof R]: TRet<R[K]>;
}] : T extends (infer A)[] ? TRet<A>[] : T extends readonly (infer A)[] ? readonly TRet<A>[] : T extends Promise<infer A> ? Promise<TRet<A>> : T extends object ? {
    [K in keyof T]: TRet<T[K]>;
} : T : TypedRet<T>) : never;
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
/** Asserts something is Bytes. */
declare const abytes: (value: TArg<Bytes>, length?: number, title?: string) => TRet<Bytes>;
/** Modular inversion using eucledian GCD (non-CT). No negative exponent for now. */
declare const invert: (num: bigint, md: bigint) => bigint;
/**
 * SHA-256 helper used by the synchronous API.
 * @param msg - message bytes to hash
 * @returns 32-byte SHA-256 digest.
 * @example
 * Hash message bytes after wiring the synchronous SHA-256 implementation.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * secp.hashes.sha256 = sha256;
 * const digest = secp.hash(new Uint8Array([1, 2, 3]));
 * ```
 */
declare const hash: (msg: TArg<Bytes>) => TRet<Bytes>;
/** Point in 2d xy affine coordinates. */
export type AffinePoint = {
    /** Affine x coordinate. */
    x: bigint;
    /** Affine y coordinate. */
    y: bigint;
};
/**
 * Point in 3d xyz projective coordinates. 3d takes less inversions than 2d.
 * @param X - X coordinate.
 * @param Y - Y coordinate.
 * @param Z - projective Z coordinate.
 * @example
 * Do point arithmetic with the base point and encode the result as hex.
 * ```ts
 * import { Point } from '@noble/secp256k1';
 * const hex = Point.BASE.double().toHex();
 * ```
 */
declare class Point {
    static BASE: Point;
    static ZERO: Point;
    readonly X: bigint;
    readonly Y: bigint;
    readonly Z: bigint;
    constructor(X: bigint, Y: bigint, Z: bigint);
    /** Returns the shared curve metadata object by reference.
     * It is readonly only at type level, and mutating it won't retarget arithmetic,
     * which already uses module-load snapshots. */
    static CURVE(): WeierstrassOpts<bigint>;
    /** Create 3d xyz point from 2d xy. (0, 0) => (0, 1, 0), not (0, 0, 1) */
    static fromAffine(ap: AffinePoint): Point;
    /** Convert Uint8Array or hex string to Point. */
    static fromBytes(bytes: TArg<Bytes>): Point;
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
     * Uses fake point to mitigate leakage shape in JS, not as a hard constant-time guarantee.
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
    toBytes(isCompressed?: boolean): TRet<Bytes>;
    toHex(isCompressed?: boolean): string;
}
/** Normalize private key to scalar (bigint). Verifies scalar is in range 1 <= d < N. */
declare const secretKeyToScalar: (secretKey: TArg<Bytes>) => bigint;
/**
 * Creates a SEC 1 public key from a 32-byte private key.
 * @param privKey - 32-byte secret key.
 * @param isCompressed - return 33-byte compressed SEC 1 encoding when `true`, otherwise 65-byte uncompressed.
 * @returns serialized secp256k1 public key in SEC 1 encoding.
 * @example
 * Derive the serialized public key for a secp256k1 secret key.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * const secretKey = secp.utils.randomSecretKey();
 * const publicKey = secp.getPublicKey(secretKey);
 * ```
 */
declare const getPublicKey: (privKey: TArg<Bytes>, isCompressed?: boolean) => TRet<Bytes>;
declare const isValidSecretKey: (secretKey: TArg<Bytes>) => boolean;
declare const isValidPublicKey: (publicKey: TArg<Bytes>, isCompressed?: boolean) => boolean;
/**
 * ECDSA Signature class. Supports only compact 64-byte representation, not DER.
 * @param r - signature `r` scalar.
 * @param s - signature `s` scalar.
 * @param recovery - optional recovery id.
 * @example
 * Build a recovered-format signature object and serialize it.
 * ```ts
 * import { Signature } from '@noble/secp256k1';
 * const bytes = new Signature(1n, 2n, 0).toBytes('recovered');
 * ```
 */
declare class Signature {
    readonly r: bigint;
    readonly s: bigint;
    readonly recovery?: number;
    constructor(r: bigint, s: bigint, recovery?: number);
    static fromBytes(b: TArg<Bytes>, format?: ECDSASignatureFormat): Signature;
    addRecoveryBit(bit: number): RecoveredSignature;
    hasHighS(): boolean;
    toBytes(format?: ECDSASignatureFormat): TRet<Bytes>;
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
 * See {@link https://paulmillr.com/posts/deterministic-signatures/ | Deterministic signatures}.
 */
export type ECDSAExtraEntropy = boolean | Bytes;
/**
 * - `compact` is the default format
 * - `recovered` is the same as compact, but with an extra byte indicating recovery byte
 * - `der` is not supported; it is included only so unsupported requests can be rejected consistently.
 *   Switch to noble-curves if you need der.
 */
export type ECDSASignatureFormat = 'compact' | 'recovered' | 'der';
/**
 * - `prehash`: (default: true) indicates whether to do sha256(message).
 *   When a custom hash is used, it must be set to `false`.
 */
export type ECDSARecoverOpts = {
    /** Set to `false` when the message is already hashed with a custom digest. */
    prehash?: boolean;
};
/**
 * - `prehash`: (default: true) indicates whether to do sha256(message).
 *   When a custom hash is used, it must be set to `false`.
 * - `lowS`: (default: true) prohibits signatures in the strict upper half (`sig.s > floor(CURVE.n / 2n)`).
 *   Compatible with BTC/ETH. Setting `lowS: false` allows to create malleable signatures,
 *   which is default openssl behavior.
 *   Non-malleable signatures can still be successfully verified in openssl.
 * - `format`: (default: 'compact') 'compact' or 'recovered' with recovery byte
 */
export type ECDSAVerifyOpts = {
    /** Set to `false` when the message is already hashed with a custom digest. */
    prehash?: boolean;
    /** Set to `false` to accept high-S signatures instead of enforcing canonical low-S ones. */
    lowS?: boolean;
    /** Signature encoding accepted by the verifier. */
    format?: ECDSASignatureFormat;
};
/**
 * - `prehash`: (default: true) indicates whether to do sha256(message).
 *   When a custom hash is used, it must be set to `false`.
 * - `lowS`: (default: true) prohibits signatures in the strict upper half (`sig.s > floor(CURVE.n / 2n)`).
 *   Compatible with BTC/ETH. Setting `lowS: false` allows to create malleable signatures,
 *   which is default openssl behavior.
 *   Non-malleable signatures can still be successfully verified in openssl.
 * - `format`: (default: 'compact') 'compact' or 'recovered' with recovery byte
 * - `extraEntropy`: (default: false) creates sigs with increased security, see {@link ECDSAExtraEntropy}
 */
export type ECDSASignOpts = {
    /** Set to `false` when the message is already hashed with a custom digest. */
    prehash?: boolean;
    /** Set to `false` to allow high-S signatures instead of normalizing to low-S form. */
    lowS?: boolean;
    /** Signature encoding produced by the signer. */
    format?: ECDSASignatureFormat;
    /** Extra entropy mixed into RFC6979 nonce generation for hedged signatures. */
    extraEntropy?: ECDSAExtraEntropy;
};
/**
 * Hash implementations used by the synchronous and async ECDSA / Schnorr helpers.
 * All slots are configurable API surface; wrapper helpers revalidate that SHA-256 and HMAC-SHA256
 * providers still return exact 32-byte Uint8Array digests.
 * @example
 * Provide sync hash helpers before calling the synchronous signing API.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * import { hmac } from '@noble/hashes/hmac.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * secp.hashes.sha256 = sha256;
 * secp.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);
 * const secretKey = secp.utils.randomSecretKey();
 * const sig = secp.sign(new Uint8Array([1, 2, 3]), secretKey);
 * ```
 */
declare const hashes: {
    hmacSha256Async: (key: TArg<Bytes>, message: TArg<Bytes>) => Promise<TRet<Bytes>>;
    hmacSha256: undefined | ((key: TArg<Bytes>, message: TArg<Bytes>) => TRet<Bytes>);
    sha256Async: (msg: TArg<Bytes>) => Promise<TRet<Bytes>>;
    sha256: undefined | ((message: TArg<Bytes>) => TRet<Bytes>);
};
/**
 * Sign a message using secp256k1. Sync: uses `hashes.sha256` and `hashes.hmacSha256`.
 * Prehashes message with sha256, disable using `prehash: false`.
 * @param message - message bytes to sign.
 * @param secretKey - 32-byte secret key.
 * @param opts - See {@link ECDSASignOpts} for details. Enabling {@link ECDSAExtraEntropy} improves security.
 * @returns ECDSA signature encoded according to `opts.format`.
 * @example
 * Sign a message using secp256k1.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * import { hmac } from '@noble/hashes/hmac.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * secp.hashes.sha256 = sha256;
 * secp.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);
 * const secretKey = secp.utils.randomSecretKey();
 * const msg = new TextEncoder().encode('hello noble');
 * secp.sign(msg, secretKey);
 * secp.sign(msg, secretKey, { extraEntropy: true });
 * secp.sign(msg, secretKey, { format: 'recovered' });
 * ```
 */
declare const sign: (message: TArg<Bytes>, secretKey: TArg<Bytes>, opts?: TArg<ECDSASignOpts>) => TRet<Bytes>;
/**
 * Sign a message using secp256k1. Async: uses built-in WebCrypto hashes.
 * Prehashes message with sha256, disable using `prehash: false`.
 * @param message - message bytes to sign.
 * @param secretKey - 32-byte secret key.
 * @param opts - See {@link ECDSASignOpts} for details. Enabling {@link ECDSAExtraEntropy} improves security.
 * @returns ECDSA signature encoded according to `opts.format`.
 * @example
 * Sign a message using secp256k1 with the async WebCrypto path.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * import { keccak_256 } from '@noble/hashes/sha3.js';
 * const secretKey = secp.utils.randomSecretKey();
 * const msg = new TextEncoder().encode('hello noble');
 * await secp.signAsync(msg, secretKey);
 * await secp.signAsync(keccak_256(msg), secretKey, { prehash: false });
 * await secp.signAsync(msg, secretKey, { extraEntropy: true });
 * await secp.signAsync(msg, secretKey, { format: 'recovered' });
 * ```
 */
declare const signAsync: (message: TArg<Bytes>, secretKey: TArg<Bytes>, opts?: TArg<ECDSASignOpts>) => Promise<TRet<Bytes>>;
/**
 * Verify a signature using secp256k1. Sync: uses `hashes.sha256` and `hashes.hmacSha256`.
 * @param signature - default is 64-byte `compact` format; also see {@link ECDSASignatureFormat}.
 * @param message - message which was signed. Keep in mind `prehash` from opts.
 * @param publicKey - public key that should verify the signature.
 * @param opts - See {@link ECDSAVerifyOpts} for details.
 * @returns `true` when the signature is valid. Unsupported format configuration still
 * throws instead of returning `false`.
 * @example
 * Verify a signature using secp256k1.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * import { hmac } from '@noble/hashes/hmac.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * import { keccak_256 } from '@noble/hashes/sha3.js';
 * secp.hashes.sha256 = sha256;
 * secp.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);
 * const secretKey = secp.utils.randomSecretKey();
 * const msg = new TextEncoder().encode('hello noble');
 * const publicKey = secp.getPublicKey(secretKey);
 * const sig = secp.sign(msg, secretKey);
 * const sigr = secp.sign(msg, secretKey, { format: 'recovered' });
 * secp.verify(sig, msg, publicKey);
 * secp.verify(sig, keccak_256(msg), publicKey, { prehash: false });
 * secp.verify(sig, msg, publicKey, { lowS: false });
 * secp.verify(sigr, msg, publicKey, { format: 'recovered' });
 * ```
 */
declare const verify: (signature: TArg<Bytes>, message: TArg<Bytes>, publicKey: TArg<Bytes>, opts?: TArg<ECDSAVerifyOpts>) => boolean;
/**
 * Verify a signature using secp256k1. Async: uses built-in WebCrypto hashes.
 * @param sig - default is 64-byte `compact` format; also see {@link ECDSASignatureFormat}.
 * @param message - message which was signed. Keep in mind `prehash` from opts.
 * @param publicKey - public key that should verify the signature.
 * @param opts - See {@link ECDSAVerifyOpts} for details.
 * @returns `true` when the signature is valid. Unsupported format configuration still
 * throws instead of returning `false`.
 * @example
 * Verify a signature using secp256k1 with the async WebCrypto path.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * import { keccak_256 } from '@noble/hashes/sha3.js';
 * const secretKey = secp.utils.randomSecretKey();
 * const msg = new TextEncoder().encode('hello noble');
 * const publicKey = secp.getPublicKey(secretKey);
 * const sig = await secp.signAsync(msg, secretKey);
 * const sigr = await secp.signAsync(msg, secretKey, { format: 'recovered' });
 * await secp.verifyAsync(sig, msg, publicKey);
 * await secp.verifyAsync(sigr, msg, publicKey, { format: 'recovered' });
 * await secp.verifyAsync(sig, keccak_256(msg), publicKey, { prehash: false });
 * ```
 */
declare const verifyAsync: (sig: TArg<Bytes>, message: TArg<Bytes>, publicKey: TArg<Bytes>, opts?: TArg<ECDSAVerifyOpts>) => Promise<boolean>;
/**
 * ECDSA public key recovery. Requires msg hash and recovery id.
 * Follows {@link https://secg.org/sec1-v2.pdf | SEC1} 4.1.6.
 * @param signature - recovered-format signature from `sign(..., { format: 'recovered' })`.
 * @param message - signed message bytes.
 * @param opts - See {@link ECDSARecoverOpts} for details.
 * @returns recovered public key bytes.
 * @example
 * Recover a secp256k1 public key from a recovered-format signature.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * import { hmac } from '@noble/hashes/hmac.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * secp.hashes.sha256 = sha256;
 * secp.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);
 * const secretKey = secp.utils.randomSecretKey();
 * const message = new Uint8Array([1, 2, 3]);
 * const sig = secp.sign(message, secretKey, { format: 'recovered' });
 * secp.recoverPublicKey(sig, message);
 * ```
 */
declare const recoverPublicKey: (signature: TArg<Bytes>, message: TArg<Bytes>, opts?: TArg<ECDSARecoverOpts>) => TRet<Bytes>;
/**
 * Async ECDSA public key recovery. Requires msg hash and recovery id.
 * @param signature - recovered-format signature from `signAsync(..., { format: 'recovered' })`.
 * @param message - signed message bytes.
 * @param opts - See {@link ECDSARecoverOpts} for details.
 * @returns recovered public key bytes.
 * @example
 * Recover a secp256k1 public key from a recovered-format signature with the async API.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * const secretKey = secp.utils.randomSecretKey();
 * const message = new Uint8Array([1, 2, 3]);
 * const sig = await secp.signAsync(message, secretKey, { format: 'recovered' });
 * await secp.recoverPublicKeyAsync(sig, message);
 * ```
 */
declare const recoverPublicKeyAsync: (signature: TArg<Bytes>, message: TArg<Bytes>, opts?: TArg<ECDSARecoverOpts>) => Promise<TRet<Bytes>>;
/**
 * Elliptic Curve Diffie-Hellman (ECDH) on secp256k1.
 * Result is **NOT hashed** and returns the serialized shared point (compressed by default),
 * not the SEC 1 x-only primitive `z = x_P`.
 * secp256k1 has cofactor `h = 1`, so there is no separate cofactor-ECDH distinction here.
 * @param secretKeyA - local 32-byte secret key.
 * @param publicKeyB - peer public key.
 * @param isCompressed - return 33-byte compressed output when `true`.
 * @returns shared secret point bytes.
 * @example
 * Derive a shared secp256k1 secret with ECDH.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * const alice = secp.utils.randomSecretKey();
 * const bob = secp.utils.randomSecretKey();
 * const shared = secp.getSharedSecret(alice, secp.getPublicKey(bob));
 * ```
 */
declare const getSharedSecret: (secretKeyA: TArg<Bytes>, publicKeyB: TArg<Bytes>, isCompressed?: boolean) => TRet<Bytes>;
declare const randomSecretKey: (seed?: TArg<Bytes>) => TRet<Bytes>;
type KeysSecPub = {
    secretKey: Bytes;
    publicKey: Bytes;
};
type KeygenFn = (seed?: TArg<Bytes>) => TRet<KeysSecPub>;
/**
 * Generates a secp256k1 keypair.
 * @param seed - optional entropy seed.
 * @returns keypair with `secretKey` and `publicKey`.
 * @example
 * Generate a secp256k1 keypair for sync signing.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * import { hmac } from '@noble/hashes/hmac.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * secp.hashes.sha256 = sha256;
 * secp.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);
 * const { secretKey, publicKey } = secp.keygen();
 * ```
 */
declare const keygen: KeygenFn;
/**
 * Math, hex, byte helpers. Not in `utils` because utils share API with noble-curves.
 * @example
 * Convert bytes to a hex string with the low-level helper namespace.
 * ```ts
 * import { etc } from '@noble/secp256k1';
 * const hex = etc.bytesToHex(new Uint8Array([1, 2, 3]));
 * ```
 */
declare const etc: {
    hexToBytes: (hex: string) => TRet<Bytes>;
    bytesToHex: (bytes: TArg<Bytes>) => string;
    concatBytes: (...arrs: TArg<Bytes[]>) => TRet<Bytes>;
    bytesToNumberBE: (a: TArg<Bytes>) => bigint;
    numberToBytesBE: (n: bigint) => TRet<Bytes>;
    mod: (a: bigint, md?: bigint) => bigint;
    invert: typeof invert;
    randomBytes: (len?: number) => TRet<Bytes>;
    secretKeyToScalar: typeof secretKeyToScalar;
    abytes: typeof abytes;
};
/**
 * Curve-specific key utilities.
 * @example
 * Generate a fresh secret key and derive its public key.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * const secretKey = secp.utils.randomSecretKey();
 * const publicKey = secp.getPublicKey(secretKey);
 * ```
 */
declare const utils: {
    isValidSecretKey: typeof isValidSecretKey;
    isValidPublicKey: typeof isValidPublicKey;
    randomSecretKey: typeof randomSecretKey;
};
/** Schnorr public key is just `x` coordinate of Point as per BIP340. */
declare const pubSchnorr: (secretKey: TArg<Bytes>) => TRet<Bytes>;
declare const keygenSchnorr: KeygenFn;
/**
 * Creates Schnorr signature as per BIP340. Verifies itself before returning anything.
 * auxRand is optional and defaults to fresh 32-byte randomness; it is not the sole source of
 * k generation, so bad CSPRNG won't be the only entropy source.
 */
declare const signSchnorr: (message: TArg<Bytes>, secretKey: TArg<Bytes>, auxRand?: TArg<Bytes>) => TRet<Bytes>;
declare const signSchnorrAsync: (message: TArg<Bytes>, secretKey: TArg<Bytes>, auxRand?: TArg<Bytes>) => Promise<TRet<Bytes>>;
/** Verifies Schnorr signature. Sync wrapper returns false for post-validation failures
 * after the initial byte checks. */
declare const verifySchnorr: (s: TArg<Bytes>, m: TArg<Bytes>, p: TArg<Bytes>) => boolean;
/** Async Schnorr verification. Curve/encoding failures after the initial byte checks still
 * become false, but async backend failures reject the promise. Missing crypto.subtle is a
 * runtime/backend error, not an "invalid signature" result, so we surface it instead of
 * turning it into false. */
declare const verifySchnorrAsync: (s: TArg<Bytes>, m: TArg<Bytes>, p: TArg<Bytes>) => Promise<boolean>;
/**
 * BIP340 Schnorr helpers over secp256k1.
 * @example
 * Sign and verify a BIP340 Schnorr signature.
 * ```ts
 * import * as secp from '@noble/secp256k1';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * secp.hashes.sha256 = sha256;
 * const secretKey = secp.utils.randomSecretKey();
 * const message = new Uint8Array([1, 2, 3]);
 * const sig = secp.schnorr.sign(message, secretKey);
 * const publicKey = secp.schnorr.getPublicKey(secretKey);
 * const isValid = secp.schnorr.verify(sig, message, publicKey);
 * ```
 */
declare const schnorr: {
    keygen: typeof keygenSchnorr;
    getPublicKey: typeof pubSchnorr;
    sign: typeof signSchnorr;
    verify: typeof verifySchnorr;
    signAsync: typeof signSchnorrAsync;
    verifyAsync: typeof verifySchnorrAsync;
};
declare const __TEST: TRet<{
    lift_x: (x: bigint) => Point;
    extractK: (rand: TArg<Bytes>) => TRet<{
        rx: Bytes;
        k: bigint;
    }>;
}>;
export { etc, getPublicKey, getSharedSecret, hash, hashes, keygen, Point, recoverPublicKey, recoverPublicKeyAsync, schnorr, sign, signAsync, Signature, utils, verify, verifyAsync, __TEST, };
