/**
 * secp256k1 curve parameters. Equation is x³ + ax + b.
 * Gx and Gy are generator coordinates. p is field order, n is group order.
 */
declare const CURVE: {
    p: bigint;
    n: bigint;
    a: bigint;
    b: bigint;
    Gx: bigint;
    Gy: bigint;
};
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
export type SignatureWithRecovery = Signature & {
    recovery: number;
};
/** Point in 2d xy affine coordinates. */
export interface AffinePoint {
    x: bigint;
    y: bigint;
}
/** Point in 3d xyz projective coordinates. 3d takes less inversions than 2d. */
declare class Point {
    readonly px: bigint;
    readonly py: bigint;
    readonly pz: bigint;
    constructor(px: bigint, py: bigint, pz: bigint);
    /** Generator / base point */
    static readonly BASE: Point;
    /** Identity / zero point */
    static readonly ZERO: Point;
    /** Create 3d xyz point from 2d xy. (0, 0) => (0, 1, 0), not (0, 0, 1) */
    static fromAffine(p: AffinePoint): Point;
    /** Convert Uint8Array or hex string to Point. */
    static fromHex(hex: Hex): Point;
    /** Create point from a private key. */
    static fromPrivateKey(k: PrivKey): Point;
    get x(): bigint;
    get y(): bigint;
    /** Equality check: compare points P&Q. */
    equals(other: Point): boolean;
    /** Flip point over y coordinate. */
    negate(): Point;
    /** Point doubling: P+P, complete formula. */
    double(): Point;
    /**
     * Point addition: P+Q, complete, exception-free formula
     * (Renes-Costello-Batina, algo 1 of [2015/1060](https://eprint.iacr.org/2015/1060)).
     * Cost: 12M + 0S + 3*a + 3*b3 + 23add.
     */
    add(other: Point): Point;
    mul(n: bigint, safe?: boolean): Point;
    mulAddQUns(R: Point, u1: bigint, u2: bigint): Point;
    /** Convert point to 2d xy affine point. (x, y, z) ∋ (x=x/z, y=y/z) */
    toAffine(): AffinePoint;
    /** Checks if the point is valid and on-curve. */
    assertValidity(): Point;
    multiply(n: bigint): Point;
    aff(): AffinePoint;
    ok(): Point;
    toHex(isCompressed?: boolean): string;
    toRawBytes(isCompressed?: boolean): Bytes;
}
/** Creates 33/65-byte public key from 32-byte private key. */
declare const getPublicKey: (privKey: PrivKey, isCompressed?: boolean) => Bytes;
/** ECDSA Signature class. Supports only compact 64-byte representation, not DER. */
declare class Signature {
    readonly r: bigint;
    readonly s: bigint;
    readonly recovery?: number | undefined;
    constructor(r: bigint, s: bigint, recovery?: number | undefined);
    /** Create signature from 64b compact (r || s) representation. */
    static fromCompact(hex: Hex): Signature;
    assertValidity(): Signature;
    /** Create new signature, with added recovery bit. */
    addRecoveryBit(rec: number): SignatureWithRecovery;
    hasHighS(): boolean;
    normalizeS(): Signature;
    /** ECDSA public key recovery. Requires msg hash and recovery id. */
    recoverPublicKey(msgh: Hex): Point;
    /** Uint8Array 64b compact (r || s) representation. */
    toCompactRawBytes(): Bytes;
    /** Hex string 64b compact (r || s) representation. */
    toCompactHex(): string;
}
type HmacFnSync = undefined | ((key: Bytes, ...msgs: Bytes[]) => Bytes);
type OptS = {
    lowS?: boolean;
    extraEntropy?: boolean | Hex;
};
type OptV = {
    lowS?: boolean;
};
/** ECDSA signature generation. via secg.org/sec1-v2.pdf 4.1.2 + RFC6979 deterministic k. */
/**
 * Sign a msg hash using secp256k1. Async.
 * It is advised to use `extraEntropy: true` (from RFC6979 3.6) to prevent fault attacks.
 * Worst case: if randomness source for extraEntropy is bad, it would be as secure as if
 * the option has not been used.
 * @param msgh - message HASH, not message itself e.g. sha256(message)
 * @param priv - private key
 * @param opts - `lowS: true` to prevent malleability (s >= CURVE.n/2), `extraEntropy: boolean | Hex` to improve sig security.
 */
declare const signAsync: (msgh: Hex, priv: PrivKey, opts?: OptS) => Promise<SignatureWithRecovery>;
/**
 * Sign a msg hash using secp256k1.
 * It is advised to use `extraEntropy: true` (from RFC6979 3.6) to prevent fault attacks.
 * Worst case: if randomness source for extraEntropy is bad, it would be as secure as if
 * the option has not been used.
 * @param msgh - message HASH, not message itself e.g. sha256(message)
 * @param priv - private key
 * @param opts - `lowS: true` to prevent malleability (s >= CURVE.n/2), `extraEntropy: boolean | Hex` to improve sig security.
 * @example
 * const sig = sign(sha256('hello'), privKey, { extraEntropy: true }).toCompactRawBytes();
 */
declare const sign: (msgh: Hex, priv: PrivKey, opts?: OptS) => SignatureWithRecovery;
/**
 * Verify a signature using secp256k1.
 * @param sig - signature, 64-byte or Signature instance
 * @param msgh - message HASH, not message itself e.g. sha256(message)
 * @param pub - public key
 * @param opts - { lowS: true } is default, prohibits s >= CURVE.n/2 to prevent malleability
 */
declare const verify: (sig: Hex | SigLike, msgh: Hex, pub: Hex, opts?: OptV) => boolean;
/**
 * Elliptic Curve Diffie-Hellman (ECDH) on secp256k1.
 * Result is **NOT hashed**. Use hash on it if you need.
 * @param privA private key A
 * @param pubB public key B
 * @param isCompressed 33-byte or 65-byte output
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
export { getPublicKey, sign, signAsync, verify, CURVE, // Remove the export to easily use in REPL
getSharedSecret, etc, utils, Point as ProjectivePoint, Signature };
