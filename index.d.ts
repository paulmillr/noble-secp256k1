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
/** Point in 2d xy affine coordinates. */
export interface AffinePoint {
    x: bigint;
    y: bigint;
}
/** Point in 3d xyz projective coordinates. */
declare class Point {
    readonly px: bigint;
    readonly py: bigint;
    readonly pz: bigint;
    constructor(px: bigint, py: bigint, pz: bigint);
    static readonly BASE: Point;
    static readonly ZERO: Point;
    static fromAffine(p: AffinePoint): Point;
    static fromHex(hex: Hex): Point;
    static fromPrivateKey(k: PrivKey): Point;
    get x(): bigint;
    get y(): bigint;
    equals(other: Point): boolean;
    negate(): Point;
    double(): Point;
    add(other: Point): Point;
    mul(n: bigint, safe?: boolean): Point;
    mulAddQUns(R: Point, u1: bigint, u2: bigint): Point;
    toAffine(): AffinePoint;
    assertValidity(): Point;
    multiply(n: bigint): Point;
    aff(): AffinePoint;
    ok(): Point;
    toHex(isCompressed?: boolean): string;
    toRawBytes(isCompressed?: boolean): Bytes;
}
/** Create public key from private. Output is compressed 33b or uncompressed 65b. */
declare const getPublicKey: (privKey: PrivKey, isCompressed?: boolean) => Bytes;
/** Signature which allows recovering pubkey from it. */
export type SignatureWithRecovery = Signature & {
    recovery: number;
};
/** ECDSA Signature class. Supports only compact 64-byte representation, not DER. */
declare class Signature {
    readonly r: bigint;
    readonly s: bigint;
    readonly recovery?: number | undefined;
    constructor(r: bigint, s: bigint, recovery?: number | undefined);
    static fromCompact(hex: Hex): Signature;
    assertValidity(): Signature;
    addRecoveryBit(rec: number): SignatureWithRecovery;
    hasHighS(): boolean;
    normalizeS(): Signature;
    recoverPublicKey(msgh: Hex): Point;
    toCompactRawBytes(): Bytes;
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
 * @param msgh - message HASH, not message itself e.g. sha256(message)
 * @param priv - private key
 */
declare const signAsync: (msgh: Hex, priv: PrivKey, opts?: OptS) => Promise<SignatureWithRecovery>;
/**
 * Sign a msg hash using secp256k1.
 * @param msgh - message HASH, not message itself e.g. sha256(message)
 * @param priv - private key
 */
declare const sign: (msgh: Hex, priv: PrivKey, opts?: OptS) => SignatureWithRecovery;
type SigLike = {
    r: bigint;
    s: bigint;
};
/**
 * Verify a signature using secp256k1.
 * @param sig - signature, 64-byte or Signature instance
 * @param msgh - message HASH, not message itself e.g. sha256(message)
 * @param pub - public key
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
