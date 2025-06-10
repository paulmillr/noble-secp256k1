/**
 * secp256k1 curve parameters. Equation is x³ + ax + b, but a=0 - which makes it x³+b.
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
    static BASE: Point;
    static ZERO: Point;
    readonly px: bigint;
    readonly py: bigint;
    readonly pz: bigint;
    constructor(px: bigint, py: bigint, pz: bigint);
    /** Convert Uint8Array to Point. */
    static fromBytes(bytes: Bytes): Point;
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
    /** Convert point to 2d xy affine point. (x, y, z) ∋ (x=x/z, y=y/z) */
    aff(): AffinePoint;
    /** Checks if the point is valid and on-curve. */
    ok(): Point;
    toBytes(isCompressed?: boolean): Bytes;
    /** Create 3d xyz point from 2d xy. (0, 0) => (0, 1, 0), not (0, 0, 1) */
    static fromAffine(ap: AffinePoint): Point;
    is0(): boolean;
    toHex(c?: boolean): string;
    multiply(n: bigint): Point;
    static fromPrivateKey(k: Bytes): Point;
    get x(): bigint;
    get y(): bigint;
    toAffine(): AffinePoint;
    toRawBytes(c?: boolean): Bytes;
    assertValidity(): Point;
}
/** Creates 33/65-byte public key from 32-byte private key. */
declare const getPublicKey: (privKey: Bytes, isCompressed?: boolean) => Bytes;
/** ECDSA Signature class. Supports only compact 64-byte representation, not DER. */
declare class Signature {
    readonly r: bigint;
    readonly s: bigint;
    readonly recovery?: number;
    constructor(r: bigint, s: bigint, recovery?: number);
    static fromBytes(b: Bytes): Signature;
    toBytes(): Bytes;
    /** Create new signature, with added recovery bit. */
    addRecoveryBit(bit: number): SignatureWithRecovery;
    hasHighS(): boolean;
    toCompactRawBytes(): Bytes;
    toCompactHex(): string;
    recoverPublicKey(msg: Bytes): Point;
}
type HmacFnSync = undefined | ((key: Bytes, ...msgs: Bytes[]) => Bytes);
type OptS = {
    lowS?: boolean;
    extraEntropy?: boolean | Bytes;
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
declare const signAsync: (msgh: Bytes, priv: Bytes, opts?: OptS) => Promise<SignatureWithRecovery>;
/**
 * Sign a msg hash using secp256k1.
 * It is advised to use `extraEntropy: true` (from RFC6979 3.6) to prevent fault attacks.
 * Worst case: if randomness source for extraEntropy is bad, it would be as secure as if
 * the option has not been used.
 * @param msgh - message HASH, not message itself e.g. sha256(message)
 * @param priv - private key
 * @param opts - `lowS: true` to prevent malleability (s >= CURVE.n/2), `extraEntropy: boolean | Hex` to improve sig security.
 * @example
 * const sig = sign(sha256('hello'), privKey, { extraEntropy: true });
 */
declare const sign: (msgh: Bytes, priv: Bytes, opts?: OptS) => SignatureWithRecovery;
/**
 * Verify a signature using secp256k1.
 * @param sig - signature, 64-byte or Signature instance
 * @param msgh - message HASH, not message itself e.g. sha256(message)
 * @param pub - public key
 * @param opts - { lowS: true } is default, prohibits s >= CURVE.n/2 to prevent malleability
 */
declare const verify: (sig: Bytes | Signature, msgh: Bytes, pub: Bytes, opts?: OptV) => boolean;
/** ECDSA public key recovery. Requires msg hash and recovery id. */
declare const recoverPublicKey: (sig: SignatureWithRecovery, msgh: Bytes) => Point;
/**
 * Elliptic Curve Diffie-Hellman (ECDH) on secp256k1.
 * Result is **NOT hashed**. Use hash on it if you need.
 * @param privA private key A
 * @param pubB public key B
 * @param isCompressed 33-byte or 65-byte output
 * @returns public key C
 */
declare const getSharedSecret: (privA: Bytes, pubB: Bytes, isCompressed?: boolean) => Bytes;
/** Math, hex, byte helpers. Not in `utils` because utils share API with noble-curves. */
declare const etc: {
    hmacSha256Async: (key: Bytes, ...msgs: Bytes[]) => Promise<Bytes>;
    hmacSha256: HmacFnSync;
    sha256Async: (msg: Bytes) => Promise<Bytes>;
    sha256: Sha256FnSync;
};
declare const etc2: {
    hexToBytes: (hex: string) => Bytes;
    bytesToHex: (bytes: Bytes) => string;
    concatBytes: (...arrs: Bytes[]) => Bytes;
    bytesToNumberBE: (a: Bytes) => bigint;
    numberToBytesBE: (n: bigint) => Bytes;
    mod: (a: bigint, md?: bigint) => bigint;
    invert: (num: bigint, md?: bigint) => bigint;
    randomBytes: (len?: number) => Bytes;
};
declare const randomPrivateKey: () => Bytes;
/** Curve-specific utilities for private keys. */
declare const utils: {
    isValidPrivateKey: (key: Bytes) => boolean;
    randomPrivateKey: () => Bytes;
};
export type Sha256FnSync = undefined | ((msg: Bytes) => Bytes);
/**
 * Schnorr public key is just `x` coordinate of Point as per BIP340.
 */
declare const pubSchnorr: (privateKey: Bytes) => Bytes;
/**
 * Creates Schnorr signature as per BIP340. Verifies itself before returning anything.
 * auxRand is optional and is not the sole source of k generation: bad CSPRNG won't be dangerous.
 */
declare const signSchnorr: (message: Bytes, privateKey: Bytes, auxRand?: Bytes) => Bytes;
declare const signAsyncSchnorr: (message: Bytes, privateKey: Bytes, auxRand?: Bytes) => Promise<Bytes>;
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
export { CURVE, etc, etc2, getPublicKey, getSharedSecret, Point, randomPrivateKey, recoverPublicKey, schnorr, sign, signAsync, Signature, utils, verify };
