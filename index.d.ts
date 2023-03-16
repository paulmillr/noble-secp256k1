export declare const CURVE: {
    P: bigint;
    n: bigint;
    a: bigint;
    b: bigint;
    Gx: bigint;
    Gy: bigint;
};
declare type Bytes = Uint8Array;
declare type Hex = Bytes | string;
declare type PrivKey = Hex | bigint;
interface AffinePoint {
    x: bigint;
    y: bigint;
}
declare class Point {
    readonly px: bigint;
    readonly py: bigint;
    readonly pz: bigint;
    constructor(px: bigint, py: bigint, pz: bigint);
    static readonly BASE: Point;
    static readonly ZERO: Point;
    get x(): bigint;
    get y(): bigint;
    equals(other: Point): boolean;
    neg(): Point;
    dbl(): Point;
    add(other: Point): Point;
    mul(n: bigint, safe?: boolean): Point;
    mulAddQUns(R: Point, u1: bigint, u2: bigint): Point;
    aff(): AffinePoint;
    ok(): Point;
    multiply(n: bigint): Point;
    negate(): Point;
    toAffine(): AffinePoint;
    assertValidity(): Point;
    static fromHex(hex: Hex): Point;
    toHex(isCompressed?: boolean): string;
    toRawBytes(isCompressed?: boolean): Uint8Array;
    static fromPrivateKey(n: PrivKey): Point;
}
export declare const getPublicKey: (privKey: PrivKey, isCompressed?: boolean) => Uint8Array;
export declare class Signature {
    readonly r: bigint;
    readonly s: bigint;
    readonly recovery?: number | undefined;
    constructor(r: bigint, s: bigint, recovery?: number | undefined);
    ok(): Signature;
    static fromCompact(hex: Hex): Signature;
    hasHighS(): boolean;
    recoverPublicKey(msgh: Hex): Point;
    toCompactRawBytes(): Uint8Array;
    toCompactHex(): string;
}
declare type HmacFnSync = undefined | ((key: Bytes, ...msgs: Bytes[]) => Bytes);
export declare const signAsync: (msgh: Hex, priv: Hex, opts?: {
    lowS?: boolean | undefined;
    extraEntropy?: boolean | Hex | undefined;
}) => Promise<Signature>;
export declare const sign: (msgh: Hex, priv: Hex, opts?: {
    lowS?: boolean | undefined;
    extraEntropy?: boolean | Hex | undefined;
}) => Signature;
declare type SigLike = {
    r: bigint;
    s: bigint;
};
export declare const verify: (sig: Hex | SigLike, msgh: Hex, pub: Hex, opts?: {
    lowS: boolean;
}) => boolean;
export declare const getSharedSecret: (privA: Hex, pubB: Hex, isCompressed?: boolean) => Uint8Array;
export declare const etc: {
    hexToBytes: (hex: string) => Bytes;
    bytesToHex: (b: Bytes) => string;
    concatBytes: (...arrs: Bytes[]) => Uint8Array;
    bytesToNumberBE: (b: Bytes) => bigint;
    numberToBytesBE: (num: bigint) => Bytes;
    mod: (a: bigint, b?: bigint) => bigint;
    invert: (num: bigint, md?: bigint) => bigint;
    hmacSha256Async: (key: Bytes, ...msgs: Bytes[]) => Promise<Bytes>;
    hmacSha256Sync: HmacFnSync;
    hashToPrivateKey: (hash: Hex) => Bytes;
    randomBytes: (len: number) => Bytes;
};
export declare const utils: {
    normPrivateKeyToScalar: (p: PrivKey) => bigint;
    randomPrivateKey: () => Bytes;
    isValidPrivateKey: (key: Hex) => boolean;
    precompute(p: Point, windowSize?: number): Point;
};
export declare const ProjectivePoint: typeof Point;
export {};
