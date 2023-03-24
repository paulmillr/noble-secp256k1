declare const CURVE: {
    p: bigint;
    n: bigint;
    a: bigint;
    b: bigint;
    Gx: bigint;
    Gy: bigint;
};
type Bytes = Uint8Array;
type Hex = Bytes | string;
type PrivKey = Hex | bigint;
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
    toRawBytes(isCompressed?: boolean): Uint8Array;
}
declare function getPublicKey(privKey: PrivKey, isCompressed?: boolean): Uint8Array;
declare class Signature {
    readonly r: bigint;
    readonly s: bigint;
    readonly recovery?: number | undefined;
    constructor(r: bigint, s: bigint, recovery?: number | undefined);
    static fromCompact(hex: Hex): Signature;
    assertValidity(): this;
    addRecoveryBit(rec: number): Signature;
    hasHighS(): boolean;
    recoverPublicKey(msgh: Hex): Point;
    toCompactRawBytes(): Uint8Array;
    toCompactHex(): string;
}
type HmacFnSync = undefined | ((key: Bytes, ...msgs: Bytes[]) => Bytes);
declare function signAsync(msgh: Hex, priv: Hex, opts?: {
    lowS?: boolean | undefined;
    extraEntropy?: boolean | Hex | undefined;
}): Promise<Signature>;
declare function sign(msgh: Hex, priv: Hex, opts?: {
    lowS?: boolean | undefined;
    extraEntropy?: boolean | Hex | undefined;
}): Signature;
type SigLike = {
    r: bigint;
    s: bigint;
};
declare function verify(sig: Hex | SigLike, msgh: Hex, pub: Hex, opts?: {
    lowS?: boolean | undefined;
}): boolean;
declare function getSharedSecret(privA: Hex, pubB: Hex, isCompressed?: boolean): Bytes;
declare function hashToPrivateKey(hash: Hex): Bytes;
declare const etc: {
    hexToBytes: (hex: string) => Bytes;
    bytesToHex: (b: Bytes) => string;
    concatBytes: (...arrs: Bytes[]) => Uint8Array;
    bytesToNumberBE: (b: Bytes) => bigint;
    numberToBytesBE: (num: bigint) => Bytes;
    mod: (a: bigint, b?: bigint) => bigint;
    invert: (num: bigint, md?: bigint) => bigint;
    hmacSha256Async: (key: Bytes, ...msgs: Bytes[]) => Promise<Bytes>;
    hmacSha256Sync: HmacFnSync;
    hashToPrivateKey: typeof hashToPrivateKey;
    randomBytes: (len: number) => Bytes;
};
declare const utils: {
    normPrivateKeyToScalar: (p: PrivKey) => bigint;
    isValidPrivateKey: (key: Hex) => boolean;
    randomPrivateKey: () => Bytes;
    precompute(w?: number, p?: Point): Point;
};
export { getPublicKey, sign, signAsync, verify, CURVE, // Remove the export to easily use in REPL
getSharedSecret, etc, utils, Point as ProjectivePoint, Signature };
