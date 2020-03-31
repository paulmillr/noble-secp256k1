export declare const CURVE_PARAMS: {
    a: bigint;
    b: bigint;
    P: bigint;
    n: bigint;
    h: bigint;
    Gx: bigint;
    Gy: bigint;
};
declare type PrivKey = Uint8Array | string | bigint | number;
declare type PubKey = Uint8Array | string | Point;
declare type Hex = Uint8Array | string;
declare type Signature = Uint8Array | string | SignResult;
declare class JacobianPoint {
    x: bigint;
    y: bigint;
    z: bigint;
    static ZERO_POINT: JacobianPoint;
    static fromAffine(p: Point): JacobianPoint;
    constructor(x: bigint, y: bigint, z: bigint);
    static batchAffine(points: JacobianPoint[]): Point[];
    equals(other: JacobianPoint): boolean;
    negate(): JacobianPoint;
    double(): JacobianPoint;
    add(other: JacobianPoint): JacobianPoint;
    multiplyUnsafe(scalar: bigint): JacobianPoint;
    toAffine(invZ?: bigint): Point;
}
export declare class Point {
    x: bigint;
    y: bigint;
    static BASE_POINT: Point;
    static ZERO_POINT: Point;
    private WINDOW_SIZE?;
    private PRECOMPUTES?;
    constructor(x: bigint, y: bigint);
    _setWindowSize(windowSize: number): void;
    static isValid(x: bigint, y: bigint): boolean;
    private static fromCompressedHex;
    private static fromUncompressedHex;
    static fromHex(hex: Hex): Point;
    static fromPrivateKey(privateKey: PrivKey): Point;
    static fromSignature(msgHash: Hex, signature: Signature, recovery: number): Point | undefined;
    toRawBytes(isCompressed?: boolean): Uint8Array;
    toHex(isCompressed?: boolean): string;
    equals(other: Point): boolean;
    negate(): Point;
    double(): Point;
    add(other: Point): Point;
    subtract(other: Point): Point;
    private precomputeWindow;
    multiply(scalar: bigint, isAffine: false): JacobianPoint;
    multiply(scalar: bigint, isAffine?: true): Point;
}
export declare class SignResult {
    r: bigint;
    s: bigint;
    constructor(r: bigint, s: bigint);
    static fromHex(hex: Hex): SignResult;
    toRawBytes(isCompressed?: boolean): Uint8Array;
    toHex(isCompressed?: boolean): string;
}
export declare function getPublicKey(privateKey: Uint8Array | bigint | number, isCompressed?: boolean): Uint8Array;
export declare function getPublicKey(privateKey: string, isCompressed?: boolean): string;
export declare function recoverPublicKey(msgHash: string, signature: string, recovery: number): string | undefined;
export declare function recoverPublicKey(msgHash: Uint8Array, signature: Uint8Array, recovery: number): Uint8Array | undefined;
export declare function getSharedSecret(privateA: PrivKey, publicB: PubKey): Uint8Array | string;
declare type OptsRecovered = {
    recovered: true;
    canonical?: true;
};
declare type OptsNoRecovered = {
    recovered?: false;
    canonical?: true;
};
export declare function sign(msgHash: Uint8Array, privateKey: PrivKey, opts: OptsRecovered): Promise<[Uint8Array, number]>;
export declare function sign(msgHash: string, privateKey: PrivKey, opts: OptsRecovered): Promise<[string, number]>;
export declare function sign(msgHash: Uint8Array, privateKey: PrivKey, opts?: OptsNoRecovered): Promise<Uint8Array>;
export declare function sign(msgHash: string, privateKey: PrivKey, opts?: OptsNoRecovered): Promise<string>;
export declare function sign(msgHash: string, privateKey: PrivKey, opts?: OptsNoRecovered): Promise<string>;
export declare function verify(signature: Signature, msgHash: Hex, publicKey: PubKey): boolean;
export declare const utils: {
    isValidPrivateKey(privateKey: PrivKey): boolean;
    generateRandomPrivateKey: (bytesLength?: number) => Uint8Array;
    precompute(windowSize?: number, point?: Point): Point;
};
export {};
