/*! noble-secp256k1 - MIT License (c) Paul Miller (paulmillr.com) */
export declare const P: bigint;
export declare const PRIME_ORDER: bigint;
declare type PrivKey = Uint8Array | string | bigint | number;
declare type PubKey = Uint8Array | string | Point;
declare type Hex = Uint8Array | string;
declare type Signature = Uint8Array | string | SignResult;
export declare class Point {
    x: bigint;
    y: bigint;
    W?: number;
    private PRECOMPUTES?;
    constructor(x: bigint, y: bigint);
    static isValidPoint(x: bigint, y: bigint): boolean;
    private static fromCompressedHex;
    private static fromUncompressedHex;
    static fromHex(hex: Hex): Point;
    static fromPrivateKey(privateKey: PrivKey): Point;
    static fromSignature(msgHash: Hex, signature: Signature, recovery: number): Point | undefined;
    toRawBytes(isCompressed?: boolean): Uint8Array;
    toHex(isCompressed?: boolean): string;
    negate(): Point;
    add(other: Point): Point;
    subtract(other: Point): Point;
    private double;
    private isZero;
    private precomputeWindow;
    multiply(scalar: number | bigint): Point;
}
export declare class SignResult {
    r: bigint;
    s: bigint;
    constructor(r: bigint, s: bigint);
    static fromHex(hex: Hex): SignResult;
    toHex(compressed?: boolean): string;
}
export declare const BASE_POINT: Point;
export declare function recoverPublicKey(msgHash: string, signature: string, recovery: number): string | undefined;
export declare function recoverPublicKey(msgHash: Uint8Array, signature: Uint8Array, recovery: number): Uint8Array | undefined;
export declare function getPublicKey(privateKey: Uint8Array | bigint | number, isCompressed?: boolean): Uint8Array;
export declare function getPublicKey(privateKey: string, isCompressed?: boolean): string;
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
    precompute(W?: number, point?: Point): true;
};
export {};
