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
    constructor(x: bigint, y: bigint);
    private static fromCompressedHex;
    static isValidPoint(x: bigint, y: bigint): boolean;
    private static fromUncompressedHex;
    static fromHex(hash: Hex): Point;
    static fromPrivateKey(privateKey: PrivKey): Point;
    static fromSignature(hash: Hex, signature: Signature, recovery: number | bigint): Point | undefined;
    private uncompressedHex;
    private compressedHex;
    toRawBytes(isCompressed?: boolean): Uint8Array;
    toHex(isCompressed?: boolean): string;
    add(other: Point): Point;
    private double;
    multiply(scalar: number | bigint | Uint8Array): Point;
}
export declare class SignResult {
    r: bigint;
    s: bigint;
    constructor(r: bigint, s: bigint);
    static fromHex(hex: Hex): SignResult;
    private formatLength;
    private formatNumberToHex;
    toHex(): string;
}
export declare const BASE_POINT: Point;
export declare function recoverPublicKey(hash: Hex, signature: Signature, recovery: number | bigint): Uint8Array | undefined;
export declare function getPublicKey(privateKey: Uint8Array | bigint | number, isCompressed?: boolean): Uint8Array;
export declare function getPublicKey(privateKey: string, isCompressed?: boolean): string;
export declare function getSharedSecret(privateA: PrivKey, publicB: PubKey): Uint8Array;
declare type Options = {
    recovered: true;
    canonical?: true;
    k?: number | bigint;
};
declare type OptionsWithK = Partial<Options>;
export declare function sign(hash: Hex, privateKey: PrivKey, { k, recovered, canonical }?: OptionsWithK): Promise<Hex | [Hex, bigint]>;
export declare function verify(signature: Signature, hash: Hex, publicKey: PubKey): boolean;
export {};
