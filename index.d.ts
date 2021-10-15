/*! noble-secp256k1 - MIT License (c) Paul Miller (paulmillr.com) */
declare const CURVE: {
    a: bigint;
    b: bigint;
    P: bigint;
    n: bigint;
    h: bigint;
    Gx: bigint;
    Gy: bigint;
    beta: bigint;
};
export { CURVE };
declare type Hex = Uint8Array | string;
declare type PrivKey = Hex | bigint | number;
declare type PubKey = Hex | Point;
declare type Sig = Hex | Signature;
export declare class Point {
    x: bigint;
    y: bigint;
    static BASE: Point;
    static ZERO: Point;
    _WINDOW_SIZE?: number;
    constructor(x: bigint, y: bigint);
    _setWindowSize(windowSize: number): void;
    private static fromCompressedHex;
    private static fromUncompressedHex;
    static fromHex(hex: Hex): Point;
    static fromPrivateKey(privateKey: PrivKey): Point;
    static fromSignature(msgHash: Hex, signature: Sig, recovery: number): Point;
    toRawBytes(isCompressed?: boolean): Uint8Array;
    toHex(isCompressed?: boolean): string;
    toHexX(): string;
    toRawX(): Uint8Array;
    assertValidity(): void;
    equals(other: Point): boolean;
    negate(): Point;
    double(): Point;
    add(other: Point): Point;
    subtract(other: Point): Point;
    multiply(scalar: number | bigint): Point;
}
export declare class Signature {
    r: bigint;
    s: bigint;
    constructor(r: bigint, s: bigint);
    static fromCompact(hex: Hex): Signature;
    static fromDER(hex: Hex): Signature;
    static fromHex(hex: Hex): Signature;
    assertValidity(): void;
    toDERRawBytes(isCompressed?: boolean): Uint8Array;
    toDERHex(isCompressed?: boolean): string;
    toRawBytes(): Uint8Array;
    toHex(): string;
    toCompactRawBytes(): Uint8Array;
    toCompactHex(): string;
}
export declare const SignResult: typeof Signature;
declare type U8A = Uint8Array;
export declare function getPublicKey(privateKey: Uint8Array | number | bigint, isCompressed?: boolean): Uint8Array;
export declare function getPublicKey(privateKey: string, isCompressed?: boolean): string;
export declare function recoverPublicKey(msgHash: string, signature: string, recovery: number): string | undefined;
export declare function recoverPublicKey(msgHash: Uint8Array, signature: Uint8Array, recovery: number): Uint8Array | undefined;
export declare function getSharedSecret(privateA: PrivKey, publicB: PubKey, isCompressed?: boolean): Hex;
declare type OptsRecov = {
    recovered: true;
    canonical?: true;
    der?: boolean;
};
declare type OptsNoRecov = {
    recovered?: false;
    canonical?: true;
    der?: boolean;
};
declare function sign(msgHash: U8A, privKey: PrivKey, opts: OptsRecov): Promise<[U8A, number]>;
declare function sign(msgHash: string, privKey: PrivKey, opts: OptsRecov): Promise<[string, number]>;
declare function sign(msgHash: U8A, privKey: PrivKey, opts?: OptsNoRecov): Promise<U8A>;
declare function sign(msgHash: string, privKey: PrivKey, opts?: OptsNoRecov): Promise<string>;
declare function sign(msgHash: string, privKey: PrivKey, opts?: OptsNoRecov): Promise<string>;
declare function signSync(msgHash: U8A, privKey: PrivKey, opts: OptsRecov): [U8A, number];
declare function signSync(msgHash: string, privKey: PrivKey, opts: OptsRecov): [string, number];
declare function signSync(msgHash: U8A, privKey: PrivKey, opts?: OptsNoRecov): U8A;
declare function signSync(msgHash: string, privKey: PrivKey, opts?: OptsNoRecov): string;
declare function signSync(msgHash: string, privKey: PrivKey, opts?: OptsNoRecov): string;
export { sign, signSync };
export declare function verify(signature: Sig, msgHash: Hex, publicKey: PubKey): boolean;
declare class SchnorrSignature {
    readonly r: bigint;
    readonly s: bigint;
    constructor(r: bigint, s: bigint);
    static fromHex(hex: Hex): SchnorrSignature;
    toHex(): string;
    toRawBytes(): Uint8Array;
}
declare function schnorrGetPublicKey(privateKey: Uint8Array): Uint8Array;
declare function schnorrGetPublicKey(privateKey: string): string;
declare function schnorrSign(msgHash: string, privateKey: string, auxRand?: Hex): Promise<string>;
declare function schnorrSign(msgHash: Uint8Array, privateKey: Uint8Array, auxRand?: Hex): Promise<Uint8Array>;
declare function schnorrVerify(signature: Hex, msgHash: Hex, publicKey: Hex): Promise<boolean>;
export declare const schnorr: {
    Signature: typeof SchnorrSignature;
    getPublicKey: typeof schnorrGetPublicKey;
    sign: typeof schnorrSign;
    verify: typeof schnorrVerify;
};
declare type Sha256FnSync = undefined | ((...messages: Uint8Array[]) => Uint8Array);
declare type HmacFnSync = undefined | ((key: Uint8Array, ...messages: Uint8Array[]) => Uint8Array);
export declare const utils: {
    isValidPrivateKey(privateKey: PrivKey): boolean;
    randomBytes: (bytesLength?: number) => Uint8Array;
    randomPrivateKey: () => Uint8Array;
    sha256: (message: Uint8Array) => Promise<Uint8Array>;
    hmacSha256: (key: Uint8Array, ...messages: Uint8Array[]) => Promise<Uint8Array>;
    sha256Sync: Sha256FnSync;
    hmacSha256Sync: HmacFnSync;
    precompute(windowSize?: number, point?: Point): Point;
};
