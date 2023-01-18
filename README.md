# noble-secp256k1 ![Node CI](https://github.com/paulmillr/noble-secp256k1/workflows/Node%20CI/badge.svg) [![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)

[Fastest](#speed) JS implementation of [secp256k1](https://www.secg.org/sec2-v2.pdf),
an elliptic curve that could be used for asymmetric encryption,
ECDH key agreement protocol and signature schemes. Supports deterministic **ECDSA** from RFC6979.

[**Audited**](#security) by an independent security firm. Check out [the online demo](https://paulmillr.com/ecc) and blog post: [Learning fast elliptic-curve cryptography in JS](https://paulmillr.com/posts/noble-secp256k1-fast-ecc/).

**2023 update:** version 2 has been released. It features 4x less code and improved security.
Some features have been removed. Use [**noble-curves**](https://github.com/paulmillr/noble-curves)
if you need big, audited & optimized library. Use **noble-secp256k1** if you need
stable, frozen, minimal feature set and smaller attack surface.
Check out [Upgrading](#upgrading) section.

### This library belongs to _noble_ crypto

> **noble-crypto** — high-security, easily auditable set of contained cryptographic libraries and tools.

- No dependencies, one small file
- Easily auditable TypeScript/JS code
- Supported in all major browsers and stable node.js versions
- All releases are signed with PGP keys
- Check out [homepage](https://paulmillr.com/noble/) & all libraries:
  [curves](https://github.com/paulmillr/noble-curves) ([secp256k1](https://github.com/paulmillr/noble-secp256k1),
  [ed25519](https://github.com/paulmillr/noble-ed25519),
  [bls12-381](https://github.com/paulmillr/noble-bls12-381)) and
  [hashes](https://github.com/paulmillr/noble-hashes)

## Usage

Use NPM in node.js / browser, or include single file from
[GitHub's releases page](https://github.com/paulmillr/noble-secp256k1/releases):

> npm install @noble/secp256k1

```js
// Common.js and ECMAScript Modules (ESM)
import * as secp from '@noble/secp256k1';
// If you're using single file, use global variable instead: `window.nobleSecp256k1`

// Supports both async and sync methods, see docs
(async () => {
  // keys, messages & other inputs can be Uint8Arrays or hex strings
  // Uint8Array.from([0xde, 0xad, 0xbe, 0xef]) === 'deadbeef'
  const privKey = secp.utils.randomPrivateKey();
  const pubKey = secp.getPublicKey(privKey);
  // sha256 of 'hello world'
  const msgHash = 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
  const signature = await secp.sign(msgHash, privKey);
  const isValid = secp.verify(signature, msgHash, pubKey);
})();
```

To use the module with [Deno](https://deno.land),
you will need [import map](https://deno.land/manual/linking_to_external_code/import_maps):

- `deno run --import-map=imports.json app.ts`
- app.ts: `import * as secp from "https://deno.land/x/secp256k1/mod.ts";`
- imports.json: `{"imports": {"crypto": "https://deno.land/std@0.153.0/node/crypto.ts"}}`

## API

- [`getPublicKey(privateKey)`](#getpublickeyprivatekey)
- [`sign(msgHash, privateKey)`](#signmsghash-privatekey)
- [`verify(signature, msgHash, publicKey)`](#verifysignature-msghash-publickey)
- [`getSharedSecret(privateKeyA, publicKeyB)`](#getsharedsecretprivatekeya-publickeyb)
- [`signature.recoverPublicKey(msgHash)`](#recoverpublickeyhash-signature-recovery)
- [Utilities](#utilities)

##### `getPublicKey(privateKey)`

```typescript
function getPublicKey(privateKey: Uint8Array | string | bigint, isCompressed = true): Uint8Array;
```

Creates public key for the corresponding private key. The default is full 33-byte key.
Set second argument to `false` if you need full (65-byte) key. Use `PPoint.fromPrivateKey(privateKey)`
if you need `PPoint` instead of `Uint8Array`

##### `sign(msgHash, privateKey)`

```typescript
function sign(
  msgHash: Uint8Array | string,
  privateKey: Uint8Array | string,
  opts?: { lowS: boolean, extraEntropy: boolean | Hex }
): Promise<Signature>;
```

Generates low-s deterministic ECDSA signature as per RFC6979.

- `msgHash: Uint8Array | string` - 32-byte message hash which would be signed
- `privateKey: Uint8Array | string | bigint` - private key which will sign the hash
- `options?: Options` - _optional_ object related to signature value and format with following keys:
  - `lowS: boolean = true` - whether a signature `s` should be no more than 1/2 prime order.
    `true` (default) makes signatures compatible with libsecp256k1,
    `false` makes signatures compatible with openssl
  - `extraEntropy: Uint8Array | string | true` - additional entropy `k'` for deterministic signature, follows section 3.6 of RFC6979. When `true`, it would automatically be filled with 32 bytes of cryptographically secure entropy. **Strongly recommended** to pass `true` to improve security:
    - It would help a lot in case there is an error somewhere in `k` generation. Exposing `k` could leak private keys
    - If the entropy generator is broken, signatures would be the same as they are without the option
    - Signatures with extra entropy would have different `r` / `s`, which means they
      would still be valid, but may break some test vectors if you're cross-testing against other libs

The function is asynchronous because we're utilizing built-in HMAC API to not rely on dependencies.

```ts
(async () => {
  // Signatures with improved security
  const signatureE = await secp.sign(msgHash, privKey, { extraEntropy: true });
  // Malleable signatures, but compatible with openssl
  const signatureM = await secp.sign(msgHash, privKey, { lowS: false });
})();
```

```typescript
function signSync(
  msgHash: Uint8Array | string,
  privateKey: Uint8Array | string,
  opts?: { lowS: boolean, extraEntropy: boolean | Hex }
): Signature;
```

`signSync` counterpart could also be used, you need to set `utils.hmacSha256Sync` to a function with signature `key: Uint8Array, ...messages: Uint8Array[]) => Uint8Array`. Example with `noble-hashes` package:

```ts
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
secp.utils.hmacSha256Sync = (key, ...msgs) => hmac(sha256, key, secp256k1.utils.concatBytes(...msgs))
secp.signSync(msgHash, privateKey); // Can be used now
```

##### `verify(signature, msgHash, publicKey)`

```typescript
function verify(
  signature: Uint8Array | string | Signature,
  msgHash: Uint8Array | string,
  publicKey: Uint8Array | string | Point,
  opts?: { lowS: boolean }
): boolean;
```

- `signature: Uint8Array | string | { r: bigint, s: bigint }` - object returned by the `sign` function
- `msgHash: Uint8Array | string` - message hash that needs to be verified
- `publicKey: Uint8Array | string | Point` - e.g. that was generated from `privateKey` by `getPublicKey`
- `options?: Options` - _optional_ object related to signature value and format
  - `lowS: boolean = true` - whether a signature `s` should be no more than 1/2 prime order.
    `true` (default) makes signatures compatible with libsecp256k1,
    `false` makes signatures compatible with openssl
- Returns `boolean`: `true` if `signature == hash`; otherwise `false`

##### `getSharedSecret(privateKeyA, publicKeyB)`

```typescript
function getSharedSecret(
  privateKeyA: Uint8Array | string | bigint,
  publicKeyB: Uint8Array | string | Point,
  isCompressed = true
): Uint8Array;
```

Computes ECDH (Elliptic Curve Diffie-Hellman) shared secret between a private key and a different public key.

- To get Point instance, use `Point.fromHex(publicKeyB).multiply(privateKeyA)`
- `isCompressed = true` determines whether to return compact (33-byte), or full (65-byte) key

##### `Signature.recoverPublicKey(hash)`

```typescript
signature.recoverPublicKey(msgHash: Uint8Array | string): Uint8Array | undefined;
```

`Signature` instance method, recovers public key from message hash.

- `msgHash: Uint8Array | string` - message hash which would be signed
- `isCompressed = false` determines whether to return compact (33-byte), or full (65-byte) key

Public key is generated by doing scalar multiplication of a base Point(x, y) by a fixed
integer. The result is another `Point(x, y)` which we will by default encode to hex Uint8Array.
If signature is invalid - function will return `undefined` as result.

#### Utilities

secp256k1 exposes a few internal utilities for improved developer experience.

```js
// Default output is Uint8Array. If you need hex string as an output:
console.log(secp.utils.bytesToHex(pubKey));
```

```typescript
const utils: {
  // Returns `Uint8Array` of 32 cryptographically secure random bytes that can be used as private key
  randomPrivateKey: () => Uint8Array;
  // Checks private key for validity
  isValidPrivateKey(privateKey: PrivKey): boolean;

  // Returns `Uint8Array` of x cryptographically secure random bytes.
  randomBytes: (bytesLength?: number) => Uint8Array;
  // Converts Uint8Array to hex string
  bytesToHex(uint8a: Uint8Array): string;
  hexToBytes(hex: string): Uint8Array;
  concatBytes(...arrays: Uint8Array[]): Uint8Array;
  // Modular division over curve prime
  mod: (number: number | bigint, modulo = CURVE.P): bigint;
  // Modular inversion
  invert(number: bigint, modulo?: bigint): bigint;

  hmacSha256: (key: Uint8Array, ...messages: Uint8Array[]) => Promise<Uint8Array>;

  // You can set up your synchronous methods for `signSync` to work.
  // The argument order is identical to async methods from above
  hmacSha256Sync: undefined;
};

secp256k1.CURVE.P // Field, 2 ** 256 - 2 ** 32 - 977
secp256k1.CURVE.n // Order, 2 ** 256 - 432420386565659656852420866394968145599
secp256k1.PPoint.G // new secp256k1.Point(Gx, Gy) where
// Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240n
// Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424n;

// Elliptic curve point in Affine (x, y) coordinates.
secp256k1.PPoint {
  constructor(x: bigint, y: bigint, z?: bigint);
  // Supports compressed and non-compressed hex
  static fromHex(hex: Uint8Array | string);
  static fromPrivateKey(privateKey: Uint8Array | string | number | bigint);
  static fromSignature(
    msgHash: Hex,
    signature: Signature,
    recovery: number | bigint
  ): Point | undefined {
  toRawBytes(isCompressed = false): Uint8Array;
  toHex(isCompressed = false): string;
  equals(other: Point): boolean;
  negate(): Point;
  add(other: Point): Point;
  subtract(other: Point): Point;
  // Constant-time scalar multiplication.
  multiply(scalar: bigint | Uint8Array): Point;
}
secp256k1.Signature {
  constructor(r: bigint, s: bigint);
  // R, S 32-byte each
  static fromCompact(hex: Uint8Array | string);
  ok(): void;
  toDERRawBytes(): Uint8Array;
  toDERHex(): string;
  toCompactRawBytes(): Uint8Array;
  toCompactHex(): string;
}
```

## Security

Noble is production-ready.

1. The library has been audited by an independent security firm cure53: [PDF](https://cure53.de/pentest-report_noble-lib.pdf). See [changes since audit](https://github.com/paulmillr/noble-secp256k1/compare/1.2.0..main).
   - The audit has been [crowdfunded](https://gitcoin.co/grants/2451/audit-of-noble-secp256k1-cryptographic-library) by community with help of [Umbra.cash](https://umbra.cash).
2. The library has also been fuzzed by [Guido Vranken's cryptofuzz](https://github.com/guidovranken/cryptofuzz). You can run the fuzzer by yourself to check it.

We're using built-in JS `BigInt`, which is potentially vulnerable to [timing attacks](https://en.wikipedia.org/wiki/Timing_attack) as [per official spec](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt#cryptography). But, _JIT-compiler_ and _Garbage Collector_ make "constant time" extremely hard to achieve in a scripting language. Which means _any other JS library doesn't use constant-time bigints_. Including bn.js or anything else. Even statically typed Rust, a language without GC, [makes it harder to achieve constant-time](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security) for some cases. If your goal is absolute security, don't use any JS lib — including bindings to native ones. Use low-level libraries & languages. Nonetheless we've hardened implementation of ec curve multiplication to be algorithmically constant time.

We however consider infrastructure attacks like rogue NPM modules very important; that's why it's crucial to minimize the amount of 3rd-party dependencies & native bindings. If your app uses 500 dependencies, any dep could get hacked and you'll be downloading malware with every `npm install`. Our goal is to minimize this attack vector.

## Speed

Benchmarks measured with Apple M2 on MacOS 12 with node.js 18.8.

    getPublicKey(utils.randomPrivateKey()) x 7,093 ops/sec @ 140μs/op
    sign x 5,615 ops/sec @ 178μs/op
    signSync (@noble/hashes) x 5,209 ops/sec @ 191μs/op
    verify x 1,114 ops/sec @ 896μs/op
    recoverPublicKey x 1,018 ops/sec @ 982μs/op
    getSharedSecret aka ecdh x 665 ops/sec @ 1ms/op
    getSharedSecret (precomputed) x 7,426 ops/sec @ 134μs/op
    Point.fromHex (decompression) x 14,582 ops/sec @ 68μs/op
    schnorr.sign x 805 ops/sec @ 1ms/op
    schnorr.verify x 1,129 ops/sec @ 885μs/op

Compare to other libraries on M1 (`openssl` uses native bindings, not JS):

    elliptic#getPublicKey x 1,940 ops/sec
    sjcl#getPublicKey x 211 ops/sec

    elliptic#sign x 1,808 ops/sec
    sjcl#sign x 199 ops/sec
    openssl#sign x 4,243 ops/sec
    ecdsa#sign x 116 ops/sec
    bip-schnorr#sign x 60 ops/sec

    elliptic#verify x 812 ops/sec
    sjcl#verify x 166 ops/sec
    openssl#verify x 4,452 ops/sec
    ecdsa#verify x 80 ops/sec
    bip-schnorr#verify x 56 ops/sec

    elliptic#ecdh x 971 ops/sec

## Contributing

Check out a blog post about this library: [Learning fast elliptic-curve cryptography in JS](https://paulmillr.com/posts/noble-secp256k1-fast-ecc/).

1. Clone the repository.
2. `npm install` to install build dependencies like TypeScript
3. `npm run build` to compile TypeScript code
4. `npm test` to run jest on `test/index.ts`

Special thanks to [Roman Koblov](https://github.com/romankoblov), who have helped to improve scalar multiplication speed.

## Upgrading

noble-secp256k1 v2.0 has been reduced 4x to just over 400 lines. It features improved security and smaller attack surface.

Some functionality present in v1, such as schnorr and DER, was removed: use [**noble-curves**](https://github.com/paulmillr/noble-curves) if you still need it.

- `getPublicKey()` and `getSharedSecret()` now produce compressed 33-byte signatures by default. If you
  need the old 65-byte behavior, set `isCompressed` option as `false`: `getPublicKey(priv, false)`, `getSharedSecret(a, b, false)`
- `sign()`: now returns `Signature` instance with `{ r, s, rec }` properties. It could still be passed to `verify` as-is.
    - `canonical` has been renamed to `lowS`. The default value is the same as before: `lowS: true`
    - `recovered` has been removed. Recovery bit is always returned in the `Signature` instance
    - `der` has been removed. DER encoding is no longer supported. Use compact format (32-byte r + 32-byte s), `Signature` instance methods `toCompactRawBytes` / `toCompactHex()`: `(await sign(msgHash, priv)).toCompactRawBytes()`
- `verify()`: `strict` option has been renamed to `lowS`, default value is still the same
- `recoverPublicKey(msgHash, sig, recovery)` has been changed to `sig.recoverPublicKey(msgHash)`
- `Point` has been changed to `PPoint`; which now works in 3d xyz projective coordinates instead of
  2d xy affine. Its methods have been renamed: `multiply` to `mul`, `subtract` to `sub` etc.
- Schnorr signature scheme has been removed
- asn.1 DER encoding has been removed
- Errors are sometimes thrown with empty messages and longer stack traces
- Support for environments that can't parse bigint literals has been removed

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
