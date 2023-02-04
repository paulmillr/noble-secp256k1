# noble-secp256k1 ![Node CI](https://github.com/paulmillr/noble-secp256k1/workflows/Node%20CI/badge.svg) [![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)

[Fastest](#speed) JS implementation of [secp256k1](https://www.secg.org/sec2-v2.pdf),
an elliptic curve that could be used for asymmetric encryption,
ECDH key agreement protocol and signature schemes. Supports deterministic **ECDSA** from RFC6979.

Check out [the online demo](https://paulmillr.com/ecc) and blog post: [Learning fast elliptic-curve cryptography in JS](https://paulmillr.com/posts/noble-secp256k1-fast-ecc/).

**2023 update:** version 2 has been released, check out [Upgrading](#upgrading) section.
It features 4x less code and improved security. Some features have been removed.
Use [**noble-curves**](https://github.com/paulmillr/noble-curves)
now if you need big, audited & optimized library with additional features.
Use **noble-secp256k1** if you need stable, frozen, minimal feature set and smaller attack surface.

### This library belongs to _noble_ crypto

> **noble-crypto** — high-security, easily auditable set of contained cryptographic libraries and tools.

- No dependencies, one small file
- Easily auditable TypeScript/JS code
- Supported in all major browsers and stable node.js versions
- All releases are signed with PGP keys
- Check out [homepage](https://paulmillr.com/noble/) & all libraries:
  [curves](https://github.com/paulmillr/noble-curves)
  ([secp256k1](https://github.com/paulmillr/noble-secp256k1),
  [ed25519](https://github.com/paulmillr/noble-ed25519)),
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
  const signature = await secp.signAsync(msgHash, privKey);
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
- [`signature.recoverPublicKey(msgHash)`](#signaturerecoverpublickeyhash)
- [Utilities](#utilities)

#### `getPublicKey(privateKey)`

```typescript
function getPublicKey(
  privateKey: Uint8Array | string | bigint,
  isCompressed = true // Optional argument: default `true` produces 33-byte compressed
): Uint8Array;
```

Creates 33-byte compact public key for the private key.

```js
const privKey = 'a1b770e7a3ba3b751b8f03d8b0712f0b428aa5a81d69efc8c522579f763ba5f4';
getPublicKey(privKey);
getPublicKey(privKey, false);
// Use `PPoint.fromPrivateKey(privateKey)` if you need `PPoint` instead of `Uint8Array`
```

#### `sign(msgHash, privateKey)`

```typescript
function signAsync(  // Available by default
  msgHash: Uint8Array | string, // 32-byte message hash (not the message itself)
  privateKey: Uint8Array | string, // private key that will sign it
  opts?: { lowS: boolean, extraEntropy: boolean | Hex } // optional object with params
): Promise<Signature>;
function sign(       // Not available by default: need to set utils.hmacSha256 first
  msgHash: Uint8Array | string, // 32-byte message hash (not the message itself)
  privateKey: Uint8Array | string, // private key that will sign it
  opts?: { lowS: boolean, extraEntropy: boolean | Hex } // optional object with params
): Signature;
```

Generates low-s deterministic-k RFC6979 ECDSA signature. Use with `extraEntropy: true` to improve security.

```js
const privKey = 'a1b770e7a3ba3b751b8f03d8b0712f0b428aa5a81d69efc8c522579f763ba5f4';
const msgHash = 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
const sig = await signAsync(msgHash, privKey);

// ^ The function is async because we're utilizing built-in HMAC API to not rely on dependencies.
// signSync is disabled by default. To enable it, pass a hmac calculator function
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
// should be `key: Uint8Array, ...messages: Uint8Array[]) => Uint8Array`
secp.utils.hmacSha256Sync = (key, ...msgs) => hmac(sha256, key, secp.utils.concatBytes(...msgs))
secp.sign(msgHash, privKey); // Can be used now

// Malleable signatures, incompatible with BTC/ETH, but compatible with openssl
// `lowS: true` prohibits signatures which have (sig.s >= CURVE.n/2n) because of malleability
const sigM = sign(msgHash, privKey, { lowS: false });

// Signatures with improved security: adds additional entropy `k` for deterministic signature,
// follows section 3.6 of RFC6979. When `true`, it would be filled with 32b from CSPRNG.
// **Strongly recommended** to pass `true` to improve security:
// - No disadvantage: if an entropy generator is broken, sigs would be the same as they are without the option
// - It would help a lot in case there is an error somewhere in `k` gen. Exposing `k` could leak private keys
// - Sigs with extra entropy would have different `r` / `s`, which means they
//   would still be valid, but may break some test vectors if you're cross-testing against other libs
const sigE = sign(msgHash, privKey, { extraEntropy: true });
```

#### `verify(signature, msgHash, publicKey)`

```typescript
function verify(
  signature: Uint8Array | string | Signature, // Signature is returned by sign()
  msgHash: Uint8Array | string, // message hash (not the message) that must be verified
  publicKey: Uint8Array | string | Point, // public (not private) key
  opts?: { lowS: boolean } // if a signature.s must be in the lower-half of CURVE.n. Used in BTC, ETH
                           // lowS: false should only be used if you need openSSL-compatible signatures
): boolean; // `true` if `signature` is valid for `hash` and `publicKey`; otherwise `false`
```

Verifies signatures against message and public key.

```js
const privKey = 'a1b770e7a3ba3b751b8f03d8b0712f0b428aa5a81d69efc8c522579f763ba5f4';
const msgHash = 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
const pub = getPublicKey(privKey);
const sig = await signAsync(msgHash, privKey);
const isValid = verify(sig, msgHash, pub);
```

#### `getSharedSecret(privateKeyA, publicKeyB)`

```typescript
function getSharedSecret(
  privateKeyA: Uint8Array | string, // Alices's private key
  publicKeyB: Uint8Array | string, // Bob's public key
  isCompressed = true // optional arg; `true` default returns 33 byte keys, `false` can return 65-byte
): Uint8Array; // Use Point.fromHex(publicKeyB).mul(privateKeyA) if you need Point instance
```

Computes ECDH (Elliptic Curve Diffie-Hellman) shared secret between key A and different key B.

```js
const privKey = 'a1b770e7a3ba3b751b8f03d8b0712f0b428aa5a81d69efc8c522579f763ba5f4';
const alicesPubkey = getPublicKey(utils.randomPrivateKey());
getSharedSecret(privKey, alicesPubkey);
```

#### `Signature.recoverPublicKey(hash)`

```typescript
signature.recoverPublicKey(
  msgHash: Uint8Array | string
): Uint8Array | undefined;
```

`Signature` instance method, recovers public key from message hash. Returns 33-byte compact key.

```js
const privKey = 'a1b770e7a3ba3b751b8f03d8b0712f0b428aa5a81d69efc8c522579f763ba5f4';
const msgHash = 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
const sig = await sign(msgHash, privKey);
sig.recoverPublicKey(msgHash);
```

#### Utilities

The package exposes a few internal utilities for improved developer experience.

```typescript
secp.utils {
  randomPrivateKey: () => Uint8Array; // Returns secure key from CSPRNG
  randomBytes: (bytesLength?: number) => Uint8Array; // Returns secure bytes from CSPRNG
  isValidPrivateKey(privateKey: PrivKey): boolean;
  mod(number: number | bigint, modulo = CURVE.P): bigint; // Modular division
  invert(number: bigint, modulo?: bigint): bigint; // Modular inversion
  hmacSha256(key: Uint8Array, ...messages: Uint8Array[]) => Promise<Uint8Array>;
  hmacSha256Sync: undefined; // Must be specified if you need `signSync` to work, args are same
  bytesToHex(bytes: Uint8Array): string; // If you need hex string as an output
};
secp.CURVE { P, n, a, b, Gx, Gy }; // CURVE prime; order; equation params; generator coordinates
secp.PPoint { // Elliptic curve point in Projective (x, y, z) coordinates.
  constructor(x: bigint, y: bigint, z?: bigint);
  static fromHex(hex: Uint8Array | string);
  static fromPrivateKey(privateKey: Uint8Array | string | number | bigint);
  ok(): PPoint; // checks Point validity
  toRawBytes(isCompressed = false): Uint8Array;
  toHex(isCompressed = false): string;
  eql(other: Point): boolean; // a.equals(b)
  neg(): Point; // negate
  add(other: Point): Point; // addition
  mul(scalar: bigint): Point; // constant-time scalar multiplication
}
secp.Signature {
  constructor(r: bigint, s: bigint, recovery?: number);
  static fromCompact(hex: Uint8Array | string); // R, S 32-byte each
  ok(): Signature; // checks Signature validity
  toCompactRawBytes(): Uint8Array; // R, S 32-byte each
  toCompactHex(): string; // same, in hex string
}
```

## Security

Noble is production-ready.

1. The library, as per version 1.2.0, has been audited by an independent security firm cure53: [PDF](https://cure53.de/pentest-report_noble-lib.pdf). See [changes since audit](https://github.com/paulmillr/noble-secp256k1/compare/1.2.0..main).
   - The audit has been [crowdfunded](https://gitcoin.co/grants/2451/audit-of-noble-secp256k1-cryptographic-library) by community with help of [Umbra.cash](https://umbra.cash).
2. The library has also been fuzzed by [Guido Vranken's cryptofuzz](https://github.com/guidovranken/cryptofuzz). You can run the fuzzer by yourself to check it.

We're using built-in JS `BigInt`, which is potentially vulnerable to [timing attacks](https://en.wikipedia.org/wiki/Timing_attack) as [per official spec](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt#cryptography). But, _JIT-compiler_ and _Garbage Collector_ make "constant time" extremely hard to achieve in a scripting language. Which means _any other JS library doesn't use constant-time bigints_. Including bn.js or anything else. Even statically typed Rust, a language without GC, [makes it harder to achieve constant-time](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security) for some cases. If your goal is absolute security, don't use any JS lib — including bindings to native ones. Use low-level libraries & languages. Nonetheless we've hardened implementation of ec curve multiplication to be algorithmically constant time.

We however consider infrastructure attacks like rogue NPM modules very important; that's why it's crucial to minimize the amount of 3rd-party dependencies & native bindings. If your app uses 500 dependencies, any dep could get hacked and you'll be downloading malware with every `npm install`. Our goal is to minimize this attack vector.

## Speed

Benchmarks measured with Apple M2 on MacOS 12 with node.js 18.10.

    getPublicKey(utils.randomPrivateKey()) x 5,030 ops/sec @ 198μs/op
    sign x 4,046 ops/sec @ 247μs/op
    verify x 479 ops/sec @ 2ms/op
    getSharedSecret x 405 ops/sec @ 2ms/op
    recoverPublicKey x 487 ops/sec @ 2ms/op
    Point.fromHex (decompression) x 7,642 ops/sec @ 130μs/op

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
    - `der` has been removed. DER encoding is no longer supported. Use compact format (32-byte r + 32-byte s), `Signature` instance methods `toCompactRawBytes` / `toCompactHex()`: `(await sign(msgHash, priv)).toCompactRawBytes()`. Use curves if you still need der
- `verify()`: `strict` option has been renamed to `lowS`, default value is still the same
- `recoverPublicKey(msgHash, sig, recovery)` has been changed to `sig.recoverPublicKey(msgHash)`
- `Point` has been changed to `PPoint`; which now works in 3d xyz projective coordinates instead of
  2d xy affine. Its methods have been renamed: `multiply` to `mul`, `subtract` to `sub` etc. Use curves if you still need affine point
- schnorr signatures, asn.1 DER, custom precomputes have been removed. Use noble-curves if you need them
- Support for environments that can't parse bigint literals has been removed

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
