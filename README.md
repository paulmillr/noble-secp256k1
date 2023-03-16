# noble-secp256k1 ![Node CI](https://github.com/paulmillr/noble-secp256k1/workflows/Node%20CI/badge.svg) [![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)

[Fastest](#speed) 4KB JS implementation of [secp256k1](https://www.secg.org/sec2-v2.pdf),
an elliptic curve that could be used for asymmetric encryption,
ECDH key agreement protocol and signature schemes. Supports deterministic **ECDSA** from RFC6979.

The library does not use dependencies and is as minimal as possible.
[noble-curves](https://github.com/paulmillr/noble-curves) is advanced drop-in
replacement for noble-secp256k1 with more features such as Schnorr signatures,
DER encoding and support for different hash functions.

Check out: [Upgrading](#upgrading) section for v1 to v2 transition instructions;
[the online demo](https://paulmillr.com/ecc) and blog post
[Learning fast elliptic-curve cryptography in JS](https://paulmillr.com/posts/noble-secp256k1-fast-ecc/).

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

Use NPM in browser and node.js:

> npm install @noble/secp256k1

For [Deno](https://deno.land), the module is available at `x/secp256k1`;
or you can use [npm specifier](https://deno.land/manual@v1.28.0/node/npm_specifiers).

```js
import * as secp from '@noble/secp256k1'; // ESM-only. Use bundler for common.js
(async () => {
  // keys, messages & other inputs can be Uint8Arrays or hex strings
  // Uint8Array.from([0xde, 0xad, 0xbe, 0xef]) === 'deadbeef'
  const privKey = secp.utils.randomPrivateKey(); // Secure random private key
  // sha256 of 'hello world'
  const msgHash = 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
  const pubKey = secp.getPublicKey(privKey); // Make pubkey from the private key 
  const signature = await secp.signAsync(msgHash, privKey); // sign
  const isValid = secp.verify(signature, msgHash, pubKey); // verify

  const pubKey2 = getPublicKey(secp.utils.randomPrivateKey()); // Key of user 2
  secp.getSharedSecret(privKey, alicesPubkey); // Elliptic curve diffie-hellman
  signature.recoverPublicKey(msgHash); // Public key recovery
})();
```

Advanced examples:

```ts
// 1. Use the shim to enable synchronous methods.
// Only async methods are available by default to keep library dependency-free.
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
secp.etc.hmacSha256Sync = (k, ...m) => hmac(sha256, k, secp.etc.concatBytes(...m))
const signature2 = secp.sign(msgHash, privKey); // Can be used now

// 2. Use the shim only for node.js <= 18 BEFORE importing noble-secp256k1.
// The library depends on global variable crypto to work. It is available in
// all browsers and many environments, but node.js <= 18 don't have it.
import { webcrypto } from 'node:crypto';
// @ts-ignore
if (!globalThis.crypto) globalThis.crypto = webcrypto;

// Other stuff
// Malleable signatures, incompatible with BTC/ETH, but compatible with openssl
// `lowS: true` prohibits signatures which have (sig.s >= CURVE.n/2n) because of
// malleability
const signatureMalleable = secp.sign(msgHash, privKey, { lowS: false });

// Signatures with improved security: adds additional entropy `k` for
// deterministic signature, follows section 3.6 of RFC6979. When `true`, it
// would be filled with 32b from CSPRNG. **Strongly recommended** to pass `true`
// to improve security:
// - No disadvantage: if an entropy generator is broken, sigs would be the same
//   as they are without the option
// - It would help a lot in case there is an error somewhere in `k` gen.
//   Exposing `k` could leak private keys
// - Sigs with extra entropy would have different `r` / `s`, which means they
//   would still be valid, but may break some test vectors if you're
//   cross-testing against other libs
const signatureImproved = secp.sign(msgHash, privKey, { extraEntropy: true });
```

## API

There are 3 main methods: `getPublicKey(privateKey)`,
`sign(messageHash, privateKey)` and
`verify(signature, messageHash, publicKey)`.

Only **async methods are available by default** to keep library dependency-free.
To enable sync methods, see below.

```typescript
type Hex = Uint8Array | string;

// Generates 33-byte / 65-byte public key from 32-byte private key.
function getPublicKey(
  privateKey: Hex,
  isCompressed?: boolean // optional arg. (default) true=33b key, false=65b.
): Uint8Array;
function getPublicKeyAsync(
  privateKey: Hex,
  isCompressed?: boolean
): Promise<Uint8Array>;
// Use:
// - `ProjectivePoint.fromPrivateKey(privateKey)` for Point instance
// - `ProjectivePoint.fromHex(publicKey)` to convert hex / bytes into Point.

// Generates low-s deterministic-k RFC6979 ECDSA signature.
// Use with `extraEntropy: true` to improve security.
function sign(
  messageHash: Hex, // message hash (not message) which would be signed
  privateKey: Hex, // private key which will sign the hash
  opts = {} // optional params `{ lowS: boolean, extraEntropy: boolean | Hex }`
): Signature;
function signAsync(messageHash: Hex, privateKey: Hex, opts = {}): Promise<Signature>;

// Verifies ECDSA signature.
// lowS option Ensures a signature.s is in the lower-half of CURVE.n.
// Used in BTC, ETH.
// `{ lowS: false }` should only be used if you need OpenSSL-compatible signatures
function verify(
  signature: Hex | Signature, // returned by the `sign` function
  messageHash: Hex, // message hash (not message) that must be verified
  publicKey: Hex, // public (not private) key
  opts?: { lowS: boolean } // optional params; { lowS: true } by default
): boolean;

// Computes ECDH (Elliptic Curve Diffie-Hellman) shared secret between
// key A and different key B.
function getSharedSecret(
  privateKeyA: Uint8Array | string, // Alices's private key
  publicKeyB: Uint8Array | string, // Bob's public key
  isCompressed = true // optional arg. (default) true=33b key, false=65b.
): Uint8Array;
// Use `ProjectivePoint.fromHex(publicKeyB).multiply(privateKeyA)` for Point instance

// Recover public key from Signature instance with `recovery` bit set
signature.recoverPublicKey(
  msgHash: Uint8Array | string
): Uint8Array | undefined;
```

A bunch of useful **utilities** are also exposed:

```typescript
type Bytes = Uint8Array;
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
class ProjectivePoint {
    readonly px: bigint;
    readonly py: bigint;
    readonly pz: bigint;
    constructor(px: bigint, py: bigint, pz: bigint);
    static readonly BASE: Point;
    static readonly ZERO: Point;
    get x(): bigint;
    get y(): bigint;
    equals(other: Point): boolean;
    add(other: Point): Point;
    multiply(n: bigint): Point;
    negate(): Point;
    toAffine(): AffinePoint;
    assertValidity(): Point;
    static fromHex(hex: Hex): Point;
    toHex(isCompressed?: boolean): string;
    toRawBytes(isCompressed?: boolean): Uint8Array;
    static fromPrivateKey(n: PrivKey): Point;
}
class Signature {
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
CURVE // curve prime; order; equation params, generator coordinates
```

## Security

The module is production-ready. Use
[noble-curves](https://github.com/paulmillr/noble-curves) if you need advanced security.

1. The current version is rewrite of v1, which has been audited by cure53:
[PDF](https://cure53.de/pentest-report_noble-lib.pdf) (funded by [Umbra.cash](https://umbra.cash) & community).
2. It's being fuzzed by [Guido Vranken's cryptofuzz](https://github.com/guidovranken/cryptofuzz):
run the fuzzer by yourself to check.

Our EC multiplication is hardened to be algorithmically constant time.
We're using built-in JS `BigInt`, which is potentially vulnerable to
[timing attacks](https://en.wikipedia.org/wiki/Timing_attack) as
[per MDN](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt#cryptography).
But, _JIT-compiler_ and _Garbage Collector_ make "constant time" extremely hard
to achieve in a scripting language. Which means _any other JS library doesn't
use constant-time bigints_. Including bn.js or anything else.
Even statically typed Rust, a language without GC,
[makes it harder to achieve constant-time](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security)
for some cases. If your goal is absolute security, don't use any JS lib —
including bindings to native ones. Use low-level libraries & languages.

We consider infrastructure attacks like rogue NPM modules very important;
that's why it's crucial to minimize the amount of 3rd-party dependencies & native
bindings. If your app uses 500 dependencies, any dep could get hacked and you'll
be downloading malware with every `npm install`. Our goal is to minimize this attack vector.

## Speed

Use [noble-curves](https://github.com/paulmillr/noble-curves) if you need even higher performance.

Benchmarks measured with Apple M2 on MacOS 13 with node.js 19.

    getPublicKey(utils.randomPrivateKey()) x 5,540 ops/sec @ 180μs/op
    sign x 3,301 ops/sec @ 302μs/op
    verify x 517 ops/sec @ 1ms/op
    getSharedSecret x 433 ops/sec @ 2ms/op
    recoverPublicKey x 526 ops/sec @ 1ms/op
    Point.fromHex (decompression) x 8,415 ops/sec @ 118μs/op

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

1. Clone the repository.
2. `npm install` to install build dependencies like TypeScript
3. `npm run build` to compile TypeScript code
4. `npm test` to run jest on `test/index.ts`

Special thanks to [Roman Koblov](https://github.com/romankoblov), who have
helped to improve scalar multiplication speed.

## Upgrading

noble-secp256k1 v2.0 has been reduced 4x to just over 400 lines. It features
improved security and smaller attack surface.

Some functionality present in v1, such as schnorr and DER, was removed:
use [**noble-curves**](https://github.com/paulmillr/noble-curves) if you still need it.

- `getPublicKey()` and `getSharedSecret()` now produce compressed 33-byte
  signatures by default. If you need the old 65-byte behavior, set isCompresse=false:
  `getPublicKey(priv, false)`, `getSharedSecret(a, b, false)`
- `sign()`: now returns `Signature` instance with `{ r, s, recovery }` properties.
  It could still be passed to `verify` as-is.
    - `canonical` is now => `lowS`. The default value is the same as before: `lowS: true`
    - `recovered` has been removed. Recovery bit is always returned in the `Signature` instance
    - `der` has been removed. DER encoding is no longer supported. Use compact
      format (32-byte r + 32-byte s), `Signature` instance methods
      `toCompactRawBytes` / `toCompactHex()`:
      `(await sign(msgHash, priv)).toCompactRawBytes()`.
      Use noble-curves if you still need DER
- `verify()`: `strict` option has been renamed to `lowS`, default value is still the same
- `recoverPublicKey(msgHash, sig, recovery)` has been changed to `sig.recoverPublicKey(msgHash)`
- `Point` is now `ProjectivePoint`, working in 3d xyz projective coordinates instead of 2d xy affine
- Removed schnorr signatures, asn.1 DER, custom precomputes. Use noble-curves if you need them
- Support for environments that can't parse bigint literals has been removed
- Some utils such as `hmacSha256Sync` have been moved to `etc`: `import { etc } from "@noble/secp256k1";
- node.js 18 and older are not supported without crypto shim (see [Usage](#usage))

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
