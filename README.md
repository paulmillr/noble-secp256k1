# noble-secp256k1

[Fastest](#speed) 4KB JS implementation of [secp256k1](https://www.secg.org/sec2-v2.pdf)
elliptic curve. Auditable, high-security, 0-dependency ECDH & ECDSA signatures compliant with RFC6979.

The library is a tiny single-feature version of
[noble-curves](https://github.com/paulmillr/noble-curves), with some features
removed. Check out curves as a drop-in replacement with
Schnorr signatures, DER encoding and support for different hash functions.

Take a look at: [Upgrading](#upgrading) section for v1 to v2 transition instructions,
[the online demo](https://paulmillr.com/noble/) and blog post
[Learning fast elliptic-curve cryptography in JS](https://paulmillr.com/posts/noble-secp256k1-fast-ecc/).

### This library belongs to _noble_ crypto

> **noble-crypto** — high-security, easily auditable set of contained cryptographic libraries and tools.

- No dependencies, protection against supply chain attacks
- Auditable TypeScript / JS code
- Supported in all major browsers and stable node.js versions
- All releases are signed with PGP keys
- Check out [homepage](https://paulmillr.com/noble/) & all libraries:
  [curves](https://github.com/paulmillr/noble-curves)
  (4kb versions [secp256k1](https://github.com/paulmillr/noble-secp256k1),
  [ed25519](https://github.com/paulmillr/noble-ed25519)),
  [hashes](https://github.com/paulmillr/noble-hashes)

## Usage

Browser, deno, node.js and unpkg are supported:

> npm install @noble/secp256k1

```js
import * as secp from '@noble/secp256k1'; // ESM-only. Use bundler for common.js
// import * as secp from "https://deno.land/x/secp256k1/mod.ts"; // Deno
// import * as secp from "https://unpkg.com/@noble/secp256k1"; // Unpkg
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

```typescript
type Hex = Uint8Array | string;

// Generates public key from 32-byte private key.
// isCompressed=true by default, meaning 33-byte output. Set to false for 65b.
function getPublicKey(privateKey: Hex, isCompressed?: boolean): Uint8Array;
// Use:
// - `ProjectivePoint.fromPrivateKey(privateKey)` for Point instance
// - `ProjectivePoint.fromHex(publicKey)` to convert hex / bytes into Point.

// Generates low-s deterministic-k RFC6979 ECDSA signature.
// Use with `extraEntropy: true` to improve security.
function sign(
  messageHash: Hex, // message hash (not message) which would be signed
  privateKey: Hex, // private key which will sign the hash
  opts?: { lowS: boolean, extraEntropy: boolean | Hex } // optional params
): Signature;
function signAsync(
  messageHash: Hex,
  privateKey: Hex,
  opts?: { lowS: boolean; extraEntropy: boolean | Hex }
): Promise<Signature>;

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
  static fromHex(hex: Hex): Point;
  static fromPrivateKey(n: PrivKey): Point;
  get x(): bigint;
  get y(): bigint;
  equals(other: Point): boolean;
  add(other: Point): Point;
  multiply(n: bigint): Point;
  negate(): Point;
  toAffine(): AffinePoint;
  assertValidity(): Point;
  toHex(isCompressed?: boolean): string;
  toRawBytes(isCompressed?: boolean): Uint8Array;
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

The module is production-ready.
It is cross-tested against [noble-curves](https://github.com/paulmillr/noble-curves),
and has similar security.

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

noble-secp256k1 v2 features improved security and smaller attack surface.
The goal of v2 is to provide minimum possible JS library which is safe and fast.

That means the library was reduced 4x, to just over 400 lines. In order to
achieve the goal, **some features were moved** to
[noble-curves](https://github.com/paulmillr/noble-curves), which is
even safer and faster drop-in replacement library with same API.
Switch to curves if you intend to keep using these features:

- DER encoding: toDERHex, toDERRawBytes, signing / verification of DER sigs
- Schnorr signatures
- Using `utils.precompute()` for non-base point
- Support for environments which don't support bigint literals
- Common.js support
- Support for node.js 18 and older without [shim](#usage)

Other changes for upgrading from @noble/secp256k1 1.7 to 2.0:

- `getPublicKey`
    - now produce 33-byte compressed signatures by default
    - to use old behavior, which produced 65-byte uncompressed keys, set
      argument `isCompressed` to `false`: `getPublicKey(priv, false)`
- `sign`
    - is now sync; use `signAsync` for async version
    - now returns `Signature` instance with `{ r, s, recovery }` properties
    - `canonical` option was renamed to `lowS`
    - `recovered` option has been removed because recovery bit is always returned now
    - `der` option has been removed. There are 2 options:
        1. Use compact encoding: `fromCompact`, `toCompactRawBytes`, `toCompactHex`.
           Compact encoding is simply a concatenation of 32-byte r and 32-byte s.
        2. If you must use DER encoding, switch to noble-curves (see above).
- `verify`
    - `strict` option was renamed to `lowS`
- `getSharedSecret`
    - now produce 33-byte compressed signatures by default
    - to use old behavior, which produced 65-byte uncompressed keys, set
      argument `isCompressed` to `false`: `getSharedSecret(a, b, false)`
- `recoverPublicKey(msg, sig, rec)` was changed to `sig.recoverPublicKey(msg)`
- `number` type for private keys have been removed: use `bigint` instead
- `Point` (2d xy) has been changed to `ProjectivePoint` (3d xyz)
- `utils` were split into `utils` (same api as in noble-curves) and
  `etc` (`hmacSha256Sync` and others)

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
