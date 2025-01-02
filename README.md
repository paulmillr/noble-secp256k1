# noble-secp256k1

Fastest 4KB JS implementation of secp256k1 signatures & ECDH.

- ✍️ [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
  signatures compliant with [RFC6979](https://www.rfc-editor.org/rfc/rfc6979)
- 🤝 Elliptic Curve Diffie-Hellman [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie–Hellman)
- 📦 Pure ESM, can be imported without transpilers
- 🪶 4KB gzipped, 490 lines of code

The module is a sister project of [noble-curves](https://github.com/paulmillr/noble-curves),
focusing on smaller attack surface & better auditability.
Curves are drop-in replacement and have more features: Common.js, Schnorr signatures, DER encoding or support for different hash functions. To upgrade from v1 to v2, see [Upgrading](#upgrading).

### This library belongs to _noble_ cryptography

> **noble-cryptography** — high-security, easily auditable set of contained cryptographic libraries and tools.

- Zero or minimal dependencies
- Highly readable TypeScript / JS code
- PGP-signed releases and transparent NPM builds with provenance
- Check out [homepage](https://paulmillr.com/noble/) & all libraries:
  [ciphers](https://github.com/paulmillr/noble-ciphers),
  [curves](https://github.com/paulmillr/noble-curves),
  [hashes](https://github.com/paulmillr/noble-hashes),
  [post-quantum](https://github.com/paulmillr/noble-post-quantum),
  4kb [secp256k1](https://github.com/paulmillr/noble-secp256k1) /
  [ed25519](https://github.com/paulmillr/noble-ed25519)

## Usage

> `npm install @noble/secp256k1`

> `deno add @noble/secp256k1`

We support all major platforms and runtimes. For node.js <= 18 and React Native, additional polyfills are needed: see below.

```js
import * as secp from '@noble/secp256k1';
// import * as secp from "https://unpkg.com/@noble/secp256k1"; // Unpkg
(async () => {
  // Uint8Arrays or hex strings are accepted:
  // Uint8Array.from([0xde, 0xad, 0xbe, 0xef]) is equal to 'deadbeef'
  const privKey = secp.utils.randomPrivateKey(); // Secure random private key
  // sha256 of 'hello world'
  const msgHash = 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
  const pubKey = secp.getPublicKey(privKey);
  const signature = await secp.signAsync(msgHash, privKey); // Sync methods below
  const isValid = secp.verify(signature, msgHash, pubKey);

  const alicesPubkey = secp.getPublicKey(secp.utils.randomPrivateKey());
  secp.getSharedSecret(privKey, alicesPubkey); // Elliptic curve diffie-hellman
  signature.recoverPublicKey(msgHash); // Public key recovery
})();
```

Additional polyfills for some environments:

```ts
// 1. Enable synchronous methods.
// Only async methods are available by default, to keep the library dependency-free.
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
secp.etc.hmacSha256Sync = (k, ...m) => hmac(sha256, k, secp.etc.concatBytes(...m));
// Sync methods can be used now:
// secp.sign(msgHash, privKey);

// 2. node.js 18 and older, requires polyfilling globalThis.crypto
import { webcrypto } from 'node:crypto';
// @ts-ignore
if (!globalThis.crypto) globalThis.crypto = webcrypto;

// 3. React Native needs crypto.getRandomValues polyfill and sha512
import 'react-native-get-random-values';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
secp.etc.hmacSha256Sync = (k, ...m) => hmac(sha256, k, secp.etc.concatBytes(...m));
secp.etc.hmacSha256Async = (k, ...m) => Promise.resolve(secp.etc.hmacSha256Sync(k, ...m));
```

## API

There are 3 main methods: `getPublicKey(privateKey)`,
`sign(messageHash, privateKey)` and
`verify(signature, messageHash, publicKey)`.
We accept Hex type everywhere:

```ts
type Hex = Uint8Array | string;
```

### getPublicKey

```ts
function getPublicKey(privateKey: Hex, isCompressed?: boolean): Uint8Array;
```

Generates 33-byte compressed public key from 32-byte private key.

- If you need uncompressed 65-byte public key, set second argument to `false`.
- Use `ProjectivePoint.fromPrivateKey(privateKey)` for Point instance.
- Use `ProjectivePoint.fromHex(publicKey)` to convert Hex / Uint8Array into Point.

### sign

```ts
function sign(
  messageHash: Hex, // message hash (not message) which would be signed
  privateKey: Hex, // private key which will sign the hash
  opts?: { lowS: boolean; extraEntropy: boolean | Hex } // optional params
): Signature;
function signAsync(
  messageHash: Hex,
  privateKey: Hex,
  opts?: { lowS: boolean; extraEntropy: boolean | Hex }
): Promise<Signature>;

sign(msgHash, privKey, { lowS: false }); // Malleable signature
sign(msgHash, privKey, { extraEntropy: true }); // Improved security
```

Generates low-s deterministic-k RFC6979 ECDSA signature. Assumes hash of message,
which means you'll need to do something like `sha256(message)` before signing.

1. `lowS: false` allows to create malleable signatures, for compatibility with openssl.
   Default `lowS: true` prohibits signatures which have (sig.s >= CURVE.n/2n) and is compatible with BTC/ETH.
2. `extraEntropy: true` improves security by adding entropy, follows section 3.6 of RFC6979:
   - No disadvantage: if an entropy generator is broken, sigs would be the same
     as they are without the option
   - It would help a lot in case there is an error somewhere in `k` gen.
     Exposing `k` could leak private keys
   - Sigs with extra entropy would have different `r` / `s`, which means they
     would still be valid, but may break some test vectors if you're
     cross-testing against other libs

### verify

```ts
function verify(
  signature: Hex | Signature, // returned by the `sign` function
  messageHash: Hex, // message hash (not message) that must be verified
  publicKey: Hex, // public (not private) key
  opts?: { lowS: boolean } // optional params; { lowS: true } by default
): boolean;
```

Verifies ECDSA signature and ensures it has lowS (compatible with BTC/ETH).
`lowS: false` turns off malleability check, but makes it OpenSSL-compatible.

### getSharedSecret

```ts
function getSharedSecret(
  privateKeyA: Uint8Array | string, // Alices's private key
  publicKeyB: Uint8Array | string, // Bob's public key
  isCompressed = true // optional arg. (default) true=33b key, false=65b.
): Uint8Array;
```

Computes ECDH (Elliptic Curve Diffie-Hellman) shared secret between
key A and different key B.

Use `ProjectivePoint.fromHex(publicKeyB).multiply(privateKeyA)` for Point instance

### recoverPublicKey

```ts
signature.recoverPublicKey(
  msgHash: Uint8Array | string
): Uint8Array | undefined;
```

Recover public key from Signature instance with `recovery` bit set.

### utils

A bunch of useful **utilities** are also exposed:

```typescript
type Bytes = Uint8Array;
const etc: {
  hexToBytes: (hex: string) => Bytes;
  bytesToHex: (b: Bytes) => string;
  concatBytes: (...arrs: Bytes[]) => Bytes;
  bytesToNumberBE: (b: Bytes) => bigint;
  numberToBytesBE: (num: bigint) => Bytes;
  mod: (a: bigint, b?: bigint) => bigint;
  invert: (num: bigint, md?: bigint) => bigint;
  hmacSha256Async: (key: Bytes, ...msgs: Bytes[]) => Promise<Bytes>;
  hmacSha256Sync: HmacFnSync;
  hashToPrivateKey: (hash: Hex) => Bytes;
  randomBytes: (len: number) => Bytes;
};
const utils: {
  normPrivateKeyToScalar: (p: PrivKey) => bigint;
  randomPrivateKey: () => Bytes; // Uses CSPRNG https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
  isValidPrivateKey: (key: Hex) => boolean;
  precompute(p: ProjectivePoint, windowSize?: number): ProjectivePoint;
};
class ProjectivePoint {
  constructor(px: bigint, py: bigint, pz: bigint);
  static readonly BASE: ProjectivePoint;
  static readonly ZERO: ProjectivePoint;
  static fromAffine(point: AffinePoint): ProjectivePoint;
  static fromHex(hex: Hex): ProjectivePoint;
  static fromPrivateKey(n: PrivKey): ProjectivePoint;
  get x(): bigint;
  get y(): bigint;
  add(other: ProjectivePoint): ProjectivePoint;
  assertValidity(): void;
  equals(other: ProjectivePoint): boolean;
  multiply(n: bigint): ProjectivePoint;
  negate(): ProjectivePoint;
  subtract(other: ProjectivePoint): ProjectivePoint;
  toAffine(): AffinePoint;
  toHex(isCompressed?: boolean): string;
  toRawBytes(isCompressed?: boolean): Bytes;
}
class Signature {
  constructor(r: bigint, s: bigint, recovery?: number | undefined);
  static fromCompact(hex: Hex): Signature;
  readonly r: bigint;
  readonly s: bigint;
  readonly recovery?: number | undefined;
  ok(): Signature;
  hasHighS(): boolean;
  normalizeS(): Signature;
  recoverPublicKey(msgh: Hex): Point;
  toCompactRawBytes(): Bytes;
  toCompactHex(): string;
}
CURVE; // curve prime; order; equation params, generator coordinates
```

## Security

The module is production-ready.
While [noble-curves](https://github.com/paulmillr/noble-curves) provide improved security,
we cross-test against curves.

1. The current version has not been independently audited. It is a rewrite of v1, which has been audited by cure53 in Apr 2021:
   [PDF](https://cure53.de/pentest-report_noble-lib.pdf) (funded by [Umbra.cash](https://umbra.cash) & community).
2. It's being fuzzed by [Guido Vranken's cryptofuzz](https://github.com/guidovranken/cryptofuzz):
   you can also run the fuzzer by yourself.

### Constant-timeness

_JIT-compiler_ and _Garbage Collector_ make "constant time" extremely hard to
achieve [timing attack](https://en.wikipedia.org/wiki/Timing_attack) resistance
in a scripting language. Which means _any other JS library can't have
constant-timeness_. Even statically typed Rust, a language without GC,
[makes it harder to achieve constant-time](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security)
for some cases. If your goal is absolute security, don't use any JS lib — including bindings to native ones.
Use low-level libraries & languages. Nonetheless we're targetting algorithmic constant time.

### Supply chain security

1. **Commits** are signed with PGP keys, to prevent forgery. Make sure to verify commit signatures.
2. **Releases** are transparent and built on GitHub CI. Make sure to verify [provenance](https://docs.npmjs.com/generating-provenance-statements) logs
3. **Rare releasing** is followed.
   The less often it is done, the less code dependents would need to audit
4. **Dependencies** are minimal:
   - All deps are prevented from automatic updates and have locked-down version ranges. Every update is checked with `npm-diff`
   - Updates themselves are rare, to ensure rogue updates are not catched accidentally
5. devDependencies are only used if you want to contribute to the repo. They are disabled for end-users:
   - [noble-hashes](https://github.com/paulmillr/noble-hashes) is used, by the same author, to provide hashing functionality tests
   - micro-bmark and micro-should are developed by the same author and follow identical security practices
   - fast-check (property-based testing) and typescript are used for code quality, vector generation and ts compilation.
     The packages are big, which makes it hard to audit their source code thoroughly and fully

We consider infrastructure attacks like rogue NPM modules very important;
that's why it's crucial to minimize the amount of 3rd-party dependencies & native bindings.
If your app uses 500 dependencies, any dep could get hacked and you'll be
downloading malware with every install. Our goal is to minimize this attack vector.

If you see anything unusual: investigate and report.

### Randomness

We're deferring to built-in
[crypto.getRandomValues](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues)
which is considered cryptographically secure (CSPRNG).

In the past, browsers had bugs that made it weak: it may happen again.

## Speed

Use [noble-curves](https://github.com/paulmillr/noble-curves) if you need even higher performance.

Benchmarks measured with Apple M2 on MacOS 13 with node.js 20.

    getPublicKey(utils.randomPrivateKey()) x 6,430 ops/sec @ 155μs/op
    sign x 3,367 ops/sec @ 296μs/op
    verify x 600 ops/sec @ 1ms/op
    getSharedSecret x 505 ops/sec @ 1ms/op
    recoverPublicKey x 612 ops/sec @ 1ms/op
    Point.fromHex (decompression) x 9,185 ops/sec @ 108μs/op

Compare to other libraries on M1 (`openssl` uses native bindings, not JS):

    elliptic#getPublicKey x 1,940 ops/sec
    sjcl#getPublicKey x 211 ops/sec

    elliptic#sign x 1,808 ops/sec
    sjcl#sign x 199 ops/sec
    openssl#sign x 4,243 ops/sec
    ecdsa#sign x 116 ops/sec

    elliptic#verify x 812 ops/sec
    sjcl#verify x 166 ops/sec
    openssl#verify x 4,452 ops/sec
    ecdsa#verify x 80 ops/sec

    elliptic#ecdh x 971 ops/sec

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

## Contributing & testing

* `npm install && npm run build && npm test` will build the code and run tests.
* `npm run bench` will run benchmarks, which may need their deps first (`npm run bench:install`)
* `npm run loc` will count total output size, important to be less than 4KB

Check out [github.com/paulmillr/guidelines](https://github.com/paulmillr/guidelines)
for general coding practices and rules.

See [paulmillr.com/noble](https://paulmillr.com/noble/)
for useful resources, articles, documentation and demos
related to the library.

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
