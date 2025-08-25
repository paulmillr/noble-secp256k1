# noble-secp256k1

Fastest 5KB JS implementation of secp256k1 signatures & ECDH.

- ✍️ [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
  signatures compliant with [RFC6979](https://www.rfc-editor.org/rfc/rfc6979)
- ➰ Schnorr
  signatures compliant with [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- 🤝 Elliptic Curve Diffie-Hellman [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie–Hellman)
- 🔒 Supports [hedged signatures](https://paulmillr.com/posts/deterministic-signatures/) guarding against fault attacks
- 🪶 4.94KB (gzipped, elliptic.js is 10x larger, tiny-secp256k1 is 25x larger)

The module is a sister project of [noble-curves](https://github.com/paulmillr/noble-curves),
focusing on smaller attack surface & better auditability.
Curves are drop-in replacement and have more features:
MSM, DER encoding, endomorphism, prehashing, custom point precomputes, hash-to-curve, oprf.
To upgrade from earlier version, see [Upgrading](#upgrading).

898-byte version of the library is available for learning purposes in `test/misc/1kb.min.js`,
it was created for the article [Learning fast elliptic-curve cryptography](https://paulmillr.com/posts/noble-secp256k1-fast-ecc/).

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
  5kb [secp256k1](https://github.com/paulmillr/noble-secp256k1) /
  [ed25519](https://github.com/paulmillr/noble-ed25519)

## Usage

> `npm install @noble/secp256k1`

> `deno add jsr:@noble/secp256k1`

We support all major platforms and runtimes. For React Native, additional polyfills are needed: see below.

```js
import * as secp from '@noble/secp256k1';
(async () => {
  const { secretKey, publicKey } = secp.keygen();
  // const publicKey = secp.getPublicKey(secretKey);
  const msg = new TextEncoder().encode('hello noble');
  const sig = await secp.signAsync(msg, secretKey);
  const isValid = await secp.verifyAsync(sig, msg, publicKey);

  const bobsKeys = secp.keygen();
  const shared = secp.getSharedSecret(secretKey, bobsKeys.publicKey); // Diffie-Hellman
  const sigr = await secp.signAsync(msg, secretKey, { format: 'recovered' });
  const publicKey2 = secp.recoverPublicKey(sigr, msg);
})();

// Schnorr signatures from BIP340
(async () => {
  const schnorr = secp.schnorr;
  const { secretKey, publicKey } = schnorr.keygen();
  const msg = new TextEncoder().encode('hello noble');
  const sig = await schnorr.signAsync(msg, secretKey);
  const isValid = await schnorr.verifyAsync(sig, msg, publicKey);
})();
```

### Enabling synchronous methods

Only async methods are available by default, to keep the library dependency-free.
To enable sync methods:

```ts
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
secp.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);
secp.hashes.sha256 = sha256;
```

### React Native: polyfill getRandomValues and sha256

```ts
import 'react-native-get-random-values';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
secp.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);
secp.hashes.sha256 = sha256;
secp.hashes.hmacSha256Async = async (key, msg) => hmac(sha256, key, msg);
secp.hashes.sha256Async = async (msg) => sha256(msg);
```

## API

There are 4 main methods, which accept Uint8Array-s:

* `keygen()`
* `getPublicKey(secretKey)`
* `sign(messageHash, secretKey)` and `signAsync(messageHash, secretKey)`
* `verify(signature, messageHash, publicKey)` and `verifyAsync(signature, messageHash, publicKey)`

### keygen

```ts
import * as secp from '@noble/secp256k1';
(async () => {
  const keys = secp.keygen();
  const { secretKey, publicKey } = keys;
})();
```

### getPublicKey

```ts
import * as secp from '@noble/secp256k1';
const secretKey = secp.utils.randomSecretKey();
const pubKey33b = secp.getPublicKey(secretKey);

// Variants
const pubKey65b = secp.getPublicKey(secretKey, false);
const pubKeyPoint = secp.Point.fromBytes(pubKey65b);
const samePoint = pubKeyPoint.toBytes();
```

Generates 33-byte compressed (default) or 65-byte public key from 32-byte private key.

### sign

```ts
import * as secp from '@noble/secp256k1';
const { secretKey } = secp.keygen();
const msg = 'hello noble';
const sig = secp.sign(msg, secretKey);

// async
const sigB = await secp.signAsync(msg, secretKey);

// recovered, allows `recoverPublicKey(sigR, msg)`
const sigR = secp.sign(msg, secretKey, { format: 'recovered' });
// custom hash
import { keccak256 } from '@noble/hashes/sha3.js';
const sigH = secp.sign(keccak256(msg), secretKey, { prehash: false });
// hedged sig
const sigC = secp.sign(msg, secretKey, { extraEntropy: true });
const sigC2 = secp.sign(msg, secretKey, { extraEntropy: Uint8Array.from([0xca, 0xfe]) });
// malleable sig
const sigD = secp.sign(msg, secretKey, { lowS: false });
```

Generates low-s deterministic-k RFC6979 ECDSA signature.

- Message will be hashed with sha256. If you want to use a different hash function,
make sure to use `{ prehash: false }`.
- `extraEntropy: true` enables hedged signatures. They incorporate
extra randomness into RFC6979 (described in section 3.6),
to provide additional protection against fault attacks.
Check out blog post [Deterministic signatures are not your friends](https://paulmillr.com/posts/deterministic-signatures/).
Even if their RNG is broken, they will fall back to determinism.
- Default behavior `lowS: true` prohibits signatures which have (sig.s >= CURVE.n/2n) and is compatible with BTC/ETH. Setting `lowS: false` allows to create malleable signatures, which is default openssl behavior. Non-malleable signatures can still be successfully verified in openssl.

### verify

```ts
import * as secp from '@noble/secp256k1';
const { secretKey, publicKey } = secp.keygen();
const msg = 'hello noble';
const sig = secp.sign(msg, secretKey);
const isValid = secp.verify(sig, msg, publicKey);

// custom hash
import { keccak256 } from '@noble/hashes/sha3.js';
const sigH = secp.sign(keccak256(msg), secretKey, { prehash: false });
```

Verifies ECDSA signature.

- Message will be hashed with sha256. If you want to use a different hash function,
make sure to use `{ prehash: false }`.
- Default behavior `lowS: true` prohibits malleable signatures which have (`sig.s >= CURVE.n/2n`) and
  is compatible with BTC / ETH.
  Setting `lowS: false` allows to create signatures, which is default openssl behavior.

### getSharedSecret

```ts
import * as secp from '@noble/secp256k1';
const alice = secp.keygen();
const bob = secp.keygen();
const shared33b = secp.getSharedSecret(alice.secretKey, bob.publicKey);
const shared65b = secp.getSharedSecret(bob.secretKey, alice.publicKey, false);
const sharedPoint = secp.Point.fromBytes(bob.publicKey).multiply(
  secp.etc.secretKeyToScalar(alice.secretKey)
);
```

Computes ECDH (Elliptic Curve Diffie-Hellman) shared secret between
key A and different key B.

### recoverPublicKey

```ts
import * as secp from '@noble/secp256k1';

const { secretKey, publicKey } = secp.keygen();
const msg = 'hello noble';
const sigR = secp.sign(msg, secretKey, { format: 'recovered' });
const publicKey2 = secp.recoverPublicKey(sigR, msg);

// custom hash
import { keccak256 } from '@noble/hashes/sha3.js';
const sigR = secp.sign(keccak256(msg), secretKey, { format: 'recovered', prehash: false });
const publicKey2 = secp.recoverPublicKey(sigR, keccak256(msg), { prehash: false });
```

Recover public key from Signature instance with `recovery` bit set.

### schnorr

```ts
import { schnorr } from '@noble/secp256k1';
const { secretKey, publicKey } = schnorr.keygen();
const msg = new TextEncoder().encode('hello noble');
const sig = schnorr.sign(msg, secretKey);
const isValid = schnorr.verify(sig, msg, publicKey);

const sig = await schnorr.signAsync(msg, secretKey);
const isValid = await schnorr.verifyAsync(sig, msg, publicKey);
```

Schnorr
signatures compliant with [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
are supported.

### utils

A bunch of useful **utilities** are also exposed:

```ts
import * as secp from '@noble/secp256k1';

const { bytesToHex, hexToBytes, concatBytes, mod, invert, randomBytes } = secp.etc;
const { isValidSecretKey, isValidPublicKey, randomSecretKey } = secp.utils;
const { Point } = secp;
console.log(Point.CURVE(), Point.BASE);
/*
class Point {
  static BASE: Point;
  static ZERO: Point;
  readonly X: bigint;
  readonly Y: bigint;
  readonly Z: bigint;
  constructor(X: bigint, Y: bigint, Z: bigint);
  static CURVE(): WeierstrassOpts<bigint>;
  static fromAffine(ap: AffinePoint): Point;
  static fromBytes(bytes: Bytes): Point;
  static fromHex(hex: string): Point;
  get x(): bigint;
  get y(): bigint;
  equals(other: Point): boolean;
  is0(): boolean;
  negate(): Point;
  double(): Point;
  add(other: Point): Point;
  subtract(other: Point): Point;
  multiply(n: bigint): Point;
  multiplyUnsafe(scalar: bigint): Point;
  toAffine(): AffinePoint;
  assertValidity(): Point;
  toBytes(isCompressed?: boolean): Bytes;
  toHex(isCompressed?: boolean): string;
}
*/
```

## Security

The module is production-ready.

We cross-test against sister project [noble-curves](https://github.com/paulmillr/noble-curves), which was audited and provides improved security.

- The current version has not been independently audited. It is a rewrite of v1, which has been audited by cure53 in Apr 2021:
  [PDF](https://cure53.de/pentest-report_noble-lib.pdf) (funded by [Umbra.cash](https://umbra.cash) & community).
- It's being fuzzed [in a separate repository](https://github.com/paulmillr/fuzzing)

### Constant-timeness

We're targetting algorithmic constant time. _JIT-compiler_ and _Garbage Collector_ make "constant time"
extremely hard to achieve [timing attack](https://en.wikipedia.org/wiki/Timing_attack) resistance
in a scripting language. Which means _any other JS library can't have
constant-timeness_. Even statically typed Rust, a language without GC,
[makes it harder to achieve constant-time](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security)
for some cases. If your goal is absolute security, don't use any JS lib — including bindings to native ones.
Use low-level libraries & languages.

### Supply chain security

- **Commits** are signed with PGP keys, to prevent forgery. Make sure to verify commit signatures
- **Releases** are transparent and built on GitHub CI.
  Check out [attested checksums of single-file builds](https://github.com/paulmillr/noble-secp256k1/attestations)
  and [provenance logs](https://github.com/paulmillr/noble-secp256k1/actions/workflows/release.yml)
- **Rare releasing** is followed to ensure less re-audit need for end-users
- **Dependencies** are minimized and locked-down: any dependency could get hacked and users will be downloading malware with every install.
  - We make sure to use as few dependencies as possible
  - Automatic dep updates are prevented by locking-down version ranges; diffs are checked with `npm-diff`
- **Dev Dependencies** are disabled for end-users; they are only used to develop / build the source code

For this package, there are 0 dependencies; and a few dev dependencies:

- [noble-hashes](https://github.com/paulmillr/noble-hashes) provides cryptographic hashing functionality
- micro-bmark, micro-should and jsbt are used for benchmarking / testing / build tooling and developed by the same author
- prettier, fast-check and typescript are used for code quality / test generation / ts compilation. It's hard to audit their source code thoroughly and fully because of their size

### Randomness

We're deferring to built-in
[crypto.getRandomValues](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues)
which is considered cryptographically secure (CSPRNG).

In the past, browsers had bugs that made it weak: it may happen again.
Implementing a userspace CSPRNG to get resilient to the weakness
is even worse: there is no reliable userspace source of quality entropy.

### Quantum computers

Cryptographically relevant quantum computer, if built, will allow to
break elliptic curve cryptography (both ECDSA / EdDSA & ECDH) using Shor's algorithm.

Consider switching to newer / hybrid algorithms, such as SPHINCS+. They are available in
[noble-post-quantum](https://github.com/paulmillr/noble-post-quantum).

NIST prohibits classical cryptography (RSA, DSA, ECDSA, ECDH) [after 2035](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf). Australian ASD prohibits it [after 2030](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism/cyber-security-guidelines/guidelines-cryptography).

## Speed

    npm run bench

Benchmarks measured with Apple M4. [noble-curves](https://github.com/paulmillr/noble-curves) enable faster performance.

```
keygen x 7,643 ops/sec @ 130μs/op
sign x 7,620 ops/sec @ 131μs/op
verify x 823 ops/sec @ 1ms/op
getSharedSecret x 707 ops/sec @ 1ms/op
recoverPublicKey x 790 ops/sec @ 1ms/op

signAsync x 4,874 ops/sec @ 205μs/op
verifyAsync x 811 ops/sec @ 1ms/op

Point.fromBytes x 13,656 ops/sec @ 73μs/op
```

## Upgrading

### v2 to v3

v3 brings the package closer to noble-curves v2.

- Add Schnorr signatures
- Most methods now expect Uint8Array, string hex inputs are prohibited
- Add `keygen`, `keygenAsync` method
- sign, verify: Switch to **prehashed messages**. Instead of
  messageHash, the methods now expect unhashed message.
  To bring back old behavior, use option `{prehash: false}`
- sign, verify: Switch to **Uint8Array signatures** (format: 'compact') by default.
- verify: **der format must be explicitly specified** in `{format: 'der'}`.
  This reduces malleability
- verify: **prohibit Signature-instance** signature. User must now always do
  `signature.toBytes()`
- Node v20.19 is now the minimum required version
- Various small changes for types
- etc: hashes are now set in `hashes` object. Also sha256 needs to be set now for `prehash: true`:

```js
// before
// etc.hmacSha256Sync = (key, ...messages) => hmac(sha256, key, etc.concatBytes(...messages));
// etc.hmacSha256Async = (key, ...messages) => Promise.resolve(etc.hmacSha256Sync(key, ...messages));
// after
hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);
hashes.sha256 = sha256;
hashes.hmacSha256Async = async (key, msg) => hmac(sha256, key, msg);
hashes.sha256Async = async (msg) => sha256(msg);
```

### v1 to v2

v2 improves security and reduces attack surface.
The goal of v2 is to provide minimum possible JS library which is safe and fast.

- Disable some features to ensure 4x smaller than v1, 5KB bundle size:
  - The features are now a part of [noble-curves](https://github.com/paulmillr/noble-curves),
    **switch to curves if you need them**. Curves is drop-in replacement.
  - DER encoding: toDERHex, toDERRawBytes, signing / verification of DER sigs
  - Schnorr signatures
  - Support for environments which don't support bigint literals
  - Common.js support
  - Support for node.js 18 and older without [shim](#usage)
  - Using `utils.precompute()` for non-base point
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
    1. Use compact encoding: `fromCompact`, `toBytes`, `toCompactHex`.
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

- `npm install && npm run build && npm test` will build the code and run tests.
- `npm run bench` will run benchmarks
- `npm run build:release` will build single non-module file

See [paulmillr.com/noble](https://paulmillr.com/noble/)
for useful resources, articles, documentation and demos
related to the library.

## License

The MIT License (MIT)

Copyright (c) 2019 Paul Miller [(https://paulmillr.com)](https://paulmillr.com)

See LICENSE file.
