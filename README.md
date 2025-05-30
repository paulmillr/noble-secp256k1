# noble-secp256k1

Fastest 4KB JS implementation of secp256k1 signatures & ECDH.

- ✍️ [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
  signatures compliant with [RFC6979](https://www.rfc-editor.org/rfc/rfc6979)
- 🤝 Elliptic Curve Diffie-Hellman [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie–Hellman)
- 🔒 Supports [hedged signatures](https://paulmillr.com/posts/deterministic-signatures/) guarding against fault attacks
- 🪶 3.98KB gzipped (elliptic.js is 12x larger, tiny-secp256k1 is 20-40x larger)

The module is a sister project of [noble-curves](https://github.com/paulmillr/noble-curves),
focusing on smaller attack surface & better auditability.
Curves are drop-in replacement and have more features:
MSM, DER encoding, endomorphism, prehashing, custom point precomputes.
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
  4kb [secp256k1](https://github.com/paulmillr/noble-secp256k1) /
  [ed25519](https://github.com/paulmillr/noble-ed25519)

## Usage

> `npm install @noble/secp256k1`

> `deno add jsr:@noble/secp256k1`

> `deno doc jsr:@noble/secp256k1` # command-line documentation

We support all major platforms and runtimes. For React Native, additional polyfills are needed: see below.

```js
import * as secp from '@noble/secp256k1';
(async () => {
  // Uint8Arrays or hex strings are accepted:
  // Uint8Array.from([0xde, 0xad, 0xbe, 0xef]) is equal to 'deadbeef'
  const privKey = secp.utils.randomPrivateKey(); // Secure random private key
  // sha256 of 'hello world'
  const msgHash = 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
  const pubKey = secp.getPublicKey(privKey);
  const signature = await secp.signAsync(msgHash, privKey); // Sync methods below
  const isValid = secp.verify(signature, msgHash, pubKey);

  const alicesPub = secp.getPublicKey(secp.utils.randomPrivateKey());
  const shared = secp.getSharedSecret(privKey, alicesPub); // Diffie-Hellman
  const pub2 = signature.recoverPublicKey(msgHash); // Public key recovery
})();
```

### Enabling synchronous methods

Only async methods are available by default, to keep the library dependency-free.
To enable sync methods:

```ts
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
secp.etc.hmacSha256Sync = (k, ...m) => hmac(sha256, k, secp.etc.concatBytes(...m));
```

### React Native: polyfill getRandomValues and sha512

```ts
import 'react-native-get-random-values';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
secp.etc.hmacSha256Sync = (k, ...m) => hmac(sha256, k, secp.etc.concatBytes(...m));
secp.etc.hmacSha256Async = (k, ...m) => Promise.resolve(secp.etc.hmacSha256Sync(k, ...m));
```

## API

There are 3 main methods:

* `getPublicKey(privateKey)`
* `sign(messageHash, privateKey)` and `signAsync(messageHash, privateKey)`
* `verify(signature, messageHash, publicKey)`

Functions generally accept Uint8Array.
There are optional utilities which convert hex strings, utf8 strings or bigints to u8a.

### getPublicKey

```ts
import { getPublicKey, utils, ProjectivePoint } from '@noble/secp256k1';
const privKey = utils.randomPrivateKey();
const pubKey33b = getPublicKey(privKey);

// Variants
const pubKey65b = getPublicKey(privKey, false);
const pubKeyPoint = ProjectivePoint.fromPrivateKey(privKey);
const samePoint = ProjectivePoint.fromHex(pubKeyPoint.toHex());
```

Generates 33-byte compressed (default) or 65-byte public key from 32-byte private key.

### sign

```ts
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';
const msg = 'noble cryptography';
const msgHash = sha256(utf8ToBytes(msg));
const priv = secp.utils.randomPrivateKey();

const sigA = secp.sign(msgHash, priv);

// Variants
const sigB = await secp.signAsync(msgHash, priv);
const sigC = secp.sign(msgHash, priv, { extraEntropy: true }); // hedged sig
const sigC2 = secp.sign(msgHash, priv, { extraEntropy: Uint8Array.from([0xca, 0xfe]) });
const sigD = secp.sign(msgHash, priv, { lowS: false }); // malleable sig
```

Generates low-s deterministic-k RFC6979 ECDSA signature. Requries hash of message,
which means you'll need to do something like `sha256(message)` before signing.

`extraEntropy: true` enables hedged signatures. They incorporate
extra randomness into RFC6979 (described in section 3.6),
to provide additional protection against fault attacks.
Check out blog post [Deterministic signatures are not your friends](https://paulmillr.com/posts/deterministic-signatures/).
Even if their RNG is broken, they will fall back to determinism.

Default behavior `lowS: true` prohibits signatures which have (sig.s >= CURVE.n/2n) and is compatible with BTC/ETH.
Setting `lowS: false` allows to create malleable signatures, which is default openssl behavior.
Non-malleable signatures can still be successfully verified in openssl.

### verify

```ts
import * as secp from '@noble/secp256k1';
const hex = secp.etc.hexToBytes;
const sig = hex(
  'ddc633c5b48a1a6725c31201892715dda3058350f7b444e89d32c33c90d9c9e218d7eaf02c2254e88c3b33d755394b08bcc7efd13df02338510b750b64572983'
);
const msgHash = hex('736403f76264eccc1b77ba58dc8fc690e76b2b1532ba82c736a60f3862082db3');
// const priv = 'd60937c2a1ece169888d4c48717dfcc0e1a7af915505823148cca11859210e9c';
const pubKey = hex('020b6d70b68873ff8fd729adf5cf4bf45021b34236f991768249cba06b11136ec6');

// verify
const isValid = secp.verify(sig, msgHash, pubKey);
const isValidLoose = secp.verify(sig, msgHash, pubKey, { lowS: false });
```

Verifies ECDSA signature.
Default behavior `lowS: true` prohibits malleable signatures which have (`sig.s >= CURVE.n/2n`) and
is compatible with BTC / ETH.
Setting `lowS: false` allows to create signatures, which is default openssl behavior.

### getSharedSecret

```ts
import * as secp from '@noble/secp256k1';
const bobsPriv = secp.utils.randomPrivateKey();
const alicesPub = secp.getPublicKey(secp.utils.randomPrivateKey());

// ECDH between Alice and Bob
const shared33b = secp.getSharedSecret(bobsPriv, alicesPub);
const shared65b = secp.getSharedSecret(bobsPriv, alicesPub, false);
const sharedPoint = secp.ProjectivePoint.fromHex(alicesPub).multiply(bobsPriv);
```

Computes ECDH (Elliptic Curve Diffie-Hellman) shared secret between
key A and different key B.

### recoverPublicKey

```ts
import * as secp from '@noble/secp256k1';

import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';
const msg = 'noble cryptography';
const msgHash = sha256(utf8ToBytes(msg));
const priv = secp.utils.randomPrivateKey();
const pub1 = secp.getPubkicKey(priv);
const sig = secp.sign(msgHash, priv);

const pub2 = sig.recoverPublicKey(msgHash);
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
getPublicKey(utils.randomPrivateKey()) x 8,770 ops/sec @ 114μs/op
signAsync x 4,848 ops/sec @ 206μs/op
sign x 7,261 ops/sec @ 137μs/op
verify x 817 ops/sec @ 1ms/op
getSharedSecret x 688 ops/sec @ 1ms/op
recoverPublicKey x 839 ops/sec @ 1ms/op
Point.fromHex (decompression) x 12,937 ops/sec @ 77μs/op
```

## Upgrading

### v1 to v2

noble-secp256k1 v2 improves security and reduces attack surface.
The goal of v2 is to provide minimum possible JS library which is safe and fast.

- Disable some features to ensure 4x smaller than v1, 4KB bundle size:
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

- `npm install && npm run build && npm test` will build the code and run tests.
- `npm run bench` will run benchmarks, which may need their deps first (`npm run bench:install`)
- `npm run loc` will count total output size, important to be less than 4KB

Check out [github.com/paulmillr/guidelines](https://github.com/paulmillr/guidelines)
for general coding practices and rules.

See [paulmillr.com/noble](https://paulmillr.com/noble/)
for useful resources, articles, documentation and demos
related to the library.

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
