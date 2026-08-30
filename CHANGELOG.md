# Changelog for noble-secp256k1

## 3.2.0 (2026-08-27)

- Added `isCompressed` to the options for `recoverPublicKey()` and `recoverPublicKeyAsync()`
- Made safe generic `Point#multiply()` execute the full 256-bit ladder regardless of the scalar's leading zero bits
- Made `signAsync()`, `schnorr.sign()`, and `schnorr.signAsync()` snapshot the message at invocation, preventing caller mutation
- Reduce code size by ~10%, rewrite some utils for this purpose

## 3.1.0 (2026-04-11)

- **March 2026 self-audit** (all files): no major issues found
  - Audited for spec compliance and security
  - General hardening was completed
- Fix all Byte Array types, to ensure proper work in both TypeScript 5.6 & TypeScript 5.9+
  - TS 5.6 has `Uint8Array`, while TS 5.9+ made it generic `Uint8Array<ArrayBuffer>`
  - This creates incompatibility of code between versions
  - Previously, it was hard to use and constantly emitted errors similar to `TS2345`
  - See [typescript#62240](https://github.com/microsoft/TypeScript/issues/62240) for more context
- Fix compilation issues on TypeScript v6
- Improve tree-shaking, reduce bundle sizes
- Add massive amounts of documentation everywhere

### New Contributors

- @Zosoled made their first contribution in https://github.com/paulmillr/noble-secp256k1/pull/140

## 3.0.0 (2025-08-25)

### v3 brings the package closer to noble-curves v2

- Add Schnorr signatures
- Most methods now expect Uint8Array, string hex inputs are prohibited
- Add `keygen` method
- sign, verify: Switch to **prehashed messages**. Instead of
  messageHash, the methods now expect unhashed message.
  To bring back old behavior, use option `{prehash: false}`
- sign, verify: Switch to **Uint8Array signatures** (format: 'compact') by default.
- verify: **recovered format must be explicitly specified** in `{format: 'recovered'}`.
  This reduces malleability
- verify: **prohibit Signature-instance** signature. User must now always do
  `signature.toBytes()`
- Node v20.19 is now the minimum required version
- Various small changes for types and Point class
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

## 2.3.0 (2025-06-11)

- Preparation for v3: rewrite code
- Remove non-erasable typescript syntax. The .ts code can now be ran natively in node.js
- Point: do assertValidity before encoding
- Signature: Freeze on creation
- CI: attest standalone build files
- Fix for Palemoon browser, which doesn't allow argument-less `new Uint8Array()`
- Bump typescript target from ES2020 to ES2022

## 2.2.3 (2025-01-07)

Revert requirement for crypto.subtle, introduced in 2.2.0 #123. This ensures synchronous environments work correctly without it.

## 2.2.2 (2025-01-02)

- Improve documentation for public methods. This ensures efficient auto-generated docs on JSR.

## 2.2.1 (2025-01-02)

Same as [2.2.0](https://github.com/paulmillr/noble-secp256k1/releases/tag/2.2.0), but now publishing to JSR without [slow-types option](https://jsr.io/docs/about-slow-types).

## 2.2.0 (2025-01-02)

### What's Changed

- Allow any size of `opts.extraEntropy` when signing
- Improve hex and bytes conversion
- Feature detect to avoid self.crypto if subtle isn't available by @gre in https://github.com/paulmillr/noble-secp256k1/pull/123
- Improve types: use `isolatedDeclarations` option

### New Contributors

- @gre made their first contribution in https://github.com/paulmillr/noble-secp256k1/pull/123
- @ChALkeR made their first contribution in https://github.com/paulmillr/noble-secp256k1/pull/129

## 2.1.0 (2024-03-24)

This release comes one year after v2.0.0, following rare update schedule for easy auditability.

- Point.fromAffine: convert ZERO points properly
- au8: improve Uint8Array check to work in extension context
- Signature: add normalizeS method
- Signature: addRecoveryBit should return more precise type, `SignatureWithRecovery`
- randomPrivateKey: fetch 48 bytes from CSPRNG instead of 40, to reduce bias

### New Contributors

- @thejoelw made their first contribution in https://github.com/paulmillr/noble-secp256k1/pull/100
- @MicahZoltu made their first contribution in https://github.com/paulmillr/noble-secp256k1/pull/102
- @legobeat made their first contribution in https://github.com/paulmillr/noble-secp256k1/pull/108
- @Elli610 made their first contribution in https://github.com/paulmillr/noble-secp256k1/pull/121

## 2.0.0 (2023-03-24)

noble-secp256k1 v2 features improved security and smaller attack surface.
The goal of v2 is to provide minimum possible JS library which is safe and fast.

That means the library was reduced 4x, to just over 400 lines. Library size is now just 4KB gzipped.
In order to achieve the goal, **some features were moved** to [noble-curves](https://github.com/paulmillr/noble-curves), which is
even safer and faster drop-in replacement library with same API.
**Switch to curves** if you intend to keep using these features:

- DER encoding: toDERHex, toDERRawBytes, signing / verification of DER sigs
- Schnorr signatures
- Using `utils.precompute()` for non-base point
- Support for environments which don't support bigint literals
- Common.js support
- Support for node.js 18 and older *without shim*

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

Pull request: https://github.com/paulmillr/noble-secp256k1/pull/92

## 1.7.2 (2025-04-14)

- Improve is-Uint8Array check. Previously it allowed invalid inputs. Thanks to @chalker for report.

## 1.7.1 (2023-01-08)

- Add support for recovery_bit=2, 3
- `JacobianPoint#fromAffine` bugfix
- `P.subtract(P)` and `JacobianPoint.ZERO.toAffine()` no longer throw errors
- Refactoring backported from [noble-curves](https://github.com/paulmillr/noble-curves)

## 1.7.0 (2022-09-11)

The library now works with React Native. Remove all bigint `**` pow operators to improve compact w bad parsers.

- Expose `Point#hasEvenY()`
- Utils `sha256Sync` and `hmacSha256Sync` redefinitions cannot be re-defined after the first time
- Add experimental `utils._normalizePrivateKey()`
- Remove experimental utils: `privateAdd`, `privateNegate`, `pointAddScalar`, `pointMultiply`. We consider their API not optimal. If you want to keep using them, copy-paste their definition from `test` directory.
- Refactor schnorr

## 1.6.3 (2022-07-14)

Allow `0000...` hash in `recoverPublicKey`

## 1.6.2 (2022-07-13)

Fixes tests for 0000... hash in `verify()`

## 1.6.1 (2022-07-13)

- Make verification of `0000...` msgHash a valid behavior; due to consensus failures
- Add TS types field to exports map by @jacogr in https://github.com/paulmillr/noble-secp256k1/pull/66

## 1.6.0 (2022-06-11)

- Expose utils: `invert`, `hexToBytes`, `concatBytes`
- Refactor Schnorr/BIP340 functionality by @brandonblack in https://github.com/paulmillr/noble-secp256k1/pull/50
- Speedup non-BASE multiplyAndAddUnsafe by @brandonblack in https://github.com/paulmillr/noble-secp256k1/pull/54
- Remove viral `esModuleInterop` option from tsconfig.
- Change `utils.hashToPrivateKey` algorithm

### New Contributors

- @brandonblack made their first contribution in https://github.com/paulmillr/noble-secp256k1/pull/50

## 1.5.5 (2022-02-20)

- Fixed a bug in `schnorr.verify` when infinity point result was not checked properly
- `schnorr.verify` now throws less errors, instead, it returns `false`
- Made `schnorr.sign` 60% faster, `schnorr.verify` 90% faster

## 1.5.4 (2022-02-19)

- `recoverPublicKey` improvements:
    - Fixed an issue where it recovered invalid points
    - Added `isCompressed` optional argument
    - Made it ~2x faster

## 1.5.3 (2022-02-14)

- New algorithm for `utils.randomPrivateKey()`
- Added `utils.hashToPrivateKey()`
- Improved `JacobianPoint#toAffine()` check
- 5-10% speed-up

## 1.5.2 (2022-01-26)

- Fix library compatibility with bad parsers over bigint syntax
- New exported `utils.mod` utility
- `recoverPublicKey` and `Point.fromSignature` now reduce `msgHash` modulo n
- Uint8Arrays are now always copied instead of using `.slice()` method of theirs
- Hex parsing improvements

## 1.5.0 (2022-01-17)

- Messages in ECDSA `sign()` are now reduced modulo `n` to match RFC6979. Contributed by @kklash.
    - Note: libsecp256k1 is awaiting pull request for the same bugfix
- `sign` can now receive `{extraEntropy: true}` to auto-populate `k` with random data. This is strongly recommended, see README
- RFC6979 has been thoroughly refactored

## 1.4.0 (2022-01-04)

- **Important:** signatures are now `canonical: true` by default. This mirrors [libsecp256k1](https://github.com/bitcoin-core/secp256k1) behavior. If you'd like old (OpenSSL) behavior, use `sign` with `canonical: false`
- **Important:** `verify()` is now `strict: true` by default. High-s signatures are rejected, which also mirrors libsecp behavior.
- **Important:** removed `string` (hex) return type from public methods. `Uint8Array` is now always returned
- Added `extraEntropy` option to `sign`. It allows to specify `k'` as per RFC6979
- Added `Signature#hasHighS()` and `Signature#normalizeS()` methods
- Rewrite DER parsing logic
- Improve hex parsing security
- `assertValidity` is now done in `Signature` constructor, instead of a separate method
- Remove `SignResult` deprecated class that cloned `Signature`

Thanks to @hank121314 for contribution

## 1.3.3 (2021-12-13)

- Add main/module fields to package.json to fix rollup/browserify

## 1.3.2 (2021-12-11)

- Typescript support bugfix

## 1.3.1 (2021-12-11)

### What's Changed

- Improve compatibility with non-compliant JS parsers: swap `<digits>n` format to `BigInt(<digits>)` in https://github.com/paulmillr/noble-secp256k1/pull/33
- ECMAScript Modules (ESM) support in https://github.com/paulmillr/noble-secp256k1/pull/32
- Do not depend on `@types/dom` when using Typescript
- Improve garbage collector behavior by not using array assignments that call ES6 iterator protocol

### New Contributors

- @jacogr made their first contribution in https://github.com/paulmillr/noble-secp256k1/pull/33

## 1.3.0 (2021-11-05)

- Security improvement: moved npm package to `@noble/secp256k1` (from `noble-secp256k1`). Namespaces cannot be used by other people, so by using `@noble` you can be sure it's authentic

## 1.2.14 (2021-10-19)

- Fix webpack builds

## 1.2.13 (2021-10-15)

- Add Signature methods: `fromDER`, `toDER`, `fromCompact`, `toCompact`; discourage `fromHex`, `toHex` since it's ambigous
- Add `der: false` option to `sign()` to output compact sig

## 1.2.12 (2021-10-15)

Buggy release, skip it

## 1.2.11 (2021-10-15)

- Added `signSync` method that relies on `utils.hmacSha256Sync`. You need to define the hmac function, it's undefined by default, to not bring any deps
- Removed experimental `_syncSign` method

## 1.2.10 (2021-09-29)

- `SchnorrSignature` validation improvements
- Small `utils` improvements

## 1.2.9 (2021-07-24)

- Small perf improvement in `JacobianPoint#double`
- Typescript publish

## 1.2.8 (2021-07-19)

Added experimental `_syncSign()` for cases when sync `utils.hmacSha256()` is used.

## 1.2.7 (2021-06-26)

- Added `browser` field to `package.json` that indicates to browsers that `require("crypto")` imports shouldn't be loaded
- Added support for service workers in browsers

## 1.2.6 (2021-05-29)

Add build files

## 1.2.5 (2021-05-23)

Improves `utils.randomPrivateKey()` generation: before, ~`2**128` values (`curve.n<value<2**256`) had 2x chance to be generated. The chance is very small: 1/2**128. We're fixing this by using NIST SP 800-56A rev 3, section 5.6.1.2.2.

Thanks to Jan Winkelmann from LeastAuthority for reporting the issue.

## 1.2.4 (2021-04-26)

Bugfixes

## 1.2.0 (2021-04-22)

Fixed all bugs reported from the security audit

## 1.1.3 (2021-04-08)

- Allowed non-32-byte message hashes.
- Hardened point, signature, and public-key recovery validation in preparation for an audit.
- Updated dependencies and benchmarks.

## 1.1.2 (2021-01-31)

- Improved compressed point parsing, including support for 32-byte Schnorr public keys, and refreshed documentation and benchmarks.

## 1.1.1 (2020-12-16)

Fixes Schnorr signatures

## 1.1.0 (2020-12-16)

Add support for Schnorr signatures per BIP0340.

## 1.0.6 (2020-10-01)

- Documented Safari support.

## 1.0.5 (2020-06-22)

Bugfixes

## 0.1.0 (2020-03-23)

- Initial release
