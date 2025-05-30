import { hexToBytes as bytes } from '@noble/hashes/utils.js';
import * as fc from 'fast-check';
import { describe, should } from 'micro-should';
import { deepStrictEqual, throws } from 'node:assert';
import * as secp256k1 from '../index.js';

function hexa() {
  const items = '0123456789abcdef';
  return fc.integer({ min: 0, max: 15 }).map((n) => items[n]);
}
function hexaString(constraints = {}) {
  return fc.string({ ...constraints, unit: hexa() });
}

const CURVES = { secp256k1 };
const name = 'secp256k1';
const C = CURVES[name];
const CURVE_ORDER = C.CURVE.n;
const FC_BIGINT = fc.bigInt(1n + 1n, CURVE_ORDER - 1n);
const NUM_RUNS = 5;

const getXY = (p) => ({ x: p.x, y: p.y });
const toHex = secp256k1.etc.bytesToHex;

function equal(a, b, comment) {
  deepStrictEqual(a.equals(b), true, `eq(${comment})`);
  if (a.toAffine && b.toAffine) {
    deepStrictEqual(getXY(a.toAffine()), getXY(b.toAffine()), `eqToAffine(${comment})`);
  } else if (!a.toAffine && !b.toAffine) {
    // Already affine
    deepStrictEqual(getXY(a), getXY(b), `eqAffine(${comment})`);
  } else throw new Error('Different point types');
}

// Check that curve doesn't accept points from other curves
const POINTS = {};

for (const pointName in POINTS) {
  const p = POINTS[pointName];
  if (!p) continue;

  const G = [p.ZERO, p.BASE];
  for (let i = 2n; i < 10n; i++) G.push(G[1].multiply(i));
  const title = `${name}/${pointName}`;
  describe(title, () => {
    describe('basic group laws', () => {
      // Here we check basic group laws, to verify that points works as group
      should('zero', () => {
        equal(G[0].double(), G[0], '(0*G).double() = 0');
        equal(G[0].add(G[0]), G[0], '0*G + 0*G = 0');
        equal(G[0].subtract(G[0]), G[0], '0*G - 0*G = 0');
        equal(G[0].negate(), G[0], '-0 = 0');
        for (let i = 0; i < G.length; i++) {
          const p = G[i];
          equal(p, p.add(G[0]), `${i}*G + 0 = ${i}*G`);
          equal(G[0].multiply(BigInt(i + 1)), G[0], `${i + 1}*0 = 0`);
        }
      });
      should('one', () => {
        equal(G[1].double(), G[2], '(1*G).double() = 2*G');
        equal(G[1].subtract(G[1]), G[0], '1*G - 1*G = 0');
        equal(G[1].add(G[1]), G[2], '1*G + 1*G = 2*G');
      });
      should('sanity tests', () => {
        equal(G[2].double(), G[4], '(2*G).double() = 4*G');
        equal(G[2].add(G[2]), G[4], '2*G + 2*G = 4*G');
        equal(G[7].add(G[3].negate()), G[4], '7*G - 3*G = 4*G');
      });
      should('add commutativity', () => {
        equal(G[4].add(G[3]), G[3].add(G[4]), '4*G + 3*G = 3*G + 4*G');
        equal(G[4].add(G[3]), G[3].add(G[2]).add(G[2]), '4*G + 3*G = 3*G + 2*G + 2*G');
      });
      should('double', () => {
        equal(G[3].double(), G[6], '(3*G).double() = 6*G');
      });
      should('multiply', () => {
        equal(G[2].multiply(3n), G[6], '(2*G).multiply(3) = 6*G');
      });
      should('add same-point', () => {
        equal(G[3].add(G[3]), G[6], '3*G + 3*G = 6*G');
      });
      should('add same-point negative', () => {
        equal(G[3].add(G[3].negate()), G[0], '3*G + (- 3*G) = 0*G');
        equal(G[3].subtract(G[3]), G[0], '3*G - 3*G = 0*G');
      });
      should('mul by curve order', () => {
        equal(G[1].multiply(CURVE_ORDER - 1n).add(G[1]), G[0], '(N-1)*G + G = 0');
        equal(G[1].multiply(CURVE_ORDER - 1n).add(G[2]), G[1], '(N-1)*G + 2*G = 1*G');
        equal(G[1].multiply(CURVE_ORDER - 2n).add(G[2]), G[0], '(N-2)*G + 2*G = 0');
        const half = CURVE_ORDER / 2n;
        const carry = CURVE_ORDER % 2n === 1n ? G[1] : G[0];
        equal(G[1].multiply(half).double().add(carry), G[0], '((N/2) * G).double() = 0');
      });
      should('inversion', () => {
        const a = 1234n;
        const b = 5678n;
        const c = a * b;
        equal(G[1].multiply(a).multiply(b), G[1].multiply(c), 'a*b*G = c*G');
        const inv = mod.invert(b, CURVE_ORDER);
        equal(G[1].multiply(c).multiply(inv), G[1].multiply(a), 'c*G * (1/b)*G = a*G');
      });
      should('multiply, rand', () =>
        fc.assert(
          fc.property(FC_BIGINT, FC_BIGINT, (a, b) => {
            const c = mod.mod(a + b, CURVE_ORDER);
            if (c === CURVE_ORDER || c < 1n) return;
            const pA = G[1].multiply(a);
            const pB = G[1].multiply(b);
            const pC = G[1].multiply(c);
            equal(pA.add(pB), pB.add(pA), 'pA + pB = pB + pA');
            equal(pA.add(pB), pC, 'pA + pB = pC');
          }),
          { numRuns: NUM_RUNS }
        )
      );
      should('multiply2, rand', () =>
        fc.assert(
          fc.property(FC_BIGINT, FC_BIGINT, (a, b) => {
            const c = mod.mod(a * b, CURVE_ORDER);
            const pA = G[1].multiply(a);
            const pB = G[1].multiply(b);
            equal(pA.multiply(b), pB.multiply(a), 'b*pA = a*pB');
            equal(pA.multiply(b), G[1].multiply(c), 'b*pA = c*G');
          }),
          { numRuns: NUM_RUNS }
        )
      );
    });

    for (const op of ['add', 'subtract']) {
      describe(op, () => {
        should('type check', () => {
          throws(() => G[1][op](0), '0');
          throws(() => G[1][op](0n), '0n');
          G[1][op](G[2]);
          throws(() => G[1][op](CURVE_ORDER), 'CURVE_ORDER');
          throws(() => G[1][op](-123n), '-123n');
          throws(() => G[1][op](123), '123');
          throws(() => G[1][op](123.456), '123.456');
          throws(() => G[1][op](true), 'true');
          throws(() => G[1][op](false), 'false');
          throws(() => G[1][op](null), 'null');
          throws(() => G[1][op](undefined), 'undefined');
          throws(() => G[1][op]('1'), "'1'");
          throws(() => G[1][op]({ x: 1n, y: 1n }), '{ x: 1n, y: 1n }');
          throws(() => G[1][op]({ x: 1n, y: 1n, z: 1n }), '{ x: 1n, y: 1n, z: 1n }');
          throws(() => G[1][op]({ x: 1n, y: 1n, z: 1n, t: 1n }), '{ x: 1n, y: 1n, z: 1n, t: 1n }');
          throws(() => G[1][op](new Uint8Array([])), 'ui8a([])');
          throws(() => G[1][op](new Uint8Array([0])), 'ui8a([0])');
          throws(() => G[1][op](new Uint8Array([1])), 'ui8a([1])');
          throws(() => G[1][op](new Uint8Array(4096).fill(1)), 'ui8a(4096*[1])');
          // if (G[1].toAffine) throws(() => G[1][op](C.Point.BASE), `Point ${op} ${pointName}`);
          throws(() => G[1][op](o.BASE), `${op}/other curve point`);
        });
      });
    }

    should('equals type check', () => {
      throws(() => G[1].equals(0), '0');
      throws(() => G[1].equals(0n), '0n');
      deepStrictEqual(G[1].equals(G[2]), false, '1*G != 2*G');
      deepStrictEqual(G[1].equals(G[1]), true, '1*G == 1*G');
      deepStrictEqual(G[2].equals(G[2]), true, '2*G == 2*G');
      throws(() => G[1].equals(CURVE_ORDER), 'CURVE_ORDER');
      throws(() => G[1].equals(123.456), '123.456');
      throws(() => G[1].equals(true), 'true');
      throws(() => G[1].equals('1'), "'1'");
      throws(() => G[1].equals({ x: 1n, y: 1n, z: 1n, t: 1n }), '{ x: 1n, y: 1n, z: 1n, t: 1n }');
      throws(() => G[1].equals(new Uint8Array([])), 'ui8a([])');
      throws(() => G[1].equals(new Uint8Array([0])), 'ui8a([0])');
      throws(() => G[1].equals(new Uint8Array([1])), 'ui8a([1])');
      throws(() => G[1].equals(new Uint8Array(4096).fill(1)), 'ui8a(4096*[1])');
      // if (G[1].toAffine) throws(() => G[1].equals(C.Point.BASE), 'Point.equals(${pointName})');
      throws(() => G[1].equals(o.BASE), 'other curve point');
    });

    for (const op of ['multiply', 'multiplyUnsafe']) {
      if (!p.BASE[op]) continue;
      describe(op, () => {
        should('type check', () => {
          if (op !== 'multiplyUnsafe') {
            throws(() => G[1][op](0), '0');
            throws(() => G[1][op](0n), '0n');
          }
          G[1][op](1n);
          G[1][op](CURVE_ORDER - 1n);
          throws(() => G[1][op](G[2]), 'G[2]');
          throws(() => G[1][op](CURVE_ORDER), 'CURVE_ORDER');
          throws(() => G[1][op](CURVE_ORDER + 1n), 'CURVE_ORDER+1');
          throws(() => G[1][op](123.456), '123.456');
          throws(() => G[1][op](true), 'true');
          throws(() => G[1][op]('1'), '1');
          throws(() => G[1][op](new Uint8Array([])), 'ui8a([])');
          throws(() => G[1][op](new Uint8Array([0])), 'ui8a([0])');
          throws(() => G[1][op](new Uint8Array([1])), 'ui8a([1])');
          throws(() => G[1][op](new Uint8Array(4096).fill(1)), 'ui8a(4096*[1])');
          throws(() => G[1][op](o.BASE), 'other curve point');
        });
      });
    }
    // Complex point (Extended/Jacobian/Projective?)
    // if (p.BASE.toAffine && C.Point) {
    //   should('toAffine()', () => {
    //     equal(p.ZERO.toAffine(), C.Point.ZERO, '0 = 0');
    //     equal(p.BASE.toAffine(), C.Point.BASE, '1 = 1');
    //   });
    // }
    // if (p.fromAffine && C.Point) {
    //   should('fromAffine()', () => {
    //     equal(p.ZERO, p.fromAffine(C.Point.ZERO), '0 = 0');
    //     equal(p.BASE, p.fromAffine(C.Point.BASE), '1 = 1');
    //   });
    // }
    // toHex/fromHex (if available)
    if (p.fromHex && p.BASE.toHex) {
      should('fromHex(toHex()) roundtrip', () => {
        fc.assert(
          fc.property(FC_BIGINT, (x) => {
            const point = p.BASE.multiply(x);
            const hex = point.toHex();
            const bytes = point.toRawBytes();
            deepStrictEqual(p.fromHex(hex).toHex(), hex);
            deepStrictEqual(p.fromHex(bytes).toHex(), hex);
          })
        );
      });
      should('fromHex(toHex(compressed=true)) roundtrip', () => {
        fc.assert(
          fc.property(FC_BIGINT, (x) => {
            const point = p.BASE.multiply(x);
            const hex = point.toHex(true);
            const bytes = point.toRawBytes(true);
            deepStrictEqual(p.fromHex(hex).toHex(true), hex);
            deepStrictEqual(p.fromHex(bytes).toHex(true), hex);
          })
        );
      });
    }
  });
}
describe(name, () => {
  if (['bn254', 'pallas', 'vesta'].includes(name)) return;
  // Generic complex things (getPublicKey/sign/verify/getSharedSecret)
  should('.getPublicKey() type check', () => {
    throws(() => C.getPublicKey(0), '0');
    throws(() => C.getPublicKey(0n), '0n');
    throws(() => C.getPublicKey(-123n), '-123n');
    throws(() => C.getPublicKey(123), '123');
    throws(() => C.getPublicKey(123.456), '123.456');
    throws(() => C.getPublicKey(true), 'true');
    throws(() => C.getPublicKey(false), 'false');
    throws(() => C.getPublicKey(null), 'null');
    throws(() => C.getPublicKey(undefined), 'undefined');
    throws(() => C.getPublicKey(''), "''");
    // NOTE: passes because of disabled hex padding checks for starknet, maybe enable?
    // throws(() => C.getPublicKey('1'), "'1'");
    throws(() => C.getPublicKey('key'), "'key'");
    throws(() => C.getPublicKey({}));
    throws(() => C.getPublicKey(new Uint8Array([])));
    throws(() => C.getPublicKey(new Uint8Array([0])));
    throws(() => C.getPublicKey(new Uint8Array([1])));
    throws(() => C.getPublicKey(new Uint8Array(4096).fill(1)));
    throws(() => C.getPublicKey(Array(32).fill(1)));
  });
  should('.verify() should verify random signatures', () =>
    fc.assert(
      fc.property(hexaString({ minLength: 64, maxLength: 64 }), (msg) => {
        const priv = C.utils.randomPrivateKey();
        const pub = C.getPublicKey(priv);
        const sig = C.sign(bytes(msg), priv);
        const err = `priv=${toHex(priv)},pub=${toHex(pub)},msg=${msg}`;
        deepStrictEqual(C.verify(sig, bytes(msg), pub), true, err);
      }),
      { numRuns: NUM_RUNS }
    )
  );
  should('.verify() should verify empty signatures', () => {
    const msg = new Uint8Array([]);
    const priv = C.utils.randomPrivateKey();
    const pub = C.getPublicKey(priv);
    const sig = C.sign(msg, priv);
    deepStrictEqual(
      C.verify(sig, msg, pub),
      true,
      `priv=${toHex(priv)},pub=${toHex(pub)},msg=${msg}`
    );
  });
  should('.sign() edge cases', () => {
    throws(() => C.sign());
    throws(() => C.sign(''));
    throws(() => C.sign('', ''));
    throws(() => C.sign(new Uint8Array(), new Uint8Array()));
  });

  describe('verify()', () => {
    const msg = bytes('01'.repeat(32));
    should('true for proper signatures', () => {
      const priv = C.utils.randomPrivateKey();
      const sig = C.sign(msg, priv);
      const pub = C.getPublicKey(priv);
      deepStrictEqual(C.verify(sig, msg, pub), true);
    });
    should('false for wrong messages', () => {
      const priv = C.utils.randomPrivateKey();
      const sig = C.sign(msg, priv);
      const pub = C.getPublicKey(priv);
      deepStrictEqual(C.verify(sig, bytes('11'.repeat(32)), pub), false);
    });
    should('false for wrong keys', () => {
      const priv = C.utils.randomPrivateKey();
      const sig = C.sign(msg, priv);
      deepStrictEqual(C.verify(sig, msg, C.getPublicKey(C.utils.randomPrivateKey())), false);
    });
  });
  if (C.Signature) {
    should('Signature serialization roundtrip', () =>
      fc.assert(
        fc.property(hexaString({ minLength: 64, maxLength: 64 }), (msg) => {
          const priv = C.utils.randomPrivateKey();
          const sig = C.sign(bytes(msg), priv);
          const sigRS = (sig) => ({ s: sig.s, r: sig.r });
          // Compact
          // deepStrictEqual(sigRS(C.Signature.fromCompact(sig.toCompactHex())), sigRS(sig));
          deepStrictEqual(sigRS(C.Signature.fromCompact(sig.toCompactRawBytes())), sigRS(sig));
          // DER
          // deepStrictEqual(sigRS(C.Signature.fromDER(sig.toDERHex())), sigRS(sig));
          // deepStrictEqual(sigRS(C.Signature.fromDER(sig.toDERRawBytes())), sigRS(sig));
        }),
        { numRuns: NUM_RUNS }
      )
    );
    should('Signature.addRecoveryBit/Signature.recoveryPublicKey', () =>
      fc.assert(
        fc.property(hexaString({ minLength: 64, maxLength: 64 }), (msg) => {
          msg = Uint8Array.from(Buffer.from(msg, 'hex'));
          const priv = C.utils.randomPrivateKey();
          const pub = C.getPublicKey(priv);
          const sig = C.sign(msg, priv);
          deepStrictEqual(sig.recoverPublicKey(msg).toRawBytes(), pub);
          const sig2 = C.Signature.fromCompact(sig.toCompactRawBytes());
          throws(() => sig2.recoverPublicKey(msg));
          const sig3 = sig2.addRecoveryBit(sig.recovery);
          deepStrictEqual(sig3.recoverPublicKey(msg).toRawBytes(), pub);
        }),
        { numRuns: NUM_RUNS }
      )
    );
    should('Signature.normalizeS', () =>
      fc.assert(
        fc.property(hexaString({ minLength: 64, maxLength: 64 }), (msg) => {
          msg = bytes(msg);
          const priv = C.utils.randomPrivateKey();
          const pub = C.getPublicKey(priv);
          const sig = C.sign(msg, priv, { lowS: false });
          if (!sig.hasHighS()) return;
          const sigNorm = sig.normalizeS();
          deepStrictEqual(sigNorm.hasHighS(), false, 'a');

          deepStrictEqual(C.verify(sig, msg, pub, { lowS: false }), true, 'b');
          deepStrictEqual(C.verify(sig, msg, pub, { lowS: true }), false, 'c');
          deepStrictEqual(C.verify(sigNorm, msg, pub, { lowS: true }), true, 'd');
          deepStrictEqual(C.verify(sigNorm, msg, pub, { lowS: false }), true, 'e');
        }),
        { numRuns: NUM_RUNS }
      )
    );
  }

  // NOTE: fails for ed, because of empty message. Since we convert it to scalar,
  // need to check what other implementations do. Empty message != new Uint8Array([0]), but what scalar should be in that case?
  // should('should not verify signature with wrong message', () => {
  //   fc.assert(
  //     fc.property(
  //       fc.array(fc.integer({ min: 0x00, max: 0xff })),
  //       fc.array(fc.integer({ min: 0x00, max: 0xff })),
  //       (bytes, wrongBytes) => {
  //         const privKey = C.utils.randomPrivateKey();
  //         const message = new Uint8Array(bytes);
  //         const wrongMessage = new Uint8Array(wrongBytes);
  //         const publicKey = C.getPublicKey(privKey);
  //         const signature = C.sign(message, privKey);
  //         deepStrictEqual(
  //           C.verify(signature, wrongMessage, publicKey),
  //           bytes.toString() === wrongBytes.toString()
  //         );
  //       }
  //     ),
  //     { numRuns: NUM_RUNS }
  //   );
  // });

  if (C.getSharedSecret) {
    should('getSharedSecret() should be commutative', () => {
      for (let i = 0; i < NUM_RUNS; i++) {
        const asec = C.utils.randomPrivateKey();
        const apub = C.getPublicKey(asec);
        const bsec = C.utils.randomPrivateKey();
        const bpub = C.getPublicKey(bsec);
        try {
          deepStrictEqual(C.getSharedSecret(asec, bpub), C.getSharedSecret(bsec, apub));
        } catch (error) {
          console.error('not commutative', { asec, apub, bsec, bpub });
          throw error;
        }
      }
    });
  }
});

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
