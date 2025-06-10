import { bytesToHex, hexToBytes, isBytes } from '@noble/hashes/utils.js';
import * as fc from 'fast-check';
import { describe, should } from 'micro-should';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { getTypeTestsNonUi8a, json, txt } from './utils.js';
// prettier-ignore
import {
  bytesToNumberBE,
  mod,
  numberToBytesBE,
  schnorr,
  secp,
  selectHash,
  sigFromDER,
  sigToDER
} from './secp256k1.helpers.js';

const VECTORS_ecdsa = json('./vectors/secp256k1/ecdsa.json');
const VECTORS_ecdh = json('./vectors/wycheproof/ecdh_secp256k1_test.json');
const VECTORS_privates = json('./vectors/secp256k1/privates.json');
const VECTORS_points = json('./vectors/secp256k1/points.json');
const VECTORS_wp = json('./vectors/wycheproof/ecdsa_secp256k1_sha256_test.json');

export function pfrom(hex) {
  return Point.fromBytes(hexToBytes(hex));
}
export function phex(point) {
  return bytesToHex(point.toBytes());
}
// Any changes to the file will need to be aware of the fact
// the file is shared between noble-curves and noble-secp256k1.

const Point = secp.Point;
const FC_BIGINT = fc.bigInt(1n + 1n, secp.CURVE.n - 1n);
const toBEHex = (n) => n.toString(16).padStart(64, '0');
// TODO: Real implementation.
function derToPub(der) {
  return hexToBytes(der.slice(46));
}
function hexToNumber(hex2) {
  if (typeof hex2 !== 'string') {
    throw new Error('hexToNumber: expected string, got ' + typeof hex2);
  }
  // Big Endian
  return BigInt(`0x${hex2}`);
}

function checkPrivatesTxt() {
  const data = txt('vectors/secp256k1/privates-2.txt').filter((l) => l[0]);
  for (let [priv, x, y] of data) {
    const point = Point.fromPrivateKey(numberToBytesBE(BigInt(priv)));
    eql(toBEHex(point.x), x);
    eql(toBEHex(point.y), y);

    // const point2 = Point.fromBytes(secp.getPublicKey(toBEHex(BigInt(priv))));
    // eql(toBEHex(point2.x), x);
    // eql(toBEHex(point2.y), y);

    const point3 = Point.fromBytes(secp.getPublicKey(hexToBytes(toBEHex(BigInt(priv)))));
    eql(toBEHex(point3.x), x);
    eql(toBEHex(point3.y), y);
  }
}

describe('secp256k1 static vectors', () => {
  should('getPublicKey()', () => {
    checkPrivatesTxt();
  });

  describe('Point', () => {
    should('.fromBytes() rejects invalid points', () => {
      for (const vector of VECTORS_points.valid.isPoint) {
        const { P, expected } = vector;
        const Pb = hexToBytes(P);
        if (expected) {
          Point.fromBytes(Pb);
        } else {
          throws(() => Point.fromBytes(Pb));
        }
      }
    });

    should('.fromPrivateKey()', () => {
      for (const vector of VECTORS_points.valid.pointFromScalar) {
        const { d, expected } = vector;
        const db = hexToBytes(d);
        eql(phex(Point.fromPrivateKey(db)), expected);
      }
    });

    should('#toBytes(compressed)', () => {
      for (const vector of VECTORS_points.valid.pointCompress) {
        const { P, compress, expected } = vector;
        let p = Point.fromBytes(hexToBytes(P));
        eql(bytesToHex(p.toBytes(compress)), expected);
      }
    });

    should('#add(other)', () => {
      for (const vector of VECTORS_points.valid.pointAdd) {
        const { P, Q, expected } = vector;
        let p = Point.fromBytes(hexToBytes(P));
        let q = Point.fromBytes(hexToBytes(Q));
        if (expected) {
          eql(bytesToHex(p.add(q).toBytes(true)), expected);
        } else {
          if (!p.equals(q.negate())) {
            throws(() => p.add(q).toBytes(true));
          }
        }
      }
    });

    should('#multiply(privateKey)', () => {
      for (const vector of VECTORS_points.valid.pointMultiply) {
        const { P, d, expected } = vector;
        const p = Point.fromBytes(hexToBytes(P));
        if (expected) {
          eql(bytesToHex(p.multiply(hexToNumber(d)).toBytes(true)), expected, P);
        } else {
          throws(() => {
            p.multiply(hexToNumber(d)).toBytes(true);
          });
        }
      }

      for (const vector of VECTORS_points.invalid.pointMultiply) {
        let { P, d } = vector;
        const Pb = hexToBytes(P);
        if (hexToNumber(d) < secp.CURVE.n) {
          throws(() => {
            const p = Point.fromBytes(Pb);
            p.multiply(hexToNumber(d)).toBytes(true);
          });
        }
      }
      for (const num of [0n, 0, -1n, -1, 1.1]) {
        throws(() => Point.BASE.multiply(num));
      }
    });
  });

  should('sign() RFC 6979 vectors', async () => {
    for (const vector of VECTORS_ecdsa.valid) {
      const m = hexToBytes(vector.m);
      const d = hexToBytes(vector.d);
      const vsig = hexToBytes(vector.signature);

      const usig = secp.sign(m, d);
      const sig = usig.toCompactRawBytes();
      eql(sig, vsig);

      if (secp.signAsync) {
        const usig = await secp.signAsync(m, d);
        const sig = usig.toCompactRawBytes();
        eql(sig, vsig);
      }
    }
  });

  should('sign() invalid RFC 6979 vectors', () => {
    for (const vector of VECTORS_ecdsa.invalid.sign) {
      const m = hexToBytes(vector.m);
      const d = hexToBytes(vector.d);
      throws(() => secp.sign(m, d));
    }
  });

  should('sign() with format: der', () => {
    const CASES = [
      [
        'd1a9dc8ed4e46a6a3e5e594615ca351d7d7ef44df1e4c94c1802f3592183794b',
        '304402203de2559fccb00c148574997f660e4d6f40605acc71267ee38101abf15ff467af02200950abdf40628fd13f547792ba2fc544681a485f2fdafb5c3b909a4df7350e6b',
      ],
      [
        '5f97983254982546d3976d905c6165033976ee449d300d0e382099fa74deaf82',
        '3045022100c046d9ff0bd2845b9aa9dff9f997ecebb31e52349f80fe5a5a869747d31dcb88022011f72be2a6d48fe716b825e4117747b397783df26914a58139c3f4c5cbb0e66c',
      ],
      [
        '0d7017a96b97cd9be21cf28aada639827b2814a654a478c81945857196187808',
        '3045022100d18990bba7832bb283e3ecf8700b67beb39acc73f4200ed1c331247c46edccc602202e5c8bbfe47ae159512c583b30a3fa86575cddc62527a03de7756517ae4c6c73',
      ],
    ];
    const privKey = hexToBytes('0101010101010101010101010101010101010101010101010101010101010101');
    for (const [msgh, exp] of CASES) {
      let msg = hexToBytes(msgh);
      const res = secp.sign(msg, privKey, { extraEntropy: undefined });
      eql(sigToDER(res), exp);
      const rs = sigFromDER(sigToDER(res));
      eql(sigToDER(rs), exp);
    }
  });

  describe('sign() {extraEntropy} creates hedged signatures', () => {
    should('pass static vectors', () => {
      const ent1 = '0000000000000000000000000000000000000000000000000000000000000000';
      const ent2 = '0000000000000000000000000000000000000000000000000000000000000001';
      const ent3 = '6e723d3fd94ed5d2b6bdd4f123364b0f3ca52af829988a63f8afe91d29db1c33';
      const ent4 = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';
      const ent5 = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

      for (const e of VECTORS_ecdsa.extraEntropy) {
        const sign = (enth) => {
          const extraEntropy = hexToBytes(enth);
          const m = hexToBytes(e.m);
          const d = hexToBytes(e.d);
          const s = secp.sign(m, d, { extraEntropy }).toCompactRawBytes();
          return bytesToHex(s);
        };
        eql(sign(''), e.signature);
        eql(sign(ent1), e.extraEntropy0);
        eql(sign(ent2), e.extraEntropy1);
        eql(sign(ent3), e.extraEntropyRand);
        eql(sign(ent4), e.extraEntropyN);
        eql(sign(ent5), e.extraEntropyMax);
      }
    });

    should('allow 1-byte {extraEntropy}', () => {
      const extraEntropy = hexToBytes('01');
      const priv = hexToBytes('0101010101010101010101010101010101010101010101010101010101010101');
      const msg = hexToBytes('d1a9dc8ed4e46a6a3e5e594615ca351d7d7ef44df1e4c94c1802f3592183794b');
      const res = secp.sign(msg, priv, { extraEntropy }).toCompactRawBytes();
      eql(
        bytesToHex(res),
        'a250ec23a54bfdecf0e924cbf484077c5044410f915cdba86731cb2e4e925aaa5b1e4e3553d88be2c48a9a0d8d849ce2cc5720d25b2f97473e02f2550abe9545'
      );
    });

    should('allow 48-byte {extraEntropy}', () => {
      const extraEntropy = hexToBytes(
        '000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000001'
      );
      const priv = hexToBytes('0101010101010101010101010101010101010101010101010101010101010101');
      const msg = hexToBytes('d1a9dc8ed4e46a6a3e5e594615ca351d7d7ef44df1e4c94c1802f3592183794b');
      const res = secp.sign(msg, priv, { extraEntropy }).toCompactRawBytes();
      eql(
        bytesToHex(res),
        '2bdf40f42ac0e42ee12750d03bb12b75306dae58eb3c961c5a80d78efae93e595295b66e8eb28f1eb046bb129a976340312159ec0c20b97342667572e4a8379a'
      );
    });
  });

  should('verify() wycheproof vectors', () => {
    for (let group of VECTORS_wp.testGroups) {
      // const pubKey = Point.fromBytes().toBytes();
      const key = group.publicKey;
      const pubKey = key.uncompressed;

      for (let test of group.tests) {
        const h = selectHash(secp);

        const m = h(hexToBytes(test.msg));
        if (test.result === 'valid' || test.result === 'acceptable') {
          let sig;
          try {
            sig = sigFromDER(test.sig);
          } catch (e) {
            // These old Wycheproof vectors which allows invalid behaviour of DER parser
            if (e.message === 'Invalid signature integer: negative') continue;
            throw e;
          }
          const verified = secp.verify(sig, m, hexToBytes(pubKey));
          if (sig.hasHighS()) {
            eql(verified, false);
          } else {
            eql(verified, true);
          }
        } else if (test.result === 'invalid') {
          let failed = false;
          try {
            const verified = secp.verify(test.sig, m, pubKey);
            if (!verified) failed = true;
          } catch (error) {
            failed = true;
          }
          eql(failed, true);
        } else {
          eql(false, true);
        }
      }
    }
  });

  should('verify() invalid RFC 6979 vectors', () => {
    for (const vector of VECTORS_ecdsa.invalid.verify) {
      const sig = hexToBytes(vector.signature);
      const m = hexToBytes(vector.m);
      const Q = hexToBytes(vector.Q);
      const res = secp.verify(sig, m, Q);
      eql(res, false);
    }
  });

  should('getSharedSecret()', () => {
    // TODO: Once der is there, run all tests.
    for (const vector of VECTORS_ecdh.testGroups[0].tests.slice(0, 230)) {
      const priv = hexToBytes(vector.private);
      if (vector.result === 'invalid' || priv.length !== 32) {
        throws(() => {
          secp.getSharedSecret(priv, derToPub(vector.public), true);
        });
      } else if (vector.result === 'valid') {
        const res = secp.getSharedSecret(priv, derToPub(vector.public), true);
        eql(bytesToHex(res.slice(1)), `${vector.shared}`);
      }
    }
  });
  should('getSharedSecret() order matters', () => {
    for (const vector of VECTORS_ecdh.testGroups[0].tests.slice(0, 100)) {
      if (vector.result === 'valid') {
        let priv = vector.private;
        priv = priv.length === 66 ? priv.slice(2) : priv;
        throws(() => secp.getSharedSecret(derToPub(vector.public), priv, true));
      }
    }
  });

  should('utils.isValidPrivateKey()', () => {
    for (const vector of VECTORS_privates.valid.isPrivate) {
      const { d, expected } = vector;
      eql(secp.utils.isValidPrivateKey(hexToBytes(d)), expected);
    }
  });

  should('recoverPublicKey() RFC 6979 vectors', () => {
    for (const vector of VECTORS_ecdsa.valid) {
      const d = hexToBytes(vector.d);
      const m = hexToBytes(vector.m);
      let usig = secp.sign(m, d);
      let sig = sigToDER(usig);
      const vpub = secp.getPublicKey(d);
      const recovered = secp.recoverPublicKey(usig, m);
      eql(recovered.toBytes(), vpub);
    }
  });

  describe('tweak utilities (legacy)', () => {
    const normal = (n) => {
      if (typeof n === 'bigint') return (n);
      if (typeof n === 'string') return hexToNumber(n);
      if (isBytes(n)) return bytesToNumberBE(n);
      throw new Error('invalid type');
    };
    const tweakUtils = {
      privateAdd: (privateKey, tweak) => {
        return numberToBytesBE(mod(normal(privateKey) + normal(tweak), secp.CURVE.n));
      },

      privateNegate: (privateKey) => {
        return numberToBytesBE(mod(-normal(privateKey), secp.CURVE.n));
      },

      pointAddScalar: (p, tweak, isCompressed) => {
        if (typeof p === 'string') p = hexToBytes(p);
        if (typeof tweak === 'string') tweak = hexToBytes(tweak);
        const tweaked = Point.fromBytes(p).add(Point.fromPrivateKey(tweak));
        if (tweaked.is0()) throw new Error('Tweaked point at infinity');
        return tweaked.toBytes(isCompressed);
      },

      pointMultiply: (p, tweak, isCompressed) => {
        if (typeof p === 'string') p = hexToBytes(p);
        if (typeof tweak === 'string') tweak = hexToBytes(tweak);
        const t = bytesToNumberBE(tweak);
        return Point.fromBytes(p).multiply(t).toBytes(isCompressed);
      },
    };

    should('privateAdd()', () => {
      for (const vector of VECTORS_privates.valid.add) {
        const { a, b, expected } = vector;
        eql(bytesToHex(tweakUtils.privateAdd(a, b)), expected);
      }
    });
    should('privateNegate()', () => {
      for (const vector of VECTORS_privates.valid.negate) {
        const { a, expected } = vector;
        eql(bytesToHex(tweakUtils.privateNegate(a)), expected);
      }
    });
    should('pointAddScalar()', () => {
      for (const vector of VECTORS_points.valid.pointAddScalar) {
        const { description, P, d, expected } = vector;
        const compressed = !!expected && expected.length === 66; // compressed === 33 bytes
        eql(bytesToHex(tweakUtils.pointAddScalar(P, d, compressed)), expected);
      }
    });
    should('pointAddScalar() invalid', () => {
      for (const vector of VECTORS_points.invalid.pointAddScalar) {
        const { P, d, exception } = vector;
        throws(() => tweakUtils.pointAddScalar(P, d));
      }
    });
    should('pointMultiply()', () => {
      for (const vector of VECTORS_points.valid.pointMultiply) {
        const { P, d, expected } = vector;
        eql(bytesToHex(tweakUtils.pointMultiply(P, d, true)), expected);
      }
    });
    should('pointMultiply() invalid', () => {
      for (const vector of VECTORS_points.invalid.pointMultiply) {
        const { P, d, exception } = vector;
        throws(() => tweakUtils.pointMultiply(P, d));
      }
    });
  });
});

describe('secp256k1', () => {
  should('getPublicKey() rejects invalid keys', () => {
    for (const item of getTypeTestsNonUi8a()) {
      throws(() => secp.getPublicKey(item));
    }
  });
  should('precompute', () => {
    return;
    secp.utils.precompute(4);
    checkPrivatesTxt();
  });

  should('#toBytes() roundtrip (failed case)', () => {
    const p1 =
      Point.fromPrivateKey(
        numberToBytesBE(88572218780422190464634044548753414301110513745532121983949500266768436236425n)
      );
    eql(Point.fromBytes(p1.toBytes(true)).equals(p1), true);
  });

  should('#toBytes() roundtrip', () => {
    fc.assert(
      fc.property(FC_BIGINT, (x) => {
        const p1 = Point.fromPrivateKey(numberToBytesBE(x));
        const b1 = p1.toBytes(true);
        eql(Point.fromBytes(b1).toBytes(true), b1);
      })
    );
  });

  should('.fromAffine', () => {
    if (!('fromAffine' in Point)) return;
    const xy = { x: 0n, y: 0n };
    const p = Point.fromAffine(xy);
    // eql(p, Point.ZERO);
    eql(p.aff(), xy);
  });

  should('getSharedSecret rejects invalid keys', () => {
    throws(() => secp.getSharedSecret(hexToBytes('01'), hexToBytes('02')));
  });

  should('sign legacy options', () => {
    return;
    if ('fromDER' in secp.Signature) return; // noble-curves has no this check
    const msg = hexToBytes('12'.repeat(32));
    const priv = hexToBytes('34'.repeat(32));
    throws(() => {
      secp.sign(msg, priv, { der: true });
    });
    throws(() => {
      secp.sign(msg, priv, { canonical: true });
    });
    throws(() => {
      secp.sign(msg, priv, { recovered: true });
    });
  });
});

// multiply() should equal multiplyUnsafe()
// should('ProjectivePoint#multiplyUnsafe', () => {
//   const p0 = new secp.Point(
//     55066263022277343669578718895168534326250603453777594175500187360389116729240n,
//     32670510020758816978083085130507043184471273380659243275938904335757337482424n,
//     1n
//   );
//   const z = 106011723082030650010038151861333186846790370053628296836951575624442507889495n;
//   console.log(p0.multiply(z));
//   console.log(secp.Point.normalizeZ([p0.multiplyUnsafe(z)])[0])
// });
describe('Signature', () => {
  should('.fromCompactHex() roundtrip', () => {
    fc.assert(
      fc.property(FC_BIGINT, FC_BIGINT, (r, s) => {
        const sig = new secp.Signature(r, s);
        eql(secp.Signature.fromBytes(sig.toCompactRawBytes()), sig);
      })
    );
  });

  should('.fromDERHex() roundtrip', () => {
    fc.assert(
      fc.property(FC_BIGINT, FC_BIGINT, (r, s) => {
        const sig = new secp.Signature(r, s);
        eql(sigFromDER(sigToDER(sig)), sig);
      })
    );
  });

  should('.hasHighS(), .normalizeS()', () => {
    const priv = hexToBytes('c509ae2138ddca15f6b33062cd3bf76351c79f58c82ee2c2236d835bdea19d13');
    const msg = hexToBytes('b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9');

    const hi =
      'a6bf36d52da4eef85a513a88d81996a47804a2390c9910c0bd35488effca36bf8bf1f9232ab0efe4a93704ae871aa953b34d1000cef59c9d33fcc696f935108d';
    const lo =
      'a6bf36d52da4eef85a513a88d81996a47804a2390c9910c0bd35488effca36bf740e06dcd54f101b56c8fb5178e556ab0761cce5e053039e8bd597f5d70130b4';
    const hi_ = new secp.Signature(
      75421779095773161492578598757717572512754773103551662129966816753283695785663n,
      63299015578620006752099543153250095157058828301739590985992016204296254460045n,
      0
    );
    const lo_ = new secp.Signature(
      75421779095773161492578598757717572512754773103551662129966816753283695785663n,
      52493073658696188671471441855437812695778735977335313396613146937221907034292n,
      0
    );

    const pub = secp.getPublicKey(priv);
    const sig = secp.sign(msg, priv, { lowS: false });
    eql(sig.hasHighS(), true);
    eql(sig, hi_);
    eql(sig.toCompactRawBytes(), hexToBytes(hi));

    // @ts-ignore
    if (!sig.normalizeS) return;
    const lowSig = sig.normalizeS();
    eql(lowSig.hasHighS(), false);
    eql(lowSig, lo_);
    eql(lowSig.toCompactHex(), lo);

    eql(secp.verify(sig, msg, pub, { lowS: false }), true);
    eql(secp.verify(sig, msg, pub, { lowS: true }), false);
    eql(secp.verify(lowSig, msg, pub, { lowS: true }), true);
    eql(secp.verify(lowSig, msg, pub, { lowS: false }), true);
  });
});

describe('sign()', () => {
  should('edge cases', () => {
    let invalidInputs = ['', hexToBytes(''), new Uint8Array(0)];
    throws(() => secp.getPublicKey());
    throws(() => secp.sign());
    throws(() => secp.verify());
    const validMsg = new Uint8Array(32).fill(0x05);
    for (let l = 0; l < 32; l++) {
      let priv = new Uint8Array(l).fill(0x03);
      throws(() => secp.getPublicKey(priv));
      throws(() => secp.sign(validMsg, priv));
    }
  });
});

describe('verify()', () => {
  function hexa() {
    const items = '0123456789abcdef';
    return fc.integer({ min: 0, max: 15 }).map((n) => items[n]);
  }
  function hexaString(constraints = {}) {
    return fc.string({ ...constraints, unit: hexa() });
  }
  should('verify random signatures', () =>
    fc.assert(
      fc.asyncProperty(
        FC_BIGINT,
        // @ts-ignore
        hexaString({ minLength: 64, maxLength: 64 }),
        async (privKey, msgh) => {
          const msg = hexToBytes(msgh);
          const pub = secp.getPublicKey(numberToBytesBE(privKey));
          const sig = secp.sign(msg, numberToBytesBE(privKey));
          eql(secp.verify(sig, msg, pub), true);
          if (secp.signAsync) {
            const sig = await secp.signAsync(msg, numberToBytesBE(privKey));
            eql(secp.verify(sig, msg, pub), true);
          }
        }
      )
    )
  );
  should('not verify signature with invalid r/s', () => {
    const msg = new Uint8Array([
      0xbb, 0x5a, 0x52, 0xf4, 0x2f, 0x9c, 0x92, 0x61, 0xed, 0x43, 0x61, 0xf5, 0x94, 0x22, 0xa1,
      0xe3, 0x00, 0x36, 0xe7, 0xc3, 0x2b, 0x27, 0x0c, 0x88, 0x07, 0xa4, 0x19, 0xfe, 0xca, 0x60,
      0x50, 0x23,
    ]);
    const x = 100260381870027870612475458630405506840396644859280795015145920502443964769584n;
    const y = 41096923727651821103518389640356553930186852801619204169823347832429067794568n;
    const r = 1n;
    const s = 115792089237316195423570985008687907852837564279074904382605163141518162728904n;

    const pub = new Point(x, y, 1n).toBytes();
    const sig = new secp.Signature(2n, 2n);
    throws(() => {
      sig.r = r;
      sig.s = s;
    });
    const sigHex = hexToBytes(
      '0000000000000000000000000000000000000000000000000000000000000001fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd04917c8'
    );

    const verified = secp.verify(sigHex, msg, pub);
    // Verifies, but it shouldn't, because signature S > curve order
    eql(verified, false);
  });
  should('not verify msg = curve order', () => {
    const msg = hexToBytes('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
    const x = 55066263022277343669578718895168534326250603453777594175500187360389116729240n;
    const y = 32670510020758816978083085130507043184471273380659243275938904335757337482424n;
    const r = 104546003225722045112039007203142344920046999340768276760147352389092131869133n;
    const s = 96900796730960181123786672629079577025401317267213807243199432755332205217369n;
    const pub = new Point(x, y, 1n).toBytes();
    const sig = new secp.Signature(r, s);
    eql(secp.verify(sig, msg, pub), false);
  });
  should('verify non-strict msg bb5a...', () => {
    const msg = hexToBytes('bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023');
    const x = 3252872872578928810725465493269682203671229454553002637820453004368632726370n;
    const y = 17482644437196207387910659778872952193236850502325156318830589868678978890912n;
    const r = 432420386565659656852420866390673177323n;
    const s = 115792089237316195423570985008687907852837564279074904382605163141518161494334n;
    const pub = new Point(x, y, 1n).toBytes();
    const sig = new secp.Signature(r, s);
    eql(secp.verify(sig, msg, pub, { lowS: false }), true);
  });

  describe('recoverPublicKey()', () => {
    should('recover public key from recovery bit', () => {
      const message = hexToBytes(
        '00000000000000000000000000000000000000000000000000000000deadbeef'
      );
      const privateKey = numberToBytesBE(123456789n);
      const publicKey = Point.fromBytes(secp.getPublicKey(privateKey)).toBytes(false);
      const sig = secp.sign(message, privateKey);
      const recoveredPubkey = secp.recoverPublicKey(sig, message);
      // const recoveredPubkey = secp.recoverPublicKey(message, signature, recovery);
      eql(recoveredPubkey !== null, true);
      eql(recoveredPubkey.toBytes(false), publicKey);
      eql(secp.verify(sig, message, publicKey), true);
    });
    should('not recover zero points', () => {
      const msgHash = hexToBytes(
        '6b8d2c81b11b2d699528dde488dbdf2f94293d0d33c32e347f255fa4a6c1f0a9'
      );
      const sigh = hexToBytes(
        '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817986b8d2c81b11b2d699528dde488dbdf2f94293d0d33c32e347f255fa4a6c1f0a9'
      );
      const recovery = 0;
      const sig = secp.Signature.fromBytes(sigh).addRecoveryBit(recovery);
      throws(() => secp.recoverPublicKey(sig, msgHash));
    });
    should('handle all-zeros msghash', () => {
      const privKey = secp.utils.randomPrivateKey();
      const pub = secp.getPublicKey(privKey);
      const zeros = hexToBytes('0000000000000000000000000000000000000000000000000000000000000000');
      const sig = secp.sign(zeros, privKey);
      const recoveredKey = secp.recoverPublicKey(sig, zeros);
      eql(recoveredKey.toBytes(), pub);
    });

    should('have proper curve equation in assertValidity()', () => {
      if (!secp.Point.Fp) return;
      throws(() => {
        const { Fp } = secp.Point;
        let point = new Point(Fp.create(-2n), Fp.create(-1n), Fp.create(1n));
        point.ok();
      });
    });
  });
});

describe('secp256k1 schnorr.sign()', () => {
  if (!schnorr) return;
  // index,secret key,public key,aux_rand,message,signature,verification result,comment
  const VECTORS_bip340 = txt('vectors/secp256k1/schnorr.csv', ',').slice(1, -1);
  for (let vec of VECTORS_bip340) {
    const index = vec[0];
    const [sec, pub, rnd, msg, expSig] = vec.slice(1, 6).map((item) => hexToBytes(item));
    const passes = vec[6];
    const comment = vec[7];
    should(`${comment || 'vector ' + index}`, () => {
      if (sec.length > 0) {
        eql(schnorr.getPublicKey(sec), pub);
        const sig = schnorr.sign(msg, sec, rnd);
        eql(sig, expSig);
        eql(schnorr.verify(sig, msg, pub), true);
      } else {
        const passed = schnorr.verify(expSig, msg, pub);
        eql(passed, passes === 'TRUE');
      }
    });
  }
});

should.runWhen(import.meta.url);
