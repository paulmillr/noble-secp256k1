import * as fc from 'fast-check';
import * as secp from '..';
import { readFileSync } from 'fs';
import { createHash } from 'crypto';
// import { createHash } from 'crypto';
import * as sysPath from 'path';
import * as ecdsa from './vectors/ecdsa.json';
import * as ecdh from './vectors/ecdh.json';
import * as privates from './vectors/privates.json';
import * as points from './vectors/points.json';
import * as wp from './vectors/wychenproof.json';
const privatesTxt = readFileSync(sysPath.join(__dirname, 'vectors', 'privates-2.txt'), 'utf-8');
const schCsv = readFileSync(sysPath.join(__dirname, 'vectors', 'schnorr.csv'), 'utf-8');

const FC_BIGINT = fc.bigInt(1n + 1n, secp.CURVE.n - 1n);
// prettier-ignore
const INVALID_ITEMS = ['deadbeef', Math.pow(2, 53), [1], 'xyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxy', secp.CURVE.n + 2n];

// secp.utils.sha256Sync = (...msgs) =>
//   createHash('sha256')
//     .update(secp.utils.concatBytes(...msgs))
//     .digest();

const toBEHex = (n: number | bigint) => n.toString(16).padStart(64, '0');
const hex = secp.utils.bytesToHex;
const hexToBytes = secp.utils.hexToBytes;
const Point = secp.JPoint;

// const { Signature } = secp;
const { bytesToNumber: b2n, hexToBytes: h2b } = secp.utils;
const DER = {
  // asn.1 DER encoding utils
  Err: class DERErr extends Error {
    constructor(m = '') {
      super(m);
    }
  },
  _parseInt(data: Uint8Array): { d: bigint; l: Uint8Array } {
    const { Err: E } = DER;
    if (data.length < 2 || data[0] !== 0x02) throw new E('Invalid signature integer tag');
    const len = data[1];
    const res = data.subarray(2, len + 2);
    if (!len || res.length !== len) throw new E('Invalid signature integer: wrong length');
    if (res[0] === 0x00 && res[1] <= 0x7f)
      throw new E('Invalid signature integer: trailing length');
    // ^ Weird condition: not about length, but about first bytes of number.
    return { d: b2n(res), l: data.subarray(len + 2) }; // d is data, l is left
  },
  toSig(hex: string) {
    // parse DER signature
    const { Err: E } = DER;
    const data = typeof hex === 'string' ? secp.utils.hexToBytes(hex) : hex;
    let l = data.length;
    if (l < 2 || data[0] != 0x30) throw new E('Invalid signature tag');
    if (data[1] !== l - 2) throw new E('Invalid signature: incorrect length');
    const { d: r, l: sBytes } = DER._parseInt(data.subarray(2));
    const { d: s, l: rBytesLeft } = DER._parseInt(sBytes);
    if (rBytesLeft.length) throw new E('Invalid signature: left bytes after parsing');
    return new secp.Signature(r, s);
  },
  fromSig(sig: secp.Signature): Uint8Array {
    return h2b(DER.hexFromSig(sig));
  },
  hexFromSig(sig: secp.Signature): string {
    const slice = (s: string): string => (Number.parseInt(s[0], 16) >= 8 ? '00' + s : s); // slice DER
    const h = (num: number | bigint) => {
      const hex = num.toString(16);
      return hex.length & 1 ? `0${hex}` : hex;
    };
    const s = slice(h(sig.s)),
      r = slice(h(sig.r));
    const shl = s.length / 2,
      rhl = r.length / 2;
    const sl = h(shl),
      rl = h(rhl);
    return `30${h(rhl + shl + 4)}02${rl}${r}02${sl}${s}`;
  },
};

function hexToNumber(hex: string): bigint {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
  }
  // Big Endian
  return BigInt(`0x${hex}`);
}

describe('secp256k1', () => {
  it('.getPublicKey()', () => {
    const data = privatesTxt
      .split('\n')
      .filter((line) => line)
      .map((line) => line.split(':'));
    for (let [priv, x, y] of data) {
      const { x: x1, y: y1 } = Point.fromPrivateKey(BigInt(priv)).aff();
      expect(toBEHex(x1)).toBe(x);
      expect(toBEHex(y1)).toBe(y);

      const { x: x2, y: y2 } = Point.fromHex(secp.getPublicKey(toBEHex(BigInt(priv)))).aff();
      expect(toBEHex(x2)).toBe(x);
      expect(toBEHex(y2)).toBe(y);

      const { x: x3, y: y3 } = Point.fromHex(
        secp.getPublicKey(hexToBytes(toBEHex(BigInt(priv))))
      ).aff();
      expect(toBEHex(x3)).toBe(x);
      expect(toBEHex(y3)).toBe(y);
    }
  });
  it('.getPublicKey() rejects invalid keys', () => {
    for (const item of INVALID_ITEMS) {
      expect(() => secp.getPublicKey(item as any)).toThrowError();
    }
  });
  // it('precompute', () => {
  //   // secp.utils.precompute(4);
  //   const data = privatesTxt
  //     .split('\n')
  //     .filter((line) => line)
  //     .map((line) => line.split(':'));
  //   for (let [priv, x, y] of data) {
  //     const point = secp.Point.fromPrivateKey(BigInt(priv));
  //     expect(toBEHex(point.x)).toBe(x);
  //     expect(toBEHex(point.y)).toBe(y);

  //     const point2 = secp.Point.fromHex(secp.getPublicKey(toBEHex(BigInt(priv))));
  //     expect(toBEHex(point2.x)).toBe(x);
  //     expect(toBEHex(point2.y)).toBe(y);

  //     const point3 = secp.Point.fromHex(secp.getPublicKey(hexToBytes(toBEHex(BigInt(priv)))));
  //     expect(toBEHex(point3.x)).toBe(x);
  //     expect(toBEHex(point3.y)).toBe(y);
  //   }
  // });
  describe('Point', () => {
    it('.isValidPoint()', () => {
      for (const vector of points.valid.isPoint) {
        const { P, expected } = vector;
        if (expected) {
          Point.fromHex(P);
        } else {
          expect(() => Point.fromHex(P)).toThrowError();
        }
      }
    });

    it('.fromPrivateKey()', () => {
      for (const vector of points.valid.pointFromScalar) {
        const { d, expected } = vector;
        let p = Point.fromPrivateKey(d);
        expect(p.toHex(true)).toBe(expected);
      }
    });

    it('#toHex(compressed)', () => {
      for (const vector of points.valid.pointCompress) {
        const { P, compress, expected } = vector;
        let p = Point.fromHex(P);
        expect(p.toHex(compress)).toBe(expected);
      }
    });

    it('#toHex() roundtrip', () => {
      fc.assert(
        fc.property(FC_BIGINT, (x) => {
          const point1 = Point.fromPrivateKey(x);
          const hex = point1.toHex(true);
          expect(Point.fromHex(hex).toHex(true)).toBe(hex);
        })
      );
    });

    it('#add(other)', () => {
      for (const vector of points.valid.pointAdd) {
        const { P, Q, expected } = vector;
        let p = Point.fromHex(P);
        let q = Point.fromHex(Q);
        if (expected) {
          expect(p.add(q).toHex(true)).toBe(expected);
        } else {
          if (p.eql(q.neg())) {
            expect(p.add(q).toHex(true)).toBe(Point.I.toHex(true));
          } else {
            expect(() => p.add(q).toHex(true)).toThrowError();
          }
        }
      }
    });

    it('#multiply(privateKey)', () => {
      for (const vector of points.valid.pointMultiply) {
        const { P, d, expected } = vector;
        const p = Point.fromHex(P);
        if (expected) {
          expect(p.mul(hexToNumber(d)).toHex(true)).toBe(expected);
        } else {
          expect(() => {
            p.mul(hexToNumber(d)).toHex(true);
          }).toThrowError();
        }
      }

      for (const vector of points.invalid.pointMultiply) {
        const { P, d } = vector;
        if (hexToNumber(d) < secp.CURVE.n) {
          expect(() => {
            const p = Point.fromHex(P);
            p.mul(hexToNumber(d)).toHex(true);
          }).toThrowError();
        }
      }
      for (const num of [0n, 0, -1n, -1, 1.1]) {
        // @ts-ignore
        expect(() => Point.G.multiply(num)).toThrowError();
      }
    });

    // multiply() should equal multiplyUnsafe()
    // it('JacobianPoint#multiplyUnsafe', () => {
    //   const p0 = new secp.JacobianPoint(
    //     55066263022277343669578718895168534326250603453777594175500187360389116729240n,
    //     32670510020758816978083085130507043184471273380659243275938904335757337482424n,
    //     1n
    //   );
    //   const z = 106011723082030650010038151861333186846790370053628296836951575624442507889495n;
    //   console.log(p0.multiply(z));
    //   console.log(secp.JacobianPoint.normalizeZ([p0.multiplyUnsafe(z)])[0])
    // });
  });

  describe('Signature', () => {
    it('.fromCompactHex() roundtrip', () => {
      fc.assert(
        fc.property(FC_BIGINT, FC_BIGINT, (r, s) => {
          const sig = new secp.Signature(r, s);
          expect(secp.Signature.fromCompact(sig.toCompactHex())).toEqual(sig);
        })
      );
    });

    it('.fromDERHex() roundtrip', () => {
      fc.assert(
        fc.property(FC_BIGINT, FC_BIGINT, (r, s) => {
          const sig = new secp.Signature(r, s);
          expect(DER.toSig(DER.hexFromSig(sig))).toEqual(sig);
        })
      );
    });
  });

  describe('.sign()', () => {
    it('should create deterministic signatures with RFC 6979', async () => {
      for (const vector of ecdsa.valid) {
        let usig = await secp.sign(vector.m, vector.d);
        let sig = usig.toCompactHex();
        const vsig = vector.signature;
        expect(sig.slice(0, 64)).toBe(vsig.slice(0, 64));
        expect(sig.slice(64, 128)).toBe(vsig.slice(64, 128));
      }
    });

    it('should not create invalid deterministic signatures with RFC 6979', async () => {
      for (const vector of ecdsa.invalid.sign) {
        expect(() => {
          return secp.sign(vector.m, vector.d);
        }).rejects.toThrowError();
      }
    });

    it('edge cases', () => {
      // @ts-ignore
      expect(async () => await secp.sign()).rejects.toThrowError();
      // @ts-ignore
      expect(async () => await secp.sign('')).rejects.toThrowError();
    });

    it('should create correct DER encoding against libsecp256k1', async () => {
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
      const privKey = hexToBytes(
        '0101010101010101010101010101010101010101010101010101010101010101'
      );
      for (let [msg, exp] of CASES) {
        const res = await secp.sign(msg, privKey, { extraEntropy: undefined });
        const derRes = DER.hexFromSig(res);
        expect(derRes).toBe(exp);
        const derRes2 = DER.toSig(derRes);
        expect(DER.hexFromSig(derRes2)).toBe(exp);
      }
    });
    it('sign ecdsa extraData', async () => {
      const ent1 = '0000000000000000000000000000000000000000000000000000000000000000';
      const ent2 = '0000000000000000000000000000000000000000000000000000000000000001';
      const ent3 = '6e723d3fd94ed5d2b6bdd4f123364b0f3ca52af829988a63f8afe91d29db1c33';
      const ent4 = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';
      const ent5 = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

      for (const e of ecdsa.extraEntropy) {
        const sign = async (extraEntropy?: string) => {
          const s = await secp.sign(e.m, e.d, { extraEntropy });
          return s.toCompactHex();
        };
        expect(await sign()).toBe(e.signature);
        expect(await sign(ent1)).toBe(e.extraEntropy0);
        expect(await sign(ent2)).toBe(e.extraEntropy1);
        expect(await sign(ent3)).toBe(e.extraEntropyRand);
        expect(await sign(ent4)).toBe(e.extraEntropyN);
        expect(await sign(ent5)).toBe(e.extraEntropyMax);
      }
    });
  });

  describe('.verify()', () => {
    it('should verify signature', async () => {
      const MSG = '01'.repeat(32);
      const PRIV_KEY = secp.utils.numToField(0x2n);
      const signature = await secp.sign(MSG, PRIV_KEY);
      const publicKey = secp.getPublicKey(PRIV_KEY);
      expect(publicKey.length).toBe(65);
      expect(secp.verify(signature, MSG, publicKey)).toBe(true);
    });
    it('should not verify signature with wrong public key', async () => {
      const MSG = '01'.repeat(32);
      const PRIV_KEY = secp.utils.numToField(0x2n);
      const WRONG_PRIV_KEY = secp.utils.numToField(0x22n);
      const signature = await secp.sign(MSG, PRIV_KEY);
      const publicKey = Point.fromPrivateKey(WRONG_PRIV_KEY).toHex();
      expect(publicKey.length).toBe(130);
      expect(secp.verify(signature, MSG, publicKey)).toBe(false);
    });
    it('should not verify signature with wrong hash', async () => {
      const MSG = '01'.repeat(32);
      const PRIV_KEY = secp.utils.numToField(0x2n);
      const WRONG_MSG = '11'.repeat(32);
      const signature = await secp.sign(MSG, PRIV_KEY);
      const publicKey = secp.getPublicKey(PRIV_KEY);
      expect(publicKey.length).toBe(65);
      expect(secp.verify(signature, WRONG_MSG, publicKey)).toBe(false);
    });
    it('should verify random signatures', async () =>
      fc.assert(
        fc.asyncProperty(
          FC_BIGINT,
          fc.hexaString({ minLength: 64, maxLength: 64 }),
          async (privKey, msg) => {
            const pk = secp.utils.numToField(privKey);
            const pub = secp.getPublicKey(pk);
            const sig = await secp.sign(msg, pk);
            expect(secp.verify(sig, msg, pub)).toBeTruthy();
          }
        )
      ));
    it('should not verify signature with invalid r/s', () => {
      const msg = new Uint8Array([
        0xbb, 0x5a, 0x52, 0xf4, 0x2f, 0x9c, 0x92, 0x61, 0xed, 0x43, 0x61, 0xf5, 0x94, 0x22, 0xa1,
        0xe3, 0x00, 0x36, 0xe7, 0xc3, 0x2b, 0x27, 0x0c, 0x88, 0x07, 0xa4, 0x19, 0xfe, 0xca, 0x60,
        0x50, 0x23,
      ]);
      const x = 100260381870027870612475458630405506840396644859280795015145920502443964769584n;
      const y = 41096923727651821103518389640356553930186852801619204169823347832429067794568n;
      const r = 1n;
      const s = 115792089237316195423570985008687907852837564279074904382605163141518162728904n;

      const pub = new Point(x, y);
      const signature = new secp.Signature(2n, 2n);
      // @ts-ignore
      signature.r = r;
      // @ts-ignore
      signature.s = s;

      const verified = secp.verify(signature, msg, pub.toRawBytes());
      // Verifies, but it shouldn't, because signature S > curve order
      expect(verified).toBeFalsy();
    });
    it('should not verify msg = curve order', async () => {
      const msg = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';
      const x = 55066263022277343669578718895168534326250603453777594175500187360389116729240n;
      const y = 32670510020758816978083085130507043184471273380659243275938904335757337482424n;
      const r = 104546003225722045112039007203142344920046999340768276760147352389092131869133n;
      const s = 96900796730960181123786672629079577025401317267213807243199432755332205217369n;
      const pub = new Point(x, y).toRawBytes();
      const sig = new secp.Signature(r, s);
      expect(secp.verify(sig, msg, pub)).toBeFalsy();
    });
    it('should verify non-strict msg bb5a...', async () => {
      const msg = 'bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023';
      const x = 3252872872578928810725465493269682203671229454553002637820453004368632726370n;
      const y = 17482644437196207387910659778872952193236850502325156318830589868678978890912n;
      const r = 432420386565659656852420866390673177323n;
      const s = 115792089237316195423570985008687907852837564279074904382605163141518161494334n;
      const pub = new Point(x, y).toRawBytes();
      const sig = new secp.Signature(r, s);
      expect(secp.verify(sig, msg, pub, { lowS: false })).toBeTruthy();
    });
    it('should not verify invalid deterministic signatures with RFC 6979', () => {
      for (const vector of ecdsa.invalid.verify) {
        const res = secp.verify(vector.signature, vector.m, vector.Q);
        expect(res).toBeFalsy();
      }
    });
  });

  // describe('schnorr', () => {
  //   // index,secret key,public key,aux_rand,message,signature,verification result,comment
  //   const vectors = schCsv
  //     .split('\n')
  //     .map((line: string) => line.split(','))
  //     .slice(1, -1);
  //   for (let vec of vectors) {
  //     const [index, sec, pub, rnd, msg, expSig, passes, comment] = vec;
  //     it(`should sign with Schnorr scheme vector ${index}`, async () => {
  //       if (sec) {
  //         expect(hex(secp.schnorr.getPublicKey(sec))).toBe(pub.toLowerCase());
  //         const sig = await secp.schnorr.sign(msg, sec, rnd);
  //         const sigS = secp.schnorr.signSync(msg, sec, rnd);
  //         expect(hex(sig)).toBe(expSig.toLowerCase());
  //         expect(hex(sigS)).toBe(expSig.toLowerCase());
  //         expect(await secp.schnorr.verify(sigS, msg, pub)).toBe(true);
  //         expect(secp.schnorr.verifySync(sig, msg, pub)).toBe(true);
  //       } else {
  //         const passed = await secp.schnorr.verify(expSig, msg, pub);
  //         const passedS = secp.schnorr.verifySync(expSig, msg, pub);
  //         if (passes === 'TRUE') {
  //           expect(passed).toBeTruthy();
  //           expect(passedS).toBeTruthy();
  //         } else {
  //           expect(passed).toBeFalsy();
  //           expect(passedS).toBeFalsy();
  //         }
  //       }
  //     });
  //   }
  // });

  describe('.recoverPublicKey()', () => {
    it('should recover public key from recovery bit', async () => {
      const message = '00000000000000000000000000000000000000000000000000000000deadbeef';
      const privateKey = secp.utils.numToField(123456789n);
      const publicKey = Point.fromHex(secp.getPublicKey(privateKey)).toHex(false);
      const sig = await secp.sign(message, privateKey);
      const recoveredPubkey = sig.recoverPublicKey(message);
      expect(recoveredPubkey).not.toBe(null);
      expect(recoveredPubkey.toHex()).toBe(publicKey);
      expect(secp.verify(sig, message, publicKey)).toBe(true);
    });
    it('should not recover zero points', () => {
      const msgHash = '6b8d2c81b11b2d699528dde488dbdf2f94293d0d33c32e347f255fa4a6c1f0a9';
      const sig =
        '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817986b8d2c81b11b2d699528dde488dbdf2f94293d0d33c32e347f255fa4a6c1f0a9';
      const recovery = 0;
      const sigi = secp.Signature.fromCompact(sig);
      const sigir = new secp.Signature(sigi.r, sigi.s, recovery);
      expect(() => sigir.recoverPublicKey(msgHash)).toThrowError();
    });
    it('should handle all-zeros msghash', async () => {
      const privKey = secp.utils.randomPrivateKey();
      const pub = secp.getPublicKey(privKey);
      const zeros = '0000000000000000000000000000000000000000000000000000000000000000';
      const sig = await secp.sign(zeros, privKey);
      const recoveredKey = sig.recoverPublicKey(zeros);
      expect(recoveredKey.toRawBytes()).toEqual(pub);
    });
    it('should handle RFC 6979 vectors', async () => {
      for (const vector of ecdsa.valid) {
        if (secp.utils.mod(hexToNumber(vector.m), secp.CURVE.n) === 0n) continue;
        let sig = await secp.sign(vector.m, vector.d);
        // let sig = hex(usig);
        const vpub = secp.getPublicKey(vector.d);
        const recovered = sig.recoverPublicKey(vector.m)!;
        expect(recovered.toHex()).toBe(hex(vpub));
      }
    });
  });

  describe('.getSharedSecret()', () => {
    // TODO: Real implementation.
    function derToPub(der: string) {
      return der.slice(46);
    }
    it('should produce correct results', () => {
      // TODO: Once der is there, run all tests.
      for (const vector of ecdh.testGroups[0].tests.slice(0, 230)) {
        if (vector.result === 'invalid' || vector.private.length !== 64) {
          expect(() => {
            secp.getSharedSecret(vector.private, derToPub(vector.public), true);
          }).toThrowError();
        } else if (vector.result === 'valid') {
          const res = secp.getSharedSecret(vector.private, derToPub(vector.public), true);
          expect(hex(res.slice(1))).toBe(`${vector.shared}`);
        }
      }
    });
    it('priv/pub order matters', () => {
      for (const vector of ecdh.testGroups[0].tests.slice(0, 100)) {
        if (vector.result === 'valid') {
          let priv = vector.private;
          priv = priv.length === 66 ? priv.slice(2) : priv;
          expect(() => secp.getSharedSecret(derToPub(vector.public), priv, true)).toThrowError();
        }
      }
    });
    it('rejects invalid keys', () => {
      expect(() => secp.getSharedSecret('01', '02')).toThrowError();
    });
  });

  describe('utils', () => {
    it('isValidPrivateKey()', () => {
      // @ts-ignore
      for (const vector of privates.valid.isPrivate) {
        const { d, expected } = vector;
        expect(secp.utils.isValidPrivateKey(d)).toBe(expected);
      }
    });
    // const normal = secp.utils._normalizePrivateKey;
    const normal = (a: any) => {
      if (typeof a === 'string') a = secp.utils.hexToBytes(a);
      if (a instanceof Uint8Array) return secp.utils.bytesToNumber(a);
      if (typeof a === 'number' || typeof a === 'bigint') return BigInt(a);
      throw new Error();
    };
    type Hex = string | Uint8Array;
    type PrivKey = Hex | bigint | number;
    const tweakUtils = {
      privateAdd: (privateKey: PrivKey, tweak: Hex): Uint8Array => {
        const p = normal(privateKey);
        const t = normal(tweak);
        return secp.utils.numToField(secp.utils.mod(p + t, secp.CURVE.n));
      },

      privateNegate: (privateKey: PrivKey): Uint8Array => {
        const p = normal(privateKey);
        return secp.utils.numToField(secp.CURVE.n - p);
      },

      pointAddScalar: (p: Hex, tweak: Hex, isCompressed?: boolean): Uint8Array => {
        const P = Point.fromHex(p);
        const t = normal(tweak);
        const Q = P.add(Point.G.mul(t));
        // const Q = Point.G.multiplyAndAddUnsafe(P, t, 1n);
        if (!Q || Q.eql(Point.I)) throw new Error('Tweaked point at infinity');
        return Q.toRawBytes(isCompressed);
      },

      pointMultiply: (p: Hex, tweak: Hex, isCompressed?: boolean): Uint8Array => {
        const P = Point.fromHex(p);
        const h = typeof tweak === 'string' ? tweak : secp.utils.bytesToHex(tweak);
        const t = BigInt(`0x${h}`);
        return P.mul(t).toRawBytes(isCompressed);
      },
    };

    it('privateAdd()', () => {
      // @ts-ignore
      for (const vector of privates.valid.add) {
        const { a, b, expected } = vector;
        expect(secp.utils.bytesToHex(tweakUtils.privateAdd(a, b))).toBe(expected);
      }
    });
    it('privateNegate()', () => {
      // @ts-ignore
      for (const vector of privates.valid.negate) {
        const { a, expected } = vector;
        expect(secp.utils.bytesToHex(tweakUtils.privateNegate(a))).toBe(expected);
      }
    });
    it('pointAddScalar()', () => {
      for (const vector of points.valid.pointAddScalar) {
        const { description, P, d, expected } = vector;
        const compressed = !!expected && expected.length === 66; // compressed === 33 bytes
        expect(secp.utils.bytesToHex(tweakUtils.pointAddScalar(P, d, compressed))).toBe(expected);
      }
    });
    it('pointAddScalar() invalid', () => {
      for (const vector of points.invalid.pointAddScalar) {
        const { P, d, exception } = vector;
        expect(() => tweakUtils.pointAddScalar(P, d)).toThrowError();
      }
    });
    it('pointMultiply()', () => {
      for (const vector of points.valid.pointMultiply) {
        const { P, d, expected } = vector;
        expect(secp.utils.bytesToHex(tweakUtils.pointMultiply(P, d, true))).toBe(expected);
      }
    });
    it('pointMultiply() invalid', () => {
      for (const vector of points.invalid.pointMultiply) {
        const { P, d, exception } = vector;
        expect(() => tweakUtils.pointMultiply(P, d)).toThrowError();
      }
    });
  });

  describe('wychenproof vectors', () => {
    const sha256 = (m: Uint8Array) => Uint8Array.from(createHash('sha256').update(m).digest());
    it('should pass all tests', async () => {
      for (let group of wp.testGroups) {
        const pubKey = Point.fromHex(group.key.uncompressed);
        for (let test of group.tests) {
          const m = sha256(hexToBytes(test.msg));
          if (test.result === 'valid' || test.result === 'acceptable') {
            const parsed = DER.toSig(test.sig);
            const verified = secp.verify(parsed, m, group.key.uncompressed);
            if (parsed.s > secp.CURVE.n >> 1n) {
              expect(verified).toBeFalsy();
            } else {
              expect(verified).toBeTruthy();
            }
          } else if (test.result === 'invalid') {
            let failed = false;
            try {
              const verified = secp.verify(test.sig, m, group.key.uncompressed);
              if (!verified) failed = true;
            } catch (error) {
              failed = true;
            }
            expect(failed).toBeTruthy();
          } else {
            expect(false).toBeTruthy();
          }
        }
      }
    });
  });
});

// describe('JacobianPoint', () => {
//   const JZERO = Point.I;
//   const AZERO = { x: 0n, y: 0n };
//   expect(AZERO.equals(JZERO)).toBeTruthy();
//   expect(AZERO.toAffine().equals(JZERO.toAffine())).toBeTruthy();
// });
