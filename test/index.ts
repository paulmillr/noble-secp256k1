import * as fc from 'fast-check';
import * as secp from '..';
import { readFileSync } from 'fs';
import * as sysPath from 'path';
import * as ecdsa from './vectors/ecdsa.json';
import * as ecdh from './vectors/ecdh.json';
import * as privates from './vectors/privates.json';
import * as points from './vectors/points.json';
import * as wp from './vectors/wychenproof.json';
const privatesTxt = readFileSync(sysPath.join(__dirname, 'vectors', 'privates-2.txt'), 'utf-8');
const schCsv = readFileSync(sysPath.join(__dirname, 'vectors', 'schnorr.csv'), 'utf-8');

const FC_BIGINT = fc.bigInt(1n, secp.CURVE.n - 1n);

const toBEHex = (n: number | bigint) => n.toString(16).padStart(64, '0');
function hexToArray(hex: string): Uint8Array {
  hex = hex.length & 1 ? `0${hex}` : hex;
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    let j = i * 2;
    array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
  }
  return array;
}

describe('secp256k1', () => {
  it('.getPublicKey()', () => {
    const data = privatesTxt
      .split('\n')
      .filter((line) => line)
      .map((line) => line.split(':'));
    for (let [priv, x, y] of data) {
      const point = secp.Point.fromPrivateKey(BigInt(priv));
      expect(toBEHex(point.x)).toBe(x);
      expect(toBEHex(point.y)).toBe(y);

      const point2 = secp.Point.fromHex(secp.getPublicKey(toBEHex(BigInt(priv))));
      expect(toBEHex(point2.x)).toBe(x);
      expect(toBEHex(point2.y)).toBe(y);

      const point3 = secp.Point.fromHex(secp.getPublicKey(hexToArray(toBEHex(BigInt(priv)))));
      expect(toBEHex(point3.x)).toBe(x);
      expect(toBEHex(point3.y)).toBe(y);
    }
  });
  it('.getPublicKey() rejects invalid keys', () => {
    const invalid = [0, true, false, undefined, null, 1.1, -5, 'deadbeef', Math.pow(2, 53), [1], 'xyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxy', secp.CURVE.n + 2n];
    for (const item of invalid) {
      expect(() => secp.getPublicKey(item as any)).toThrowError();
    }
  });
  it('precompute', () => {
    secp.utils.precompute(4);
    const data = privatesTxt
      .split('\n')
      .filter((line) => line)
      .map((line) => line.split(':'));
    for (let [priv, x, y] of data) {
      const point = secp.Point.fromPrivateKey(BigInt(priv));
      expect(toBEHex(point.x)).toBe(x);
      expect(toBEHex(point.y)).toBe(y);

      const point2 = secp.Point.fromHex(secp.getPublicKey(toBEHex(BigInt(priv))));
      expect(toBEHex(point2.x)).toBe(x);
      expect(toBEHex(point2.y)).toBe(y);

      const point3 = secp.Point.fromHex(secp.getPublicKey(hexToArray(toBEHex(BigInt(priv)))));
      expect(toBEHex(point3.x)).toBe(x);
      expect(toBEHex(point3.y)).toBe(y);
    }
  });
  describe('Point', () => {
    it('.isValidPoint()', () => {
      for (const vector of points.valid.isPoint) {
        const { P, expected } = vector;
        if (expected) {
          secp.Point.fromHex(P);
        } else {
          expect(() => secp.Point.fromHex(P)).toThrowError();
        }
      }
    });

    it('.fromPrivateKey()', () => {
      for (const vector of points.valid.pointFromScalar) {
        const { d, expected } = vector;
        let p = secp.Point.fromPrivateKey(d);
        expect(p.toHex(true)).toBe(expected);
      }
    });

    it('#toHex(compressed)', () => {
      for (const vector of points.valid.pointCompress) {
        const { P, compress, expected } = vector;
        let p = secp.Point.fromHex(P);
        expect(p.toHex(compress)).toBe(expected);
      }
    });

    it('#toHex() roundtrip', () => {
      fc.assert(
        fc.property(FC_BIGINT, (x) => {

          const point1 = secp.Point.fromPrivateKey(x);
          const hex = point1.toHex(true);
          expect(secp.Point.fromHex(hex).toHex(true)).toBe(hex);
        })
      );
    });

    it('#add(other)', () => {
      for (const vector of points.valid.pointAdd) {
        const { P, Q, expected } = vector;
        let p = secp.Point.fromHex(P);
        let q = secp.Point.fromHex(Q);
        if (expected) {
          expect(p.add(q).toHex(true)).toBe(expected);
        } else {
          // console.log(p, q);
          if (!p.equals(q.negate())) {
            expect(() => p.add(q).toHex(true)).toThrowError();
          }
        }
      }
    });

    it('#multiply(privateKey)', () => {
      function hexToNumber(hex: string): bigint {
        if (typeof hex !== 'string') {
          throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
        }
        // Big Endian
        return BigInt(`0x${hex}`);
      }
      for (const vector of points.valid.pointMultiply) {
        const { P, d, expected } = vector;
        const p = secp.Point.fromHex(P);
        if (expected) {
          expect(p.multiply(hexToNumber(d)).toHex(true)).toBe(expected);
        } else {
          expect(() => {
            p.multiply(hexToNumber(d)).toHex(true);
          }).toThrowError();
        }
      }

      for (const vector of points.invalid.pointMultiply) {
        const { P, d } = vector;
        if (hexToNumber(d) < secp.CURVE.n) {
          expect(() => {
            const p = secp.Point.fromHex(P);
            p.multiply(hexToNumber(d)).toHex(true);
          }).toThrowError();
        }
      }
      for (const num of [0n, 0, -1n, -1, 1.1]) {
        expect(() => secp.Point.BASE.multiply(num)).toThrowError();
      }
    });
  });

  describe('Signature', () => {
    it('.fromHex() roundtrip', () => {
      fc.assert(
        fc.property(FC_BIGINT, FC_BIGINT, (r, s) => {
          const signature = new secp.Signature(r, s);
          const hex = signature.toDERHex();
          expect(secp.Signature.fromHex(hex)).toEqual(signature);
        })
      );
    });
  });

  describe('.sign()', () => {
    it('should create deterministic signatures with RFC 6979', async () => {
      for (const vector of ecdsa.valid) {
        const full = await secp.sign(vector.m, vector.d, { canonical: true });
        const vsig = vector.signature;
        const [vecR, vecS] = [vsig.slice(0, 64), vsig.slice(64, 128)];
        const res = secp.Signature.fromHex(full).toCompactHex();
        const [r, s] = [res.slice(0, 64), res.slice(64, 128)];
        expect(r).toBe(vecR);
        expect(s).toBe(vecS);
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
          '304402203de2559fccb00c148574997f660e4d6f40605acc71267ee38101abf15ff467af02200950abdf40628fd13f547792ba2fc544681a485f2fdafb5c3b909a4df7350e6b'
        ],
        [
          '5f97983254982546d3976d905c6165033976ee449d300d0e382099fa74deaf82',
          '3045022100c046d9ff0bd2845b9aa9dff9f997ecebb31e52349f80fe5a5a869747d31dcb88022011f72be2a6d48fe716b825e4117747b397783df26914a58139c3f4c5cbb0e66c'
        ],
        [
          '0d7017a96b97cd9be21cf28aada639827b2814a654a478c81945857196187808',
          '3045022100d18990bba7832bb283e3ecf8700b67beb39acc73f4200ed1c331247c46edccc602202e5c8bbfe47ae159512c583b30a3fa86575cddc62527a03de7756517ae4c6c73'
        ]
      ];
      const privKey = hexToArray(
        '0101010101010101010101010101010101010101010101010101010101010101'
      );
      for (let [msg, exp] of CASES) {
        const res = await secp.sign(msg, privKey, { canonical: true });
        expect(res).toBe(exp);
        const rs = secp.Signature.fromHex(res).toCompactHex();
        expect(secp.Signature.fromCompact(rs).toDERHex()).toBe(exp);
      }
    });
  });

  describe('.verify()', () => {
    it('should verify signature', async () => {
      const MSG = '1';
      const PRIV_KEY = 0x2n;
      const signature = await secp.sign(MSG, PRIV_KEY);
      const publicKey = secp.getPublicKey(PRIV_KEY);
      expect(publicKey.length).toBe(65);
      expect(secp.verify(signature, MSG, publicKey)).toBe(true);
    });
    it('should not verify signature with wrong public key', async () => {
      const MSG = '1';
      const PRIV_KEY = 0x2n;
      const WRONG_PRIV_KEY = 0x22n;
      const signature = await secp.sign(MSG, PRIV_KEY);
      const publicKey = secp.Point.fromPrivateKey(WRONG_PRIV_KEY).toHex();
      expect(publicKey.length).toBe(130);
      expect(secp.verify(signature, MSG, publicKey)).toBe(false);
    });
    it('should not verify signature with wrong hash', async () => {
      const MSG = '1';
      const PRIV_KEY = 0x2n;
      const WRONG_MSG = '11';
      const signature = await secp.sign(MSG, PRIV_KEY);
      const publicKey = secp.getPublicKey(PRIV_KEY);
      expect(publicKey.length).toBe(65);
      expect(secp.verify(signature, WRONG_MSG, publicKey)).toBe(false);
    });
    it('should verify random signatures', async () => {
      fc.assert(
        fc.asyncProperty(FC_BIGINT, fc.hexaString(64, 64), async (privKey, msg) => {
          const pub = secp.getPublicKey(privKey);
          const sig = await secp.sign(msg, privKey);
          expect(secp.verify(sig, msg, pub)).toBeTruthy();
        })
      );
    });
    it('should not verify signature with invalid r/s', () => {
      const msg = new Uint8Array([0xbb, 0x5a, 0x52, 0xf4, 0x2f, 0x9c, 0x92, 0x61, 0xed, 0x43, 0x61, 0xf5, 0x94, 0x22, 0xa1, 0xe3, 0x00, 0x36, 0xe7, 0xc3, 0x2b, 0x27, 0x0c, 0x88, 0x07, 0xa4, 0x19, 0xfe, 0xca, 0x60, 0x50, 0x23]);
      const x = 100260381870027870612475458630405506840396644859280795015145920502443964769584n;
      const y = 41096923727651821103518389640356553930186852801619204169823347832429067794568n;
      const r = 1n;
      const s = 115792089237316195423570985008687907852837564279074904382605163141518162728904n;

      const pub = new secp.Point(x, y);
      const signature = new secp.Signature(r, s);

      const verified = secp.verify(signature, msg, pub);
      // Verifies, but it shouldn't, because signature S > curve order
      expect(verified).toBeFalsy();
    });
    it('should not verify msg = curve order', async() => {
      const msg = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
      const x = 55066263022277343669578718895168534326250603453777594175500187360389116729240n;
      const y = 32670510020758816978083085130507043184471273380659243275938904335757337482424n;
      const r = 104546003225722045112039007203142344920046999340768276760147352389092131869133n;
      const s = 96900796730960181123786672629079577025401317267213807243199432755332205217369n;
      const pub = new secp.Point(x, y);
      const sig = new secp.Signature(r, s);
      expect(secp.verify(sig, msg, pub)).toBeFalsy();
    });
    it('should verify msg bb5a...', async() => {
      const msg = 'bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023';
      const x = 3252872872578928810725465493269682203671229454553002637820453004368632726370n
      const y = 17482644437196207387910659778872952193236850502325156318830589868678978890912n;
      const r = 432420386565659656852420866390673177323n;
      const s = 115792089237316195423570985008687907852837564279074904382605163141518161494334n;
      const pub = new secp.Point(x, y);
      const sig = new secp.Signature(r, s);
      expect(secp.verify(sig, msg, pub)).toBeTruthy();
    })
  });

  describe('schnorr', () => {
    // index,secret key,public key,aux_rand,message,signature,verification result,comment
    const vectors = schCsv.split('\n').map((line: string) => line.split(',')).slice(1, -1);
    for (let vec of vectors) {
      const [index, sec, pub, rnd, msg, expSig, passes, comment] = vec;
      if (index == '4' && !sec) continue; // pass test for now — it has invalid private key?

      it(`should sign with Schnorr scheme vector ${index}`, async () => {
        if (passes === 'TRUE') {
          const sig = await secp.schnorr.sign(msg, sec, rnd);
          expect(secp.schnorr.getPublicKey(sec)).toBe(pub.toLowerCase());
          expect(sig).toBe(expSig.toLowerCase());
          expect(await secp.schnorr.verify(sig, msg, pub)).toBe(true);
        } else {
          try {
            await secp.schnorr.sign(msg, sec, rnd);
            expect(false);
          } catch (error) {
            expect(error).toBeInstanceOf(Error);
          }
        }
      });
    }
  });

  describe('.recoverPublicKey()', () => {
    it('should recover public key from recovery bit', async () => {
      const message = '00000000000000000000000000000000000000000000000000000000deadbeef';
      const privateKey = 123456789n;
      const publicKey = secp.Point.fromHex(secp.getPublicKey(privateKey)).toHex(false);
      const [signature, recovery] = await secp.sign(message, privateKey, {
        recovered: true
      });
      const recoveredPubkey = secp.recoverPublicKey(message, signature, recovery);
      expect(recoveredPubkey).not.toBe(null);
      expect(recoveredPubkey).toBe(publicKey);
      expect(secp.verify(signature, message, publicKey)).toBe(true);
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
          expect(res.slice(2)).toBe(`${vector.shared}`);
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
      for (const vector of privates.valid.isPrivate) {
        const { d, expected } = vector;
        // const privateKey = hexToNumber(d);
        expect(secp.utils.isValidPrivateKey(d)).toBe(expected);
      }
    });
  });

  describe('wychenproof vectors', () => {
    it('should pass all tests', async () => {
      for (let group of wp.testGroups) {
        const pubKey = secp.Point.fromHex(group.key.uncompressed);
        for (let test of group.tests) {
          if (test.result === 'valid') {
            const hash = await secp.utils.sha256(hexToArray(test.msg));
            expect(secp.verify(test.sig, hash, pubKey)).toBeTruthy()
          } else if (test.result === 'invalid') {
            let fail = false;
            const hash = await secp.utils.sha256(hexToArray(test.msg));
            try {
              if (!secp.verify(test.sig, hash, pubKey)) fail = true;
            } catch (error) {
              fail = true;
            }
            expect(fail).toBeTruthy();
          } else {
            expect(true).toBeTruthy();
          }
        }
      }
    })
  })
});
