import * as fc from 'fast-check';
import * as secp256k1 from '..';
import { readFileSync } from 'fs';
import * as sysPath from 'path';
import * as ecdsa from './vectors/ecdsa.json';
import * as privates from './vectors/privates.json';
import * as points from './vectors/points.json';
const privatesTxt = readFileSync(sysPath.join(__dirname, 'vectors', 'privates-2.txt'), 'utf-8');

// let sha256 = (message: Uint8Array) => new Uint8Array();
// const req = require;
// const { createHash } = req("crypto");
// sha256 = (message) => {
//   const hash = createHash("sha256");
//   hash.update(message);
//   return Uint8Array.from(hash.digest());
// };
// function hash(message: string) {
//   return sha256(new TextEncoder().encode(message));
// }

const MAX_PRIVATE_KEY = secp256k1.PRIME_ORDER - 1n;

const toBEHex = (n: number | bigint) => n.toString(16).padStart(64, '0');

// const toLEHex = (n: number | bigint) =>
//   n
//     .toString(16)
//     .padStart(64, '0')
//     .replace(/\w\w/gi, a => `${a},`)
//     .split(',')
//     .reverse()
//     .slice(1)
//     .join('');

describe('secp256k1', () => {
  it('.getPublicKey()', () => {
    const data = privatesTxt
      .split('\n')
      .filter(line => line)
      .map(line => line.split(':'));
    for (let [priv, x, y] of data) {
      const point = secp256k1.Point.fromPrivateKey(BigInt(priv));
      expect(toBEHex(point.x)).toBe(x);
      expect(toBEHex(point.y)).toBe(y);
    }
  });
  describe('Point', () => {
    it('.isValidPoint()', () => {
      for (const vector of points.valid.isPoint) {
        const { P, expected } = vector;
        if (expected) {
          secp256k1.Point.fromHex(P);
        } else {
          expect(() => secp256k1.Point.fromHex(P)).toThrowError();
        }
      }
    });

    it('.fromPrivateKey()', () => {
      for (const vector of points.valid.pointFromScalar) {
        const { d, expected } = vector;
        let p = secp256k1.Point.fromPrivateKey(d);
        expect(p.toHex(true)).toBe(expected);
      }
    });

    it('#toHex(compressed)', () => {
      for (const vector of points.valid.pointCompress) {
        const { P, compress, expected } = vector;
        let p = secp256k1.Point.fromHex(P);
        expect(p.toHex(compress)).toBe(expected);
      }
    });

    it('#toHex() roundtrip', () => {
      fc.assert(
        fc.property(fc.bigInt(1n, MAX_PRIVATE_KEY), x => {
          const point1 = secp256k1.Point.fromPrivateKey(x);
          const hex = point1.toHex(true);
          expect(secp256k1.Point.fromHex(hex).toHex(true)).toBe(hex);
        })
      );
    });

    it('#add(other)', () => {
      for (const vector of points.valid.pointAdd) {
        const { P, Q, expected } = vector;
        let p = secp256k1.Point.fromHex(P);
        let q = secp256k1.Point.fromHex(Q);
        if (expected) {
          expect(p.add(q).toHex(true)).toBe(expected);
        } else {
          expect(() => p.add(q).toHex(true)).toThrowError();
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
        const p = secp256k1.Point.fromHex(P);
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
        expect(() => {
          const p = secp256k1.Point.fromHex(P);
          p.multiply(hexToNumber(d)).toHex(true);
        }).toThrowError();
      }
    });
  });

  describe('SignResult', () => {
    it('.fromHex() roundtrip', () => {
      fc.assert(
        fc.property(fc.bigInt(1n, MAX_PRIVATE_KEY), fc.bigInt(1n, MAX_PRIVATE_KEY), (r, s) => {
          const signature = new secp256k1.SignResult(r, s);
          const hex = signature.toHex();
          expect(secp256k1.SignResult.fromHex(hex)).toEqual(signature);
        })
      );
    });
  });

  describe('.sign()', () => {
    it('should create deterministic signatures with RFC 6979', async () => {
      for (const vector of ecdsa.valid) {
        const full = await secp256k1.sign(vector.m, vector.d, { canonical: true });
        const vsig = vector.signature;
        const [vecR, vecS] = [vsig.slice(0, 64), vsig.slice(64, 128)];
        const res = secp256k1.SignResult.fromHex(full);
        expect(toBEHex(res.r)).toBe(vecR);
        expect(toBEHex(res.s)).toBe(vecS);
      }
    });
  });

  describe('.verify()', () => {
    it('should verify signature', async () => {
      const MSG = '1';
      const PRIV_KEY = '2';
      const signature = await secp256k1.sign(MSG, PRIV_KEY);
      const publicKey = secp256k1.getPublicKey(PRIV_KEY);
      expect(publicKey.length).toBe(130);
      expect(secp256k1.verify(signature, MSG, publicKey)).toBe(true);
    });
    it('should not verify signature with wrong public key', async () => {
      const MSG = '1';
      const PRIV_KEY = '2';
      const WRONG_PRIV_KEY = '22';
      const signature = await secp256k1.sign(MSG, PRIV_KEY);
      const publicKey = secp256k1.Point.fromPrivateKey(WRONG_PRIV_KEY).toHex();
      expect(publicKey.length).toBe(130);
      expect(secp256k1.verify(signature, MSG, publicKey)).toBe(false);
    });
    it('should not verify signature with wrong hash', async () => {
      const MSG = '1';
      const PRIV_KEY = '2';
      const WRONG_MSG = '11';
      const signature = await secp256k1.sign(MSG, PRIV_KEY);
      const publicKey = secp256k1.getPublicKey(PRIV_KEY);
      expect(publicKey.length).toBe(130);
      expect(secp256k1.verify(signature, WRONG_MSG, publicKey)).toBe(false);
    });
  });

  describe('.recoverPublicKey()', () => {
    it('should recover public key from recovery bit', async () => {
      const message = 'deadbeef';
      const privateKey = 123456789n;
      const publicKey = secp256k1.getPublicKey(privateKey.toString(16));
      const [signature, recovery] = await secp256k1.sign(message, privateKey, {
        recovered: true
      });
      const recoveredPubkey = secp256k1.recoverPublicKey(message, signature, recovery);
      expect(recoveredPubkey).not.toBe(null);
      expect(recoveredPubkey).toBe(publicKey);
      expect(secp256k1.verify(signature, message, publicKey)).toBe(true);
    });
  });

  describe('utils', () => {
    it('isValidPrivateKey()', () => {
      for (const vector of privates.valid.isPrivate) {
        const { d, expected } = vector;
        // const privateKey = hexToNumber(d);
        expect(secp256k1.utils.isValidPrivateKey(d)).toBe(expected);
      }
    });
  });
});
