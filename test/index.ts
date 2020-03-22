import * as fc from "fast-check";
import * as secp256k1 from "..";

import * as ecdsa from './vectors/ecdsa.json';
import * as privates from './vectors/privates.json';
import * as points from './vectors/points.json';

let sha256 = (message: Uint8Array) => new Uint8Array();
const req = require;
const { createHash } = req("crypto");
sha256 = (message) => {
  const hash = createHash("sha256");
  hash.update(message);
  return Uint8Array.from(hash.digest());
};
function arrayToHex(uint8a: Uint8Array) {
  return Array.from(uint8a)
    .map(c => c.toString(16).padStart(2, "0"))
    .join("");
}
function hash(message: string) {
  return sha256(new TextEncoder().encode(message));
}
function hexToNumber(hex: string): bigint {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
  }
  // Big Endian
  return BigInt(`0x${hex}`);
}


const SignResult = secp256k1.SignResult;

const MAX_PRIVATE_KEY = secp256k1.PRIME_ORDER - 1n;

const toBEHex = (n: number | bigint) => n.toString(16).padStart(64, "0");

const toLEHex = (n: number | bigint) =>
  n
    .toString(16)
    .padStart(64, "0")
    .replace(/\w\w/gi, a => `${a},`)
    .split(",")
    .reverse()
    .slice(1)
    .join("");

describe("secp256k1", () => {
  // describe('verify()', () => {
  //   it("should verify signed message", () => {
  //     fc.assert(
  //       fc.property(
  //         fc.hexaString(32, 32),
  //         fc.bigInt(1n, MAX_PRIVATE_KEY),
  //         (message, privateKey) => {
  //           const signature = await secp256k1.sign(message, privateKey);
  //           const publicKey = secp256k1.Point.fromPrivateKey(privateKey).toHex(true);
  //           expect(publicKey.length).toBe(66);
  //           expect(secp256k1.verify(signature, message, publicKey)).toBeTruthy();
  //         }
  //       )
  //     );
  //   });
  //   it("should deny invalid message", () => {
  //     fc.assert(
  //       fc.property(
  //         fc.hexaString(32, 32),
  //         fc.hexaString(32, 32),
  //         fc.bigInt(1n, MAX_PRIVATE_KEY),
  //         (message, wrongMessage, privateKey) => {
  //           const signature = await secp256k1.sign(message, privateKey);
  //           const publicKey = secp256k1.getPublicKey(privateKey);
  //           expect(secp256k1.verify(signature, wrongMessage, publicKey)).toBe(
  //             message === wrongMessage
  //           );
  //         }
  //       )
  //     );
  //   });
  // });

  it("SignResult#fromHex()", () => {
    fc.assert(
      fc.property(
        fc.bigInt(1n, MAX_PRIVATE_KEY),
        fc.bigInt(1n, MAX_PRIVATE_KEY),
        (r, s) => {
          const signature = new secp256k1.SignResult(r, s);
          const hex = signature.toHex();
          expect(SignResult.fromHex(hex)).toEqual(signature);
        }
      )
    );
  });
  // it("should resove valid curve point", () => {
  //   fc.assert(
  //     fc.property(
  //       fc.bigInt(1n, MAX_PRIVATE_KEY),
  //       fc.integer(2, 3),
  //       (x, prefix) => {
  //         const compresedHex = `0${prefix}${toLEHex(x)}`;
  //         const point = secp256k1.Point.fromHex(compresedHex);
  //         const uncompressedHex = point.toHex();
  //         expect(secp256k1.Point.fromHex(uncompressedHex)).toEqual(point);
  //       }
  //     )
  //   );
  // });
  // it("should reject invalid curve point", () => {
  //   fc.assert(
  //     fc.property(
  //       fc.bigInt(1n, MAX_PRIVATE_KEY),
  //       (x, prefix) => {
  //         const point = secp256k1.Point.fromHex(compresedHex);
  //         point.x = secp256k1.PRIME_ORDER + 6n;
  //         const uncompressedHex = point.toHex();
  //         expect(() => secp256k1.Point.fromHex(uncompressedHex)).toThrow(
  //           new TypeError("Point.fromHex: Point is not on elliptic curve")
  //         );
  //       }
  //     )
  //   );
  // });
  // it("should recovery public key from recovery bit", () => {
  //   fc.assert(
  //     fc.property(
  //       fc.hexa(),
  //       fc.bigInt(1n, MAX_PRIVATE_KEY),
  //       (message, privateKey) => {
  //         const [signature, recovery] = secp256k1.sign(message, privateKey, { recovered: true });
  //         const recoveredPublicKey = secp256k1.recoverPublicKey(message, signature, recovery);
  //         const publicKey = secp256k1.getPublicKey(privateKey);
  //         expect(recoveredPublicKey).not.toBe(null);
  //         expect(secp256k1.verify(signature, message, publicKey)).toBe(true);
  //       }
  //     )
  //   );
  // });

  const PRIVATE_KEY = "86ad0882dbbb8156e85b5eea72b2645ddda4da857e0cc4e95035761adbb9876e";
  const MESSAGE = "63262f29f0c9c0abc347b5c519f646d6ff683760";
  const WRONG_MESSAGE = "ab9c7f26c71e9d442bccd5fdc9747b3b74c8d587";
  it("should sign and verify", async () => {
    const signature = await secp256k1.sign(MESSAGE, PRIVATE_KEY);
    const publicKey = secp256k1.getPublicKey(PRIVATE_KEY, true);
    expect(publicKey.length).toBe(66);
    expect(secp256k1.verify(signature, MESSAGE, publicKey)).toBe(true);
  });
  it("should not verify signature with wrong public key", async () => {
    const signature = await secp256k1.sign(MESSAGE, PRIVATE_KEY);
    const publicKey = secp256k1.Point.fromPrivateKey(12).toHex(true);
    expect(publicKey.length).toBe(66);
    expect(secp256k1.verify(signature, MESSAGE, publicKey)).toBe(false);
  });
  it("should not verify signature with wrong hash", async () => {
    const signature = await secp256k1.sign(MESSAGE, PRIVATE_KEY);
    const publicKey = secp256k1.getPublicKey(PRIVATE_KEY, true);
    expect(publicKey.length).toBe(66);
    expect(secp256k1.verify(signature, WRONG_MESSAGE, publicKey)).toBe(false);
  });

  describe('utils', () => {
    it('isValidPrivateKey()', () => {
      for (const vector of privates.valid.isPrivate) {
        const {d, expected, description} = vector;
        const privateKey = hexToNumber(d);
        expect(secp256k1.utils.isValidPrivateKey(d)).toBe(expected);
      }
    });
  });

  describe('Point', () => {
    it('.isValidPoint()', () => {
      for (const vector of points.valid.isPoint) {
        const {P, expected, description} = vector;
        if (expected) {
          secp256k1.Point.fromHex(P);
        } else {
          expect(() => secp256k1.Point.fromHex(P)).toThrowError();
        }
      }
    });

    it('.fromPrivateKey()', () => {
      for (const vector of points.valid.pointFromScalar) {
        const {d, expected} = vector;
        let p = secp256k1.Point.fromPrivateKey(d);
        expect(p.toHex(true)).toBe(expected);
      }
    });

    it("#toHex(compressed)", () => {
      for (const vector of points.valid.pointCompress) {
        const {P, compress, expected} = vector;
        let p = secp256k1.Point.fromHex(P);
        let actual = p.toHex(compress);
        expect(p.toHex(compress)).toBe(expected);
      }
    });

    it(".toHex() roundtrip", () => {
      fc.assert(
        fc.property(
          fc.bigInt(1n, MAX_PRIVATE_KEY),
          (x) => {
            const point1 = secp256k1.Point.fromPrivateKey(x);
            const hex = point1.toHex(true);
            expect(secp256k1.Point.fromHex(hex).toHex(true)).toBe(hex);
          }
        )
      );
    });

    it('#add(other)', () => {
      for (const vector of points.valid.pointAdd) {
        const {P, Q, expected, description} = vector;
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
        const {P, d, expected, description} = vector;
        const p = secp256k1.Point.fromHex(P);
        if (expected) {
          expect(p.multiply(hexToNumber(d)).toHex(true)).toBe(expected);
        } else {
          expect(() => {
            p.multiply(hexToNumber(d)).toHex(true)
          }).toThrowError();
        }
      }

      for (const vector of points.invalid.pointMultiply) {
        const {P, d, description} = vector;
        expect(() => {
          const p = secp256k1.Point.fromHex(P);
          p.multiply(hexToNumber(d)).toHex(true);
        }).toThrowError();
      }
    });
  });

  describe('.sign()', () => {
    it('should create deterministic signatures with RFC 6979', async () => {
      for (const vector of ecdsa.valid) {
        const full = await secp256k1.sign(vector.m, vector.d, {canonical: true});
        const vsig = vector.signature;
        const [vecR, vecS] = [vsig.slice(0, 64), vsig.slice(64, 128)];
        const res = secp256k1.SignResult.fromHex(full);
        expect(toBEHex(res.r)).toBe(vecR);
        expect(toBEHex(res.s)).toBe(vecS);
      }
    })
  });
});
