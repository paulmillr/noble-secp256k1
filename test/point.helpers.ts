import { secp as secp256k1 } from './secp256k1.helpers.ts';
import { bytesToHex as hex, hexToBytes, invert, mod } from './utils.helpers.ts';

// prettier-ignore
export const CURVES = {
  secp256k1,
};

export function getOtherCurve(_currCurveName) {
  class Point {
    constructor() {}
    add() {
      throw new Error('1');
    }
    subtract() {
      throw new Error('1');
    }
    multiply() {
      throw new Error('1');
    }
    multiplyUnsafe() {}
    static fromAffine() {
      throw new Error('1');
    }
  }
  return { Point };
}

export const pippenger = undefined;
export const precomputeMSMUnsafe = undefined;
export const wNAF = undefined;
export { hex, hexToBytes, invert, mod };
