import {
  getPublicKey,
  sign,
  verify,
  recoverPublicKey,
  getSharedSecret,
  utils,
  CURVE,
  Point,
} from './index.ts';
import { hmac } from 'https://denopkg.com/chiefbiiko/hmac/mod.ts';

function concatTypedArrays(...arrays: Uint8Array[]): Uint8Array {
  if (arrays.length === 1) return arrays[0];
  const length = arrays.reduce((a, arr) => a + arr.length, 0);
  const result = new Uint8Array(length);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const arr = arrays[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
}

utils.hmacSha256 = async (key: Uint8Array, ...messages: Uint8Array[]): Promise<Uint8Array> => {
  return hmac('sha256', key, concatTypedArrays(...messages)) as Uint8Array;
};

export { getPublicKey, sign, verify, recoverPublicKey, getSharedSecret, utils, CURVE, Point };
