// prettier-ignore
import {
  getPublicKey, sign, signSync, verify,
  recoverPublicKey, getSharedSecret,
  utils, CURVE, Point, Signature, schnorr
} from './index.ts';
import { Sha256, HmacSha256 } from 'https://deno.land/std@0.119.0/hash/sha256.ts';

function sha256(...messages: Uint8Array[]) {
  const sha = new Sha256();
  for (let msg of messages) sha.update(msg);
  return new Uint8Array(sha.arrayBuffer());
}

function hmac(key: Uint8Array, ...messages: Uint8Array[]): Uint8Array {
  const sha = new HmacSha256(key);
  for (let msg of messages) sha.update(msg);
  return new Uint8Array(sha.arrayBuffer());
}

utils.sha256 = async (...messages: Uint8Array[]) => Promise.resolve(sha256(...messages));
utils.sha256Sync = (...messages: Uint8Array[]) => sha256(...messages);
utils.hmacSha256 = async (key: Uint8Array, ...messages: Uint8Array[]) =>
  Promise.resolve(hmac(key, ...messages));
utils.hmacSha256Sync = (key: Uint8Array, ...messages: Uint8Array[]) => hmac(key, ...messages);

// prettier-ignore
export {
  getPublicKey, sign, signSync, verify,
  recoverPublicKey, getSharedSecret,
  utils, CURVE, Point, Signature, schnorr
};
