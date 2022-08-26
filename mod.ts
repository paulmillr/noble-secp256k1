// prettier-ignore
import {
  CURVE, Point, Signature,
  getPublicKey, sign, signSync, verify, recoverPublicKey, getSharedSecret,
  schnorr, utils,
} from './index.ts';
import { HmacSha256 } from 'https://deno.land/std@0.153.0/hash/sha256.ts';
import { crypto } from 'https://deno.land/std@0.153.0/crypto/mod.ts';

utils.sha256 = async (...msgs: Uint8Array[]): Promise<Uint8Array> => {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', utils.concatBytes(...msgs)));
};
utils.sha256Sync = (...msgs: Uint8Array[]): Uint8Array => {
  return new Uint8Array(crypto.subtle.digestSync('SHA-256', utils.concatBytes(...msgs)));
};

function hmac(key: Uint8Array, ...messages: Uint8Array[]): Uint8Array {
  const sha = new HmacSha256(key);
  for (let msg of messages) sha.update(msg);
  return new Uint8Array(sha.arrayBuffer());
}

utils.hmacSha256 = async (key: Uint8Array, ...messages: Uint8Array[]) =>
  Promise.resolve(hmac(key, ...messages));
utils.hmacSha256Sync = (key: Uint8Array, ...messages: Uint8Array[]) => hmac(key, ...messages);

// prettier-ignore
export {
  CURVE, Point, Signature,
  getPublicKey, sign, signSync, verify, recoverPublicKey, getSharedSecret,
  schnorr, utils,
};
