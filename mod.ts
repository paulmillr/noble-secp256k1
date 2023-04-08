// prettier-ignore
import {
  CURVE, ProjectivePoint, Signature,
  getPublicKey, sign, signAsync, verify, getSharedSecret,
  utils, etc,
} from './index.ts';
import { hmac } from 'npm:@noble/hashes@1.2.0/hmac';
import { sha256 } from 'npm:@noble/hashes@1.2.0/sha256';
import { crypto } from 'https://deno.land/std@0.175.0/crypto/mod.ts';

utils.sha256 = async (...msgs: Uint8Array[]): Promise<Uint8Array> => {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', utils.concatBytes(...msgs)));
};
utils.sha256Sync = (...msgs: Uint8Array[]): Uint8Array => {
  return new Uint8Array(crypto.subtle.digestSync('SHA-256', utils.concatBytes(...msgs)));
};

utils.hmacSha256Sync = function hmac(key: Uint8Array, ...messages: Uint8Array[]): Uint8Array {
  return hmac(sha256, key, ...messages);
}

// prettier-ignore
export {
  CURVE, ProjectivePoint, Signature,
  getPublicKey, sign, signAsync, verify, getSharedSecret,
  utils, etc,
};
