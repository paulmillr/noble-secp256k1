import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import mark from 'micro-bmark';
import * as curve from '../index.ts';

(async () => {
  curve.hashes.sha256 = sha256;
  curve.hashes.hmacSha256 = (k, m) => hmac(sha256, k, m);
  let keys, bobKeys, sig, sigr;
  const msg = new TextEncoder().encode('hello noble');
  await mark('init', 1, () => {
    keys = curve.keygen();
    bobKeys = curve.keygen();
    sig = curve.sign(msg, keys.secretKey);
    sigr = curve.sign(msg, keys.secretKey, { format: 'recovered' });
  });
  await mark('keygen', () => curve.keygen());
  await mark('sign', () => curve.sign(msg, keys.secretKey));
  await mark('verify', () => curve.verify(sig, msg, keys.publicKey));
  await mark('getSharedSecret', () => curve.getSharedSecret(keys.secretKey, bobKeys.publicKey));
  await mark('recoverPublicKey', () => curve.recoverPublicKey(sigr, msg));

  console.log();
  await mark('signAsync', () => curve.signAsync(msg, keys.secretKey));
  await mark('verifyAsync', () => curve.verifyAsync(sig, msg, keys.publicKey));

  console.log();
  await mark('Point.fromBytes', () => curve.Point.fromBytes(keys.publicKey));
})();
