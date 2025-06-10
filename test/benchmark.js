import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import mark from 'micro-bmark';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as secp from '../index.js';
const bytes = secp.etc.hexToBytes;
const points = readFileSync(join('.', 'test/vectors/points.txt'), 'utf-8')
  .split('\n')
  .filter((a) => a)
  .slice(0, 1000)
  .map(ph => bytes(ph));
(async () => {
  secp.hashes.hmacSha256 = (k, ...m) => hmac(sha256, k, secp.etc.concatBytes(...m));
  // secp.etc.hmacSha256Sync = (k, ...m) => hmac(sha256, k, secp.etc2.concatBytes(...m));
  secp.getPublicKey(secp.utils.randomPrivateKey(), true); // warmup
  await mark('getPublicKey(utils.randomPrivateKey())', () => {
    secp.getPublicKey(secp.utils.randomPrivateKey());
  });
  const priv = bytes('f6fc7fd5acaf8603709160d203253d5cd17daa307483877ad811ec8411df56d2');
  const pub = secp.getPublicKey(priv, true);
  const priv2 = bytes('2e63f49054e1e44ccc2e6ef6ce387936efb16158f89cc302a2426e0b7fd66f66');
  const pub2 = secp.getPublicKey(priv2, true);
  const msg = bytes('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef');
  const signature = await secp.signAsync(msg, priv);
  await mark('signAsync', async () => secp.signAsync(msg, priv));
  await mark('sign', async () => secp.sign(msg, priv));
  await mark('verify', () => secp.verify(signature, msg, pub));
  await mark('getSharedSecret', () => secp.getSharedSecret(priv, pub2));
  // await mark('recoverPublicKey', () => signature.recoverPublicKey(msg));
  let i = 0;
  let len = points.length;
  await mark('Point.fromHex (decompression)', () => secp.Point.fromBytes(points[i++ % len]));
  if (secp.schnorr) {
    secp.hashes.sha256 = sha256;
    const pubs = secp.schnorr.getPublicKey(priv);
    const signed = secp.schnorr.sign(msg, priv);
    await mark('schnorr.sign', () => secp.schnorr.sign(msg, priv));
    await mark('schnorr.verify', () => secp.schnorr.verify(signed, msg, pubs));
  }
})();
