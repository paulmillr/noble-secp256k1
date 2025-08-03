import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import mark from 'micro-bmark';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as secp from '../index.ts';

const { hexToBytes } = secp.etc;
const points = readFileSync(join('.', 'test/vectors/points.txt'), 'utf-8')
  .split('\n')
  .filter((a) => a)
  .slice(0, 1000)
  .map(ps => hexToBytes(ps));
(async () => {
  secp.hashes.sha256 = sha256;
  secp.hashes.hmacSha256 = (k, m) => hmac(sha256, k, m);
  secp.getPublicKey(secp.utils.randomSecretKey(), true); // warmup
  await mark('getPublicKey', () => {
    secp.getPublicKey(secp.utils.randomSecretKey());
  });
  const priv = hexToBytes('f6fc7fd5acaf8603709160d203253d5cd17daa307483877ad811ec8411df56d2');
  const pub = secp.getPublicKey(priv, true);
  const priv2 = hexToBytes('2e63f49054e1e44ccc2e6ef6ce387936efb16158f89cc302a2426e0b7fd66f66');
  const pub2 = secp.getPublicKey(priv2, true);
  const msg = hexToBytes('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef');
  const signature = await secp.signAsync(msg, priv);
  const signatureRec = await secp.signAsync(msg, priv, { format: 'recovered' });
  await mark('sign', async () => secp.sign(msg, priv));
  await mark('verify', () => secp.verify(signature, msg, pub));
  await mark('getSharedSecret', () => secp.getSharedSecret(priv, pub2));
  await mark('recoverPublicKey', () => secp.recoverPublicKey(signatureRec, msg));

  console.log();
  await mark('signAsync', async () => secp.signAsync(msg, priv));
  await mark('verifyAsync', async () => secp.verifyAsync(signature, msg, pub));

  console.log();
  let i = 0;
  let len = points.length;
  await mark('Point.fromBytes', 10000, () =>
    secp.Point.fromBytes(points[i++ % len])
  );
})();
