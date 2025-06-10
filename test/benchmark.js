import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import mark from 'micro-bmark';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as secp from '../index.js';
const points = readFileSync(join('.', 'test/vectors/points.txt'), 'utf-8')
  .split('\n')
  .filter((a) => a)
  .slice(0, 1000);
(async () => {
  secp.etc.hmacSha256Sync = (k, ...m) => hmac(sha256, k, secp.etc.concatBytes(...m));
  secp.getPublicKey(secp.utils.randomPrivateKey(), true); // warmup
  await mark('getPublicKey(utils.randomPrivateKey())', 10000, () => {
    secp.getPublicKey(secp.utils.randomPrivateKey());
  });
  const priv = 'f6fc7fd5acaf8603709160d203253d5cd17daa307483877ad811ec8411df56d2';
  const pub = secp.getPublicKey(priv, true);
  const priv2 = '2e63f49054e1e44ccc2e6ef6ce387936efb16158f89cc302a2426e0b7fd66f66';
  const pub2 = secp.getPublicKey(priv2, true);
  const msg = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
  const signature = await secp.signAsync(msg, priv);
  await mark('signAsync', 8000, async () => secp.signAsync(msg, priv));
  await mark('sign', 8000, async () => secp.sign(msg, priv));
  await mark('verify', 1000, () => secp.verify(signature, msg, pub));
  await mark('getSharedSecret', 1000, () => secp.getSharedSecret(priv, pub2));
  await mark('recoverPublicKey', 1000, () => signature.recoverPublicKey(msg));
  let i = 0;
  let len = points.length;
  await mark('Point.fromHex (decompression)', 10000, () =>
    secp.ProjectivePoint.fromHex(points[i++ % len])
  );
})();
