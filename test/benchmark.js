import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;
import { run, mark } from 'micro-bmark';
import * as secp from '../index.js';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
const points = readFileSync(join('.', 'test/vectors/points.txt'), 'utf-8')
  .split('\n')
  .filter((a) => a)
  .slice(0, 1000);
run(async () => {
  secp.getPublicKey(secp.utils.randomPrivateKey(), true); // warmup
  await mark('getPublicKey(utils.randomPrivateKey())', 5000, () => {
    secp.getPublicKey(secp.utils.randomPrivateKey(), true);
  });
  const priv = 'f6fc7fd5acaf8603709160d203253d5cd17daa307483877ad811ec8411df56d2';
  const pub = secp.getPublicKey(priv, true);
  const priv2 = '2e63f49054e1e44ccc2e6ef6ce387936efb16158f89cc302a2426e0b7fd66f66';
  const pub2 = secp.getPublicKey(priv2, true);
  const msg = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
  const signature = await secp.signAsync(msg, priv);
  await mark('sign', 4000, async () => secp.signAsync(msg, priv));
  await mark('verify', 500, () => secp.verify(signature, msg, pub));
  await mark('getSharedSecret', 500, () => secp.getSharedSecret(priv, pub2));
  await mark('recoverPublicKey', 500, () => signature.recoverPublicKey(msg));
  let i = 0;
  let len = points.length;
  await mark('Point.fromHex (decompression)', 10000, () => secp.ProjectivePoint.fromHex(points[i++ % len]));
});
