const { run, mark, logMem } = require('micro-bmark');
const secp = require('..');
const { join } = require('path');
const points = require('fs')
  .readFileSync(join(__dirname, './vectors/points.txt'), 'utf-8')
  .split('\n')
  .filter((a) => a)
  .slice(0, 1000);
run(async () => {
  await mark('getPublicKey(utils.randomPrivateKey())', 500, () => {
    secp.getPublicKey(secp.utils.randomPrivateKey(), true);
  });
  const priv = 'f6fc7fd5acaf8603709160d203253d5cd17daa307483877ad811ec8411df56d2';
  const pub = secp.getPublicKey(priv, true);
  const priv2 = '2e63f49054e1e44ccc2e6ef6ce387936efb16158f89cc302a2426e0b7fd66f66';
  const pub2 = secp.getPublicKey(priv2, true);
  const msg = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
  const signature = await secp.sign(msg, priv);
  await mark('sign', 500, async () => secp.sign(msg, priv));
  await mark('verify', 200, () => secp.verify(signature, msg, pub));
  await mark('getSharedSecret', 500, () => secp.getSharedSecret(priv, pub2));
  let i = 0;
  let len = points.length;
  await mark('Point.fromHex (decompression)', 10000, () => secp.Point.fromHex(points[i++ % len]));
});
