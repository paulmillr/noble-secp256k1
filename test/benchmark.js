const { run, mark, logMem } = require('micro-bmark');
const secp = require('..');
const { join } = require('path');
const points = require('fs')
  .readFileSync(join(__dirname, './vectors/points.txt'), 'utf-8')
  .split('\n')
  .filter((a) => a)
  .slice(0, 1000);

// run([4, 8, 16], async (windowSize) => {
run(async (windowSize) => {
  const samples = 1000;
  //console.log(`-------\nBenchmarking window=${windowSize} samples=${samples}...`);
  await mark(() => {
    secp.utils.precompute(windowSize);
  });

  logMem();
  console.log();

  // await mark('getPublicKey 1 bit', samples * 10, () => {
  //   secp.getPublicKey('0000000000000000000000000000000000000000000000000000000000000003');
  // });

  // await mark('getPublicKey 256 bit', samples * 10, () => {
  //   secp.getPublicKey('7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffcfcb');
  // });

  await mark('getPublicKey(utils.randomPrivateKey())', samples * 10, () => {
    secp.getPublicKey(secp.utils.randomPrivateKey());
  });

  const priv = 'f6fc7fd5acaf8603709160d203253d5cd17daa307483877ad811ec8411df56d2';
  const pub = secp.getPublicKey(priv, false);
  const priv2 = '2e63f49054e1e44ccc2e6ef6ce387936efb16158f89cc302a2426e0b7fd66f66';
  const pub2 = secp.getPublicKey(priv2, false);
  const msg = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
  const signature = await secp.sign(msg, priv);
  await mark('sign', samples, async () => {
    await secp.sign(msg, priv);
  });

  await mark('verify', samples, () => {
    secp.verify(signature, msg, pub);
  });

  const [rsig, reco] = await secp.sign(msg, priv, { canonical: true, recovered: true });
  await mark('recoverPublicKey', samples, () => {
    secp.recoverPublicKey(msg, rsig, reco);
  });

  await mark('getSharedSecret aka ecdh', samples, () => {
    secp.getSharedSecret(priv, pub2);
  });

  const pub2Pre = secp.utils.precompute(windowSize, secp.Point.fromHex(pub2));
  await mark('getSharedSecret (precomputed)', samples, () => {
    secp.getSharedSecret(priv, pub2Pre);
  });

  let i = 0;
  await mark('Point.fromHex (decompression)', samples * 2, () => {
    const p = points[i++ % points.length];
    secp.Point.fromHex(p);
  });

  const smsg = '0000000000000000000000000000000000000000000000000000000000000000';
  const spri = '0000000000000000000000000000000000000000000000000000000000000003';
  const spub = secp.Point.fromPrivateKey(spri);
  const ssig = await secp.schnorr.sign(smsg, spri);
  await mark('schnorr.sign', samples, () => secp.schnorr.sign(smsg, spri));
  await mark('schnorr.verify', samples, () => secp.schnorr.verify(ssig, smsg, spub));

  console.log();
  logMem();
});
