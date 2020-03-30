const {run, mark, logMem} = require('micro-bmark');
const secp = require('.');

run([4, 8, 16], async (windowSize) => {
  const samples = 1000;
  //console.log(`-------\nBenchmarking window=${windowSize} samples=${samples}...`);
  await mark(() => {
    secp.utils.precompute(windowSize);
  });

  logMem();
  console.log();

  let pub;
  await mark('getPublicKey 1 bit', samples, () => {
    pub = secp.getPublicKey(2n);
  });

  // console.profile('cpu');
  const priv = 2n ** 255n + 12341n;
  await mark('getPublicKey', samples, () => {
    pub = secp.getPublicKey(priv);
  });

  const hex = '02cc734b5c09322e61a8f0762af66da3143ab06319d87a73063c1bca6f7719f0ce';
  const msg = 'deadbeefdeadbeefdeadbeefdeadbeef';
  await mark('sign', samples, async () => {
    await secp.sign(msg, priv, { canonical: true });
  });

  let signed = await secp.sign(msg, priv, { canonical: true });
  await mark('verify', samples, () => {
    secp.verify(signed, msg, pub);
  });

  let [sig, reco] = await secp.sign(msg, priv, { canonical: true, recovered: true });
  await mark('recoverPublicKey', samples, () => {
    secp.recoverPublicKey(msg, sig, reco);
  });

  const pubKey = secp.Point.fromHex(hex);
  await mark('getSharedSecret aka ecdh', samples, () => {
    secp.getSharedSecret(priv, pubKey);
  });

  const pubKeyPre = secp.utils.precompute(windowSize, pubKey);
  await mark('getSharedSecret (precomputed)', samples, () => {
    secp.getSharedSecret(priv, pubKeyPre);
  });

  await mark('generateRandomPrivateKey', samples, () => {
    secp.utils.generateRandomPrivateKey();
  });

  console.log();
  logMem();
});
