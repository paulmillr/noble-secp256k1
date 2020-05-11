const {run, mark, logMem} = require('micro-bmark');
const secp = require('..');

// run([4, 8, 16], async (windowSize) => {
run(async (windowSize) => {
  const samples = 1000;
  //console.log(`-------\nBenchmarking window=${windowSize} samples=${samples}...`);
  await mark(() => {
    secp.utils.precompute(windowSize);
  });

  logMem();
  console.log();

  let pub;
  let priv;

  priv = '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffcfcb';
  await mark('getPublicKey 256 bit', samples * 10, () => {
    pub = secp.getPublicKey(priv);
  });

  priv = '0000000000000000000000000000000000000000000000000000000000000003';
  await mark('getPublicKey 1 bit', samples * 10, () => {
    pub = secp.getPublicKey(priv);
  });

  await mark('getPublicKey(utils.randomPrivateKey())', samples, () => {
    pub = secp.getPublicKey(secp.utils.randomPrivateKey());
  });

  const hex = '02cc734b5c09322e61a8f0762af66da3143ab06319d87a73063c1bca6f7719f0ce';
  const msg = 'deadbeefdeadbeefdeadbeefdeadbeef';
  await mark('sign', samples, async () => {
    await secp.sign(msg, priv);
  });

  let signed = await secp.sign(msg, priv);
  await mark('verify', samples, () => {
    secp.verify(signed, msg, pub);
  });

  let [sig, reco] = await secp.sign(msg, priv, { canonical: true, recovered: true });
  await mark('recoverPublicKey', samples, () => {
    secp.recoverPublicKey(msg, sig, reco);
  });

  const pubKey = secp.Point.fromHex(hex);
  await mark('getSharedSecret aka ecdh', samples, () => {
    secp.getSharedSecret(priv, hex);
  });

  const pubKeyPre = secp.utils.precompute(windowSize, pubKey);
  await mark('getSharedSecret (precomputed)', samples, () => {
    secp.getSharedSecret(priv, pubKeyPre);
  });

  console.log();
  logMem();
});
