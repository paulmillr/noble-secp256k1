let secp = require('.');

function time() {
  return process.hrtime.bigint();
}

function logMem() {
  const vals = Object.entries(process.memoryUsage()).map(([k, v]) => {
    return `${k}=${`${(v / 1e6).toFixed(1)}M`.padEnd(7)}`;
  });
  // console.log('RAM:', ...vals);
}

async function bench(label, samples, callback) {
  let initial = false;
  if (typeof label === 'function' && !samples && !callback) {
    callback = label;
    samples = 1;
    label = 'Initialized in';
    initial = true;
  }
  const [μs, ms, sec] = [1000n, 1000000n, 1000000000n];
  const start = time();
  for (let i = 0; i < samples; i++) {
    let val = callback();
    if (val instanceof Promise) await val;
  }
  const end = time();
  const total = end - start;
  const perItem = total / BigInt(samples);

  let perItemStr = perItem.toString();
  let symbol = 'ns';
  if (perItem > μs) {
    symbol = 'μs';
    perItemStr = (perItem / μs).toString();
  }
  if (perItem > ms) {
    symbol = 'ms';
    perItemStr = (perItem / ms).toString();
  }

  const perSec = (sec / perItem).toString();
  let str = `${label} `;
  if (!initial) {
    str += `x ${perSec} ops/sec @ ${perItemStr}${symbol}/op`;
  } else {
    str += `${perItemStr}${symbol}`;
  }
  console.log(str);
}

async function runAll(windowSize=4, samples=1000) {
  console.log(`-------\nBenchmarking window=${windowSize} samples=${samples}...`);
  await bench(() => {
    secp.utils.precompute(windowSize);
  });

  logMem();
  console.log();

  let pub;
  await bench('getPublicKey 1 bit', samples, () => {
    pub = secp.getPublicKey(2n);
  });

  // console.profile('cpu');
  const priv = 2n ** 255n + 12341n;
  await bench('getPublicKey', samples, () => {
    pub = secp.getPublicKey(priv);
  });

  const hex = '02cc734b5c09322e61a8f0762af66da3143ab06319d87a73063c1bca6f7719f0ce';
  const msg = 'deadbeefdeadbeefdeadbeefdeadbeef';
  await bench('sign', samples, async () => {
    await secp.sign(msg, priv, { canonical: true });
  });

  let signed = await secp.sign(msg, priv, { canonical: true });
  await bench('verify', samples, () => {
    secp.verify(signed, msg, pub);
  });

  let [sig, reco] = await secp.sign(msg, priv, { canonical: true, recovered: true });
  await bench('recoverPublicKey', samples, () => {
    secp.recoverPublicKey(msg, sig, reco);
  });

  const pubKey = secp.Point.fromHex(hex);
  await bench('getSharedSecret aka ecdh', samples, () => {
    secp.getSharedSecret(priv, pubKey);
  });

  const pubKeyPre = secp.utils.precompute(windowSize, pubKey);
  await bench('getSharedSecret (precomputed)', samples, () => {
    secp.getSharedSecret(priv, pubKeyPre);
  });

  console.log();
  logMem();
}

runAll(4).then(() => runAll(8)).then(() => runAll(16));
