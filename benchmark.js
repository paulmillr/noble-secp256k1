let secp;

function time() {
  return process.hrtime.bigint();
}

function logMem() {
  const vals = Object.entries(process.memoryUsage()).map(([k, v]) => {
    return `${k}=${`${(v / 1e6).toFixed(1)}M`.padEnd(7)}`;
  });
  console.log('RAM:', ...vals);
}

async function bench(label, samples, callback) {
  const [μs, ms, sec] = [1000n, 1000000n, 1000000000n];
  // if (counts > 1) label += ` x${counts}`;
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
  console.log(`${label} x ${perSec} ops/sec, ${perItemStr}${symbol} / op, ${samples} samples`);
}

(async () => {
  // warm-up
  let pub;
  console.log('Benchmarking...\n');
  await bench('load', 1, () => {
    secp = require('.');
    secp.utils.precompute(4);
  });

  logMem('start');
  console.log();

  await bench('getPublicKey 1 bit', 100, () => {
    pub = secp.getPublicKey(2n);
  });

  // console.profile('cpu');
  const priv = 2n ** 255n + 12341n;
  await bench('getPublicKey 256 bit', 100, () => {
    pub = secp.getPublicKey(priv);
  });

  await bench('sign', 100, async () => {
    const s = Date.now();
    const full = await secp.sign('beef', 4321n, { canonical: true });
  });

  let custom = secp.Point.fromHex(pub);
  await bench('multiply custom point', 100, () => {
    pub = custom.multiply(0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefn);
  });

  console.log();
  logMem();
})();
