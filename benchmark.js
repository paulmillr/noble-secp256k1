let secp;

function logMem(i) {
  const vals = Object.entries(process.memoryUsage()).map(([k, v]) => {
    return `${k}=${(`${(v / 1e6).toFixed(1)}M`).padEnd(7)}`;
  });
  console.log(String(i).padStart(6), ...vals);
}

function bench(name, counts, callback) {
  const label = `${name} x${counts}`;
  console.time(label);
  for (let i = 0; i < counts; i++) {
    callback();
  }
  console.timeEnd(label);
}

// warm-up
let pub;
console.log('Starting');
bench('load', 1, () => {
  secp = require('.');
  pub = secp.getPublicKey('beef');
});

logMem('start');
bench('getPublicKey 1 bit', 1, () => {
  pub = secp.getPublicKey(2n);
});

// console.profile('cpu');
const priv = 2n ** 255n + 12341n;
bench('getPublicKey 256 bit', 1, () => {
  pub = secp.getPublicKey(priv);
});

let custom = secp.Point.fromHex(pub);
bench('multiply custom point', 1, () => {
  pub = custom.multiply(0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefn);
});

secp.Point.adds = 0;
// secp.getPublicKey('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
console.log('adds', secp.Point.adds);

logMem('end');
// console.profileEnd('cpu');
