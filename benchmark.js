let secp;

function logMem(i) {
  const vals = Object.entries(process.memoryUsage()).map(([k, v]) => {
    return `${k}=${(`${(v / 1e6).toFixed(1)}M`).padEnd(7)}`;
  });
  console.log(String(i).padStart(6), ...vals);
}

bench('load', 1, () => {
  secp = require('.');
});

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
pub = secp.getPublicKey('beef');

logMem('start');
bench('getPublicKey 1 bit', 100, () => {
  pub = secp.getPublicKey('01');
});

// console.profile('cpu');
bench('getPublicKey 256 bit', 100, () => {
  pub = secp.getPublicKey('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
});

let custom = secp.Point.fromHex(pub);
bench('getPublicKey 256 bit', 100, () => {
  pub = custom.multiply(0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefn);
});
logMem('end');
// console.profileEnd('cpu');
