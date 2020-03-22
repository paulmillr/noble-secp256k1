const secp = require('.');

function bench(name, counts, callback) {
  const label = `${name} x${counts}`;
  console.time(label);
  for (let i = 0; i < counts; i++) {
    callback();
  }
  console.timeEnd(label);
}

// warm-up
secp.getPublicKey('beef');

bench('getPublicKey 1 bit', 100, () => {
  secp.getPublicKey('01');
});

bench('getPublicKey 256 bit', 100, () => {
  secp.getPublicKey('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
});
