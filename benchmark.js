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

bench('getPublicKey 1 bit', 1, () => {
  secp.getPublicKey('01');
});

console.profile('cpu');
bench('getPublicKey 256 bit', 1, () => {
  secp.getPublicKey('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
});
console.profileEnd('cpu');
