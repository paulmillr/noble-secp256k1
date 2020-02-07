const secp = require('.');

// warm-up
secp.getPublicKey('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');

console.time('getPublicKey 256 bit');
secp.getPublicKey('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
console.timeEnd('getPublicKey 256 bit');

console.time('getPublicKey 1 bit');
secp.getPublicKey(1n);
console.timeEnd('getPublicKey 1 bit');

console.log(secp.getPublicKey(0, true));
console.log(secp.getPublicKey(1, true));
console.log(secp.getPublicKey(6, true));
// Uint8Array(33) [
//   2, 0, 0, 0, 0, 0, 0, 0, 0,
//   0, 0, 0, 0, 0, 0, 0, 0, 0,
//   0, 0, 0, 0, 0, 0, 0, 0, 0,
//   0, 0, 0, 0, 0, 0
// ]
// Uint8Array(33) [
//     2, 121, 190, 102, 126, 249, 220, 187,
//   172,  85, 160,  98, 149, 206, 135,  11,
//     7,   2, 155, 252, 219,  45, 206,  40,
//   217,  89, 242, 129,  91,  22, 248,  23,
//   152
// ]
// Uint8Array(33) [
//     3, 255, 249, 123, 213, 117,  94, 238,
//   164,  32,  69,  58,  20,  53,  82,  53,
//   211, 130, 246,  71,  47, 133, 104, 161,
//   139,  47,   5, 122,  20,  96,  41, 117,
//    86
// ]
