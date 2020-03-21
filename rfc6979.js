const ecdsa = require('./vectors/ecdsa.json');
const privates = require('./vectors/privates.json');
const points = require('./vectors/points.json');

const fs = require('fs');
const secp256k1 = require('.');
let sha256;
const req = require;
const { createHash } = req("crypto");
sha256 = async (message) => {
  const hash = createHash("sha256");
  hash.update(message);
  return Uint8Array.from(hash.digest());
};
function arrayToHex(uint8a) {
  return Array.from(uint8a)
    .map(c => c.toString(16).padStart(2, "0"))
    .join("");
}
function h(msg) {
  return sha256(new TextEncoder().encode(msg));
}


(async () => {
  // for (const vector of vectors) {
  //   let [key, msg, expected] = vector;
  //   key = BigInt(key);
  //   expected = expected.toLowerCase();
  //   const msgh = await h(msg);
  //   const signed = await secp256k1.sign(msgh, key);
  //   const signature = arrayToHex(signed);
  //   const matches = signature === expected;
  //   console.log({
  //     msg, msgh, key, signature, expected, matches
  //   });
  // }
  // for (const vector of vectors2) {
  // const {message, d, k0, k1, k15} = vector;
  // const msgh = await h(message);
  // const key = BigInt('0x' + d);
  // const signature = arrayToHex(await secp256k1.sign(msgh, key));
  // console.log(vector, signature);
  // }

  // for (const vector of privates.valid.isPrivate) {
  //   const {d, expected, description} = vector;
  //   try {
  //     const pub = secp256k1.getPublicKey(d);
  //     // console.log(d, pub);
  //     if (!expected) {
  //       console.log('FAIL: allows', description, d);
  //     }
  //   } catch (error) {
  //     if (expected) {
  //       console.log('Invalid vector', d, error);
  //     } else {
  //       console.log('PASS: Does not allow', description, d);
  //     }
  //   }
  // }

  // for (const vector of points.valid.isPoint) {
  //   const {P, expected, description} = vector;
  //   if (expected) {
  //     try {
  //       let point = secp256k1.Point.fromHex(P);
  //     } catch (error) {
  //       console.log('error', P, error);
  //     }
  //   } else {
  //     let err;
  //     try {
  //       let point = secp256k1.Point.fromHex(P);
  //     } catch (error) { err = error; }
  //     if (!err) console.log('Expected error: ', description)
  //   }
  // }

  for (const vector of [1]) {
    const {P, Q, expected, description} =       {
      "description": "1 + -1 == 0/Infinity",
      "P": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "Q": "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "expected": null
    };
    if (expected) {
      try {
        let p = secp256k1.Point.fromHex(P);
        let q = secp256k1.Point.fromHex(Q);
        let actual = p.add(q).toHex(true);
        if (actual !== expected) console.log('addition failed', {P, Q, actual, expected});
      } catch (error) {
        console.log('error', P, error);
      }
    } else {
      let err;
      try {
        let p = secp256k1.Point.fromHex(P);
        let q = secp256k1.Point.fromHex(Q);
        let actual = p.add(q).toHex(true);
        if (actual !== expected) console.log('addition failed', {P, Q, actual, expected});
      } catch (error) { err = error; }
      if (!err) console.log('Expected error: ', P, Q, expected, description)
    }
  }

  // for (const vector of ecdsa.valid)) {
  //   // const msgh = await h(vector.)
  //   const actual = await secp256k1.sign(vector.m, vector.d, {canonical: true});
  //   console.log({actual: actual.slice(10), expected: vector.signature});
  // }
})();
