import { hexToBytes as bytes, bytesToHex as hex } from '@noble/hashes/utils';
import { describe, should } from 'micro-should';
import { deepStrictEqual } from 'node:assert';
import { readFileSync } from 'node:fs';
import { schnorr } from '../index.js';
import {
  secp
} from './secp256k1.helpers.js';
const schCsv = readFileSync('./test/vectors/secp256k1/schnorr.csv', 'utf-8');
secp;
describe('schnorr.sign()', () => {
  // index,secret key,public key,aux_rand,message,signature,verification result,comment
  const vectors = schCsv
    .split('\n')
    .map((line) => line.split(','))
    .slice(1, -1);
  for (let vec of vectors) {
    const [index, sec, pub, rnd, msg, expSig, passes, comment] = vec;
    should(`${comment || 'vector ' + index}`, () => {
      if (sec) {
        deepStrictEqual(hex(schnorr.getPublicKey(sec)), pub.toLowerCase());
        const sig = schnorr.sign(bytes(msg), bytes(sec), bytes(rnd));
        deepStrictEqual(hex(sig), expSig.toLowerCase());
        deepStrictEqual(schnorr.verify(sig, bytes(msg), bytes(pub)), true);
      } else {
        const passed = schnorr.verify(bytes(expSig), bytes(msg), bytes(pub));
        deepStrictEqual(passed, passes === 'TRUE');
      }
    });

    should(`${comment || 'vector ' + index} async`, async () => {
      if (sec) {
        deepStrictEqual(hex(schnorr.getPublicKey(sec)), pub.toLowerCase());
        const sig = await schnorr.signAsync(bytes(msg), bytes(sec), bytes(rnd));
        deepStrictEqual(hex(sig), expSig.toLowerCase());
        deepStrictEqual(await schnorr.verifyAsync(sig, bytes(msg), bytes(pub)), true);
      } else {
        const passed = await schnorr.verifyAsync(bytes(expSig), bytes(msg), bytes(pub));
        deepStrictEqual(passed, passes === 'TRUE');
      }
    });
  }
});

should.runWhen(import.meta.url);
