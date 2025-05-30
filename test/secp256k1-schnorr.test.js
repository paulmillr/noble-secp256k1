import { hexToBytes as bytes, bytesToHex as hex } from '@noble/hashes/utils.js';
import { describe, should } from 'micro-should';
import { deepStrictEqual as eql } from 'node:assert';
import { readFileSync } from 'node:fs';
import { schnorr } from '../index.js';
import './secp256k1.helpers.js';
const schCsv = readFileSync('./test/vectors/secp256k1/schnorr.csv', 'utf-8');

// h;
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
        eql(hex(schnorr.getPublicKey(bytes(sec))), pub.toLowerCase());
        const sig = schnorr.sign(bytes(msg), bytes(sec), bytes(rnd));
        eql(hex(sig), expSig.toLowerCase());
        eql(schnorr.verify(sig, bytes(msg), bytes(pub)), true);
      } else {
        const passed = schnorr.verify(bytes(expSig), bytes(msg), bytes(pub));
        eql(passed, passes === 'TRUE');
      }
    });
  }
});

should.runWhen(import.meta.url);
