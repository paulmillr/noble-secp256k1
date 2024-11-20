import { deepStrictEqual, throws } from 'assert';
import { describe, should } from 'micro-should';
import * as secp256k1 from '../index.js';

const { bytesToHex, hexToBytes } = secp256k1.etc;

// Everything except undefined, string, Uint8Array
const TYPE_TEST_BASE = [
  null,
  [1, 2, 3],
  { a: 1, b: 2, c: 3 },
  NaN,
  0.1234,
  1.0000000000001,
  10e9999,
  new Uint32Array([1, 2, 3]),
  100n,
  new Set([1, 2, 3]),
  new Map([['aa', 'bb']]),
  new Uint8ClampedArray([1, 2, 3]),
  new Int16Array([1, 2, 3]),
  new Float32Array([1]),
  new BigInt64Array([1n, 2n, 3n]),
  new ArrayBuffer(100),
  new DataView(new ArrayBuffer(100)),
  { constructor: { name: 'Uint8Array' }, length: '1e30' },
  () => {},
  async () => {},
  class Test {},
  Symbol.for('a'),
  new Proxy(new Uint8Array(), {})
];

const TYPE_TEST_OPT = [
  '',
  new Uint8Array(),
  new (class Test {})(),
  class Test {},
  () => {},
  0,
  0.1234,
  NaN,
  null,
];

const TYPE_TEST_NOT_BOOL = [false, true];
const TYPE_TEST_NOT_BYTES = ['', 'test', '1', new Uint8Array([]), new Uint8Array([1, 2, 3])];
const TYPE_TEST_NOT_HEX = [
  ' 1 2 3 4 5',
  '010203040x',
  'abcdefgh',
  '1 2 3 4 5 ',
  'bee',
  new String('1234'),
];
const TYPE_TEST_NOT_INT = [-0.0, 0, 1];

const TYPE_TEST = {
  bytes: TYPE_TEST_BASE.concat(TYPE_TEST_NOT_INT, TYPE_TEST_NOT_BOOL),
  hex: TYPE_TEST_BASE.concat(TYPE_TEST_NOT_INT, TYPE_TEST_NOT_BOOL, TYPE_TEST_NOT_HEX),
};

describe('utils', () => {
  const staticHexVectors = [
    { bytes: Uint8Array.from([]), hex: '' },
    { bytes: Uint8Array.from([0xbe]), hex: 'be' },
    { bytes: Uint8Array.from([0xca, 0xfe]), hex: 'cafe' },
    { bytes: Uint8Array.from(new Array(1024).fill(0x69)), hex: '69'.repeat(1024) },
  ];
  should('hexToBytes', () => {
    for (let v of staticHexVectors) deepStrictEqual(hexToBytes(v.hex), v.bytes);
    for (let v of TYPE_TEST.hex) {
      throws(() => hexToBytes(v));
    }
  });
  should('bytesToHex', () => {
    for (let v of staticHexVectors) deepStrictEqual(bytesToHex(v.bytes), v.hex);
    for (let v of TYPE_TEST.bytes) {
      throws(() => bytesToHex(v));
    }
  });
});

should.run();
