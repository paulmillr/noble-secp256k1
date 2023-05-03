import { webcrypto } from 'node:crypto';
// @ts-ignore
globalThis.crypto = webcrypto;

import './secp256k1.test.js';

// Force ESM import to execute
import { should } from 'micro-should';
should.run();
