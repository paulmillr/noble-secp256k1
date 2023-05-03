import { webcrypto } from 'node:crypto';
// @ts-ignore
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import './secp256k1.test.js';

// Force ESM import to execute
import { should } from 'micro-should';
should.run();
