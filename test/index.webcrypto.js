import { should } from 'micro-should';
import './basic.test.js';
import './secp256k1.test.js';

// A copy of index.js with polyfilled globalThis.crypto to run on Node.js 18
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

should.run();
