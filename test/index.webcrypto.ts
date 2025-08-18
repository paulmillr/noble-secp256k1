import { should } from '@paulmillr/jsbt/test.js';
import './basic.test.js';
import './secp256k1.test.js';
import './utils.test.js';

// A copy of index.js with polyfilled globalThis.crypto to run on Node.js 18
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

should.runWhen(import.meta.url);
