import { should } from 'micro-should';
import './basic.test.js';
import './secp256k1-schnorr.test.js';
import './secp256k1.test.js';
import './utils.test.js';

if (!globalThis.crypto) {
  console.error('global crypto not found (old Node.js?), perhaps you meant to run test:webcrypto');
}

should.runWhen(import.meta.url);
