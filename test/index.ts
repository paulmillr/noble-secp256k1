import { should } from '@paulmillr/jsbt/test.js';
import './point.test.ts';
import './secp256k1.test.ts';
import './utils.test.ts';

if (!globalThis.crypto) {
  console.error('global crypto not found (old Node.js?), perhaps you meant to run test:webcrypto');
}

should.runWhen(import.meta.url);
