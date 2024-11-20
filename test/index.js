import { should } from 'micro-should';
import './basic.test.js';
import './secp256k1.test.js';
import * as t3 from './utils.test.js';

if (!globalThis.crypto) {
  console.error('global crypto not found (old Node.js?), perhaps you meant to run test:webcrypto');
}

should.run();
