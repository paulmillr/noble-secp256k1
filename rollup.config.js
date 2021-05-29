import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

export default {
  input: 'index.js',
  output: {
    file: 'build/noble-secp256k1.js',
    format: 'umd',
    name: 'nobleSecp256k1',
    exports: 'named',
    preferConst: true,
  },
  plugins: [resolve(), commonjs()],
};
