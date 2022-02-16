import resolve from '@rollup/plugin-node-resolve';

export default {
  input: 'lib/esm/index.js',
  output: {
    file: 'build/noble-secp256k1.js',
    format: 'umd',
    name: 'nobleSecp256k1',
    exports: 'named',
    preferConst: true,
  },
  plugins: [resolve({ browser: true })],
};
