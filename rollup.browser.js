import resolve from '@rollup/plugin-node-resolve';

export default {
  input: 'lib/esm/index.js',
  output: {
    file: 'lib/browser/index.js',
    format: 'cjs',
  },
  plugins: [resolve({ browser: true })],
};
