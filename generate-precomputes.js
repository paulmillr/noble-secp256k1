// Optional file that allows to generate precomputes
// Not included in NPM distribution to simplify code.
// Precomputes are initially computed powers of two (2^120, 2^121 etc)
// Which are used to speed-up calculations of elliptic curve cryptography.
const fs = require("fs");
const path = require("path");
const { GG, multiple } = require("./index");

let precomputeContent = `import { Point } from "./point";
export default [`

for (let i = 0; i < 257; i++) {
  const multiplier = 2n ** BigInt(i);
  const result = multiple(GG, multiplier);
  precomputeContent = `${precomputeContent}
  new Point(
    ${result.x}n,
    ${result.y}n,
  ),`
}

precomputeContent += "\n];";

fs.writeFileSync(path.join(__dirname, "./precomputed.ts"), precomputeContent);
