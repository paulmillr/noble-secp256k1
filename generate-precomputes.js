// Optional file that allows to generate precomputes
// Not included in NPM distribution to simplify code.
// Precomputes are initially computed powers of two (2^120, 2^121 etc)
// Which are used to speed-up calculations of elliptic curve cryptography.
const {writeFileSync} = require("fs");
const sysPath = require("path");
const { BASE_POINT } = require("./index");

const output = sysPath.join(__dirname, "./precomputed.ts");

let content = `import { Point } from "./point";
export default [`

for (let i = 0; i <= 256; i++) {
  const multiplier = 2n ** BigInt(i);
  const result = BASE_POINT.multiply(multiplier);
  content = `${content}
  new Point(
    ${result.x}n,
    ${result.y}n,
  ),`
}

content += "\n];";

writeFileSync(output, content);
