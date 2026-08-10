/*!MIT(c)paulmillr.com*/
// PART 1: unsafe pub
// secp256k1 curve parameters. Verify using https://www.secg.org/sec2-v2.pdf
const _256 = 2n ** 256n;
const P = _256 - 0x1000003d1n; // curve's field prime
const N = _256 - 0x14551231950b75fc4402da1732fc9bebfn; // curve (group) order
const err = (m: string): never => { throw new Error(m); }; // error helper
const M = (a: bigint, b: bigint = P) => {
  // mod division
  const r = a % b;
  return r >= 0n ? r : b + r; // a % b = r
};
// prettier-ignore
const inv = (num: bigint, md: bigint): bigint => {      // modular inversion
  if (num === 0n || md <= 0n) err('no inverse');        // no neg exponent for now
  let a = M(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
  while (a !== 0n) {                                    // uses euclidean gcd algorithm
    const q = b / a, r = b % a;                         // not constant-time
    const m = x - u * q, n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  return b === 1n ? M(x, md) : err('no inverse');       // b is gcd at this point
};
// Point in 2d affine (x, y) coordinates
interface AffinePoint {
  x: bigint;
  y: bigint;
}
const affine = (x: bigint, y: bigint): AffinePoint => ({ x: x, y: y });
const Point_ZERO = affine(0n, 0n); // Point at infinity aka identity point aka zero
// Checks if a point is on curve: y² = x³ + 7. Zero point is not on curve.
const onCurve = (p: AffinePoint) => M(p.y * p.y - p.x ** 3n - 7n) === 0n;
// Validates a scalar (e.g. private key): must be in range [1, N-1]
const checkScalar = (d: bigint): bigint => (0n < d && d < N ? d : err('invalid scalar'));
// Adds point to other point. https://hyperelliptic.org/EFD/g1p/auto-shortw.html
// Doubling (a == b) uses the tangent-line slope, addition uses the chord-line slope.
const padd = (a: AffinePoint, b: AffinePoint): AffinePoint => {
  const X1 = a.x, Y1 = a.y, X2 = b.x, Y2 = b.y;
  if (X1 === 0n && Y1 === 0n) return b; // 0 + b = b
  if (X2 === 0n && Y2 === 0n) return a; // a + 0 = a
  let lam;
  if (X1 === X2) {
    if (Y1 !== Y2) return Point_ZERO; // opposite points, a + (-a) = 0
    lam = M(3n * X1 * X1 * inv(2n * Y1, P)); // λ = (3x₁² + a) / (2y₁)
  } else {
    lam = M((Y2 - Y1) * inv(X2 - X1, P)); // λ = (y₂ - y₁) / (x₂ - x₁)
  }
  const X3 = M(lam * lam - X1 - X2); // x₃ = λ² - x₁ - x₂
  const Y3 = M(lam * (X1 - X3) - Y1); // y₃ = λ * (x₁ - x₃) - y₁
  return affine(X3, Y3);
};
// Adds point to itself
const pdouble = (a: AffinePoint) => padd(a, a);

/** Generator / base point */
// G x, y values taken from official secp256k1 document: https://www.secg.org/sec2-v2.pdf
const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
const Point_BASE = affine(Gx, Gy);
const mul_unsafe = (q: AffinePoint, n: bigint) => {
  let curr = q;
  let p = Point_ZERO;
  while (n > 0n) {
    if (n & 1n) p = padd(p, curr);
    curr = pdouble(curr);
    n >>= 1n;
  }
  return p;
};
const _getPublicKey = (privateKey: bigint): AffinePoint => {
  return mul_unsafe(Point_BASE, checkScalar(privateKey));
};

// PART 2: unsafe sigs

interface Signature {
  r: bigint;
  s: bigint;
  recovery?: number;
}
// Convert Uint8Array to bigint, big endian
const bytesToNumBE = (bytes: Uint8Array): bigint =>
  bytes.reduce((n, byte) => (n << 8n) | BigInt(byte), 0n);
// Get random k from CSPRNG.
// (rand32 mod N) is naive version
// (rand48 mod N-1)+1 is ours, proper version.
// +16 more bytes are fetched to make modulo bias small.
// (mod N-1)+1 is done to eliminate 0 from output.
const randK = (): bigint => {
  // @ts-ignore
  const b = crypto.getRandomValues(new Uint8Array(48));
  const num = M(bytesToNumBE(b), N - 1n);
  return num + 1n;
};
const _sign = (msgh: Uint8Array, priv: bigint): Signature => {
  const m = bytesToNumBE(msgh);
  const d = checkScalar(priv);
  let r = 0n;
  let s = 0n;
  let q;
  do {
    const k = randK();
    const ik = inv(k, N);
    q = mul_unsafe(Point_BASE, k);
    r = M(q.x, N);
    s = M(ik * M(m + d * r, N), N);
  } while (r === 0n || s === 0n);
  if (s > N >> 1n) {
    s = M(-s, N);
  }
  return { r, s };
};
const _verify = (sig: Signature, msgh: Uint8Array, pub: AffinePoint): boolean => {
  const { r, s } = sig;
  if (r <= 0n || r >= N || s <= 0n || s >= N || !onCurve(pub)) return false;
  const h = M(bytesToNumBE(msgh), N);
  const is = inv(s, N);
  const u1 = M(h * is, N);
  const u2 = M(r * is, N);
  const G_u1 = mul_unsafe(Point_BASE, u1);
  const P_u2 = mul_unsafe(pub, u2);
  const R = padd(G_u1, P_u2);
  if (R.x === 0n && R.y === 0n) return false;
  const v = M(R.x, N);
  return v === r;
};
export { _getPublicKey, _sign, _verify };

// PART 3: safe mul

// Constant Time multiplication
const getPowers = (q: AffinePoint) => {
  let points: AffinePoint[] = [];
  for (let bit = 0, dbl = q; bit <= 256; bit++, dbl = pdouble(dbl)) {
    points.push(dbl);
  }
  return points;
};
const mul_CT_slow = (q: AffinePoint, n: bigint) => {
  const pows = getPowers(q);
  let p = Point_ZERO;
  let f = Point_ZERO; // fake point
  for (let bit = 0; bit <= 256; bit++) {
    const at_bit_i = pows[bit];
    if (n & 1n) p = padd(p, at_bit_i);
    else f = padd(f, at_bit_i);
    n >>= 1n;
  }
  return p;
};

// PART 4: proj mul

const CURVE = { P: P, n: N, a: 0n, b: 7n };
const equals = (a: AffinePoint, b: AffinePoint) => a.x === b.x && a.y === b.y;
// Point in 3d projective (x, y, z) coordinates
class Point {
  px: bigint;
  py: bigint;
  pz: bigint;
  constructor(x: bigint, y: bigint, z: bigint) {
    this.px = x;
    this.py = y;
    this.pz = z;
  }
  /** Create 3d xyz point from 2d xy. Edge case: (0, 0) => (0, 1, 0), not (0, 0, 1) */
  static fromAffine(p: AffinePoint): Point {
    return p.x === 0n && p.y === 0n ? new Point(0n, 1n, 0n) : new Point(p.x, p.y, 1n);
  }
  toAffine(): AffinePoint {
    if (this.pz === 0n) return Point_ZERO; // zero point has z=0
    const iz = inv(this.pz, P);
    const x = M(this.px * iz);
    const y = M(this.py * iz);
    return { x, y };
  }
  // prettier-ignore
  add(other: Point) {
    const { px: X1, py: Y1, pz: Z1 } = this;
    const { px: X2, py: Y2, pz: Z2 } = other;
    const { a, b } = CURVE;
    let X3 = 0n, Y3 = 0n, Z3 = 0n;
    const b3 = M(b * 3n); // step 1
    let t0 = M(X1 * X2), t1 = M(Y1 * Y2), t2 = M(Z1 * Z2), t3 = M(X1 + Y1);
    let t4 = M(X2 + Y2);                                // step 5
    t3 = M(t3 * t4); t4 = M(t0 + t1); t3 = M(t3 - t4); t4 = M(X1 + Z1);
    let t5 = M(X2 + Z2);                                // step 10
    t4 = M(t4 * t5); t5 = M(t0 + t2); t4 = M(t4 - t5); t5 = M(Y1 + Z1);
    X3 = M(Y2 + Z2);                                    // step 15
    t5 = M(t5 * X3); X3 = M(t1 + t2); t5 = M(t5 - X3); Z3 = M(a * t4);
    X3 = M(b3 * t2);                                    // step 20
    Z3 = M(X3 + Z3); X3 = M(t1 - Z3); Z3 = M(t1 + Z3); Y3 = M(X3 * Z3);
    t1 = M(t0 + t0);                                    // step 25
    t1 = M(t1 + t0); t2 = M(a * t2); t4 = M(b3 * t4); t1 = M(t1 + t2);
    t2 = M(t0 - t2);                                    // step 30
    t2 = M(a * t2); t4 = M(t4 + t2); t0 = M(t1 * t4); Y3 = M(Y3 + t0);
    t0 = M(t5 * t4);                                    // step 35
    X3 = M(t3 * X3); X3 = M(X3 - t0); t0 = M(t3 * t1); Z3 = M(t5 * Z3);
    Z3 = M(Z3 + t0);                                    // step 40
    return new Point(X3, Y3, Z3);
  }
  double() {
    return this.add(this);
  }
  negate() {
    return new Point(this.px, M(-this.py), this.pz);
  }
}
const Proj_ZERO = Point.fromAffine(Point_ZERO);
const Proj_BASE = Point.fromAffine(Point_BASE);
const getPowersProj = (qxy: AffinePoint): Point[] => {
  const q = Point.fromAffine(qxy);
  let points: Point[] = [];
  for (let bit = 0, dbl = q; bit <= 256; bit++, dbl = dbl.double()) {
    points.push(dbl);
  }
  return points;
};
const mul_CT = (q: AffinePoint, n: bigint) => {
  const pows = getPowersProj(q);
  let p = Proj_ZERO;
  let f = Proj_ZERO; // fake point
  for (let bit = 0; bit <= 256; bit++) {
    const at_bit_i = pows[bit];
    if (n & 1n) p = p.add(at_bit_i);
    else f = f.add(at_bit_i);
    n >>= 1n;
  }
  return p.toAffine();
};

// PART 5: wnaf mul

const W = 8; // Precomputes-related code. W = window size
// prettier-ignore
const precompute = () => {                              // They give 12x faster getPublicKey(),
  const points: Point[] = [];                           // 10x sign(), 2x verify(). To achieve this,
  const windows = 256 / W + 1;                          // app needs to spend 40ms+ to calculate
  let p = Proj_BASE, b = p;                  // a lot of points related to base point G.
  for (let w = 0; w < windows; w++) {                   // Points are stored in array and used
    b = p;                                              // any time Gx multiplication is done.
    points.push(b);                                     // They consume 16-32 MiB of RAM.
    for (let i = 1; i < 2 ** (W - 1); i++) { b = b.add(p); points.push(b); }
    p = b.double();                                     // Precomputes don't speed-up getSharedKey,
  }                                                     // which multiplies user point by scalar,
  return points;                                        // when precomputes are using base point
}
let Gpows: Point[] | undefined = undefined; // precomputes for base point G
// prettier-ignore
const wNAF = (n: bigint): { p: Point; f: Point } => {   // w-ary non-adjacent form (wNAF) method.
                                                        // Compared to other point mult methods,
  const comp = Gpows || (Gpows = precompute());         // stores 2x less points using subtraction
  const neg = (cnd: boolean, p: Point) => { let n = p.negate(); return cnd ? n : p; } // negate
  let p = Proj_ZERO, f = Proj_BASE;// f must be G, or could become I in the end
  const windows = 1 + 256 / W;                          // W=8 17 windows
  const wsize = 2 ** (W - 1);                           // W=8 128 window size
  const mask = BigInt(2 ** W - 1);                      // W=8 will create mask 0b11111111
  const maxNum = 2 ** W;                                // W=8 256
  const shiftBy = BigInt(W);                            // W=8 8
  for (let w = 0; w < windows; w++) {
    const off = w * wsize;
    let wbits = Number(n & mask);                       // extract W bits.
    n >>= shiftBy;                                      // shift number by W bits.
    if (wbits > wsize) { wbits -= maxNum; n += 1n; }    // split if bits > max: +224 => 256-32
    const off1 = off, off2 = off + Math.abs(wbits) - 1; // offsets, evaluate both
    const cnd1 = w % 2 !== 0, cnd2 = wbits < 0;         // conditions, evaluate both
    if (wbits === 0) {
      f = f.add(neg(cnd1, comp[off1]));                 // bits are 0: add garbage to fake point
    } else {                                            //          ^ can't add off2, off2 = I
      p = p.add(neg(cnd2, comp[off2]));                 // bits are 1: add to result point
    }
  }
  return { p, f }                                       // return both real and fake points for JIT
}; // !! you can disable precomputes by commenting-out call of the wNAF() inside Point#mul()
const mul_G_wnaf = (n: bigint) => {
  const { p, f } = wNAF(n);
  f.toAffine(); // result ignored
  return p.toAffine();
};

// PART 6: endo

const CURVE_beta = 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501een;
// const CURVE_lambda = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72n;
const CURVE_basis = [
  [0x3086d221a7d46bcde86c90e49284eb15n, -0xe4437ed6010e88286f547fa90abfe4c3n],
  [0x114ca50f7a8e2f3f657c1108d9d44cfd8n, 0x3086d221a7d46bcde86c90e49284eb15n]
];
const divNearest = (a: bigint, b: bigint) => (a + b / 2n) / b;
const splitScalar = (k: bigint) => {
  const n = N;
  const [[a1, b1], [a2, b2]] = CURVE_basis;

  // Use Babai's round-off algorithm:
  // Calculate continuous coordinates in the basis
  const c1 = divNearest(b2 * k, n);
  const c2 = divNearest(-b1 * k, n);

  // Calculate the closest lattice point to (k, 0)
  // Calculate k1 = k - b1 (mod n) and k2 = -b2 (mod n)
  let k1 = M(k - c1 * a1 - c2 * a2, n);
  let k2 = M(-c1 * b1 - c2 * b2, n);

  const POW_2_128 = 0x100000000000000000000000000000000n; // (2n**128n).toString(16)
  const k1neg = k1 > POW_2_128;
  const k2neg = k2 > POW_2_128;
  if (k1neg) k1 = n - k1;
  if (k2neg) k2 = n - k2;
  if (k1 > POW_2_128 || k2 > POW_2_128) err('endomorphism failed, k=' + k);
  return { k1neg, k1, k2neg, k2 };
};
const mul_endo = (q: AffinePoint, n: bigint) => {
  let { k1neg, k1, k2neg, k2 } = splitScalar(n);
  let k1p = Proj_ZERO;
  let k2p = Proj_ZERO;
  let d: Point = Point.fromAffine(q);
  while (k1 > 0n || k2 > 0n) {
    if (k1 & 1n) k1p = k1p.add(d);
    if (k2 & 1n) k2p = k2p.add(d);
    d = d.double();
    k1 >>= 1n;
    k2 >>= 1n;
  }
  if (k1neg) k1p = k1p.negate();
  if (k2neg) k2p = k2p.negate();
  k2p = new Point(M(k2p.px * CURVE_beta), k2p.py, k2p.pz);
  return k1p.add(k2p).toAffine();
};

// PART 7, final pub + sign + verify + shared
const mul = (q: AffinePoint, n: bigint, safe = true) => {
  if (equals(q, Point_BASE)) return mul_G_wnaf(n);
  return safe ? mul_CT(q, n) : mul_endo(q, n);
};

function getPublicKey(privateKey: bigint): AffinePoint {
  return mul(Point_BASE, checkScalar(privateKey));
}

function sign(msgh: Uint8Array, priv: bigint): Signature {
  const m = bytesToNumBE(msgh);
  const d = checkScalar(priv);
  let r = 0n;
  let s = 0n;
  let q;
  do {
    const k = randK();
    const ik = inv(k, N);
    q = mul(Point_BASE, k);
    r = M(q.x, N);
    s = M(ik * M(m + d * r, N), N);
  } while (r === 0n || s === 0n);
  let recovery = (q.x === r ? 0 : 2) | Number(q.y & 1n);
  if (s > N >> 1n) {
    recovery ^= 1;
    s = M(-s, N);
  }
  return { r, s, recovery };
}
function verify(sig: Signature, msgh: Uint8Array, pub: AffinePoint): boolean {
  const { r, s } = sig;
  if (r <= 0n || r >= N || s <= 0n || s >= N || !onCurve(pub)) return false;
  const h = M(bytesToNumBE(msgh), N);
  const is = inv(s, N);
  const u1 = M(h * is, N);
  const u2 = M(r * is, N);
  const G_u1 = mul(Point_BASE, u1);
  const P_u2 = mul(pub, u2, false);
  const R = padd(G_u1, P_u2);
  if (R.x === 0n && R.y === 0n) return false;
  const v = M(R.x, N);
  return v === r;
}
function getSharedSecret(privA: bigint, pubB: AffinePoint): AffinePoint {
  if (!onCurve(pubB)) err('point not on curve');
  return mul(pubB, checkScalar(privA));
}
export { getPublicKey, getSharedSecret, sign, verify };

// PART 8, TEST

const measure = (label: string, fn: any) => {
  console.time(label);
  fn();
  console.timeEnd(label);
};
const test = () => {
  let displayAllLogs = false;

  const P = affine(
    112711660439710606056748659173929673102114977341539408544630613555209775888121n,
    25583027980570883691656905877401976406448868254816295069919888960541586679410n
  );
  const Q = affine(
    21505829891763648114329055987619236494102133314575206970830385799158076338148n,
    98003708678762621233683240503080860129026887322874138805529884920309963580118n
  );
  console.log('test_basic');
  console.log('P + Q', padd(P, Q));
  console.log('P + P', pdouble(P));
  // P+Q {
  //   x: 21262057306151627953595685090280431278183829487175876377991189246716355947009n,
  //   y: 41749993296225487051377864631615517161996906063147759678534462689479575333124n
  // }
  // P+P {
  //   x: 115780575977492633039504758427830329241728645270042306223540962614150928364886n,
  //   y: 78735063515800386211891312544505775871260717697865196436804966483607426560663n
  // }

  const G5 = {
    x: 21505829891763648114329055987619236494102133314575206970830385799158076338148n,
    y: 98003708678762621233683240503080860129026887322874138805529884920309963580118n,
  };

  const assert = (a: AffinePoint, b: AffinePoint) => {
    if (!equals(a, b)) throw new Error(`expected a == b, got a=${a}, b=${b}`);
  };

  function header(label: string, point: any) {
    if (displayAllLogs) console.log(label, point);
    assert(point, G5);
  }

  header('mul_DA', mul_unsafe(Point_BASE, 5n));
  measure('small DA', () => mul_unsafe(Point_BASE, 2n));
  measure('large DA', () => mul_unsafe(Point_BASE, 2n ** 255n - 19n));
  // small: 0.078ms
  // large: 14.687ms
  // BASE * 5, Point {
  //   x: 21505829891763648114329055987619236494102133314575206970830385799158076338148n,
  //   y: 98003708678762621233683240503080860129026887322874138805529884920309963580118n
  // }

  header('mul_CT', mul_CT_slow(Point_BASE, 5n));
  measure('small CT', () => mul_CT_slow(Point_BASE, 2n));
  measure('large CT', () => mul_CT_slow(Point_BASE, 2n ** 255n - 19n));
  // small CT: 13.197ms
  // large CT: 13.182ms

  header('mul_CT_proj', mul_CT(Point_BASE, 5n));
  measure('CT proj', () => mul_CT(Point_BASE, 2n ** 255n - 19n));
  // console.log("BASE * 5", mul_CT_proj(Point_BASE, 5n));
  // small CT: 13.197ms
  // large CT: 13.182ms
  header('mul_G_wnaf', mul_G_wnaf(5n));
  measure('mul_G_wnaf', () => mul_G_wnaf(5n));

  header('mul_endo', mul_endo(Point_BASE, 5n));
  measure('mul_endo', () => mul_endo(Point_BASE, 5n));

  header('mul_combined', mul(Point_BASE, 5n));
  measure('mul_combined', () => mul(Point_BASE, 5n));

  const priv = 2n ** 253n - 1230n;
  const msgh = new Uint8Array(32).fill(0xca);
  const pub = getPublicKey(priv);
  const sig = sign(msgh, priv);
  const is_valid = _verify(sig, msgh, pub);
  // console.log({
  //   priv,
  //   msgh,
  //   pub,
  //   sig,
  //   is_valid,
  // });
  console.log('is valid sig', is_valid);

  console.log('test_edge_cases');
  const ok = (cond: boolean, m: string) => { if (!cond) err(m); };
  const throws = (fn: () => any) => { try { fn(); return false; } catch { return true; } };
  ok(is_valid, '_verify(sig)');
  ok(verify(sig, msgh, pub), 'verify(sig)');
  ok(verify(_sign(msgh, priv), msgh, pub), 'verify(_sign(...))');
  ok(_verify(sign(msgh, priv), msgh, pub), '_verify(sign(...))');
  ok(equals(pub, _getPublicKey(priv)), 'getPublicKey == _getPublicKey');
  ok(equals(getSharedSecret(priv, G5), mul_unsafe(G5, priv)), 'getSharedSecret');
  for (const v of [verify, _verify]) {
    ok(!v(sig, new Uint8Array(32).fill(1), pub), 'tampered msg');
    ok(!v({ r: 0n, s: sig.s }, msgh, pub), 'r=0');
    ok(!v({ r: sig.r, s: 0n }, msgh, pub), 's=0');
    ok(!v({ r: sig.r + N, s: sig.s }, msgh, pub), 'r>N');
    ok(!v({ r: sig.r, s: sig.s + N }, msgh, pub), 's>N');
    ok(!v(sig, msgh, affine(2n, 3n)), 'pub not on curve');
    ok(!v(sig, msgh, Point_ZERO), 'pub is zero');
  }
  for (const fn of [getPublicKey, _getPublicKey]) {
    ok(throws(() => fn(0n)), 'priv=0 throws');
    ok(throws(() => fn(N)), 'priv=N throws');
    ok(throws(() => fn(-1n)), 'priv<0 throws');
  }
  ok(throws(() => getSharedSecret(priv, affine(2n, 3n))), 'ecdh bad point throws');
  ok(equals(padd(pub, Point_ZERO), pub), 'P + 0 = P');
  ok(equals(padd(Point_ZERO, pub), pub), '0 + P = P');
  ok(equals(padd(pub, affine(pub.x, M(-pub.y))), Point_ZERO), 'P + (-P) = 0');
  ok(equals(mul_G_wnaf(0n), Point_ZERO), 'wnaf mul by 0 = zero point');
  ok(equals(mul_CT(Point_BASE, 0n), Point_ZERO), 'CT mul by 0 = zero point');
  console.log('edge cases OK');

  console.log();
  measure('getPublicKey_unsafe 1', () => _getPublicKey(priv));
  measure('getPublicKey_unsafe 2', () => _getPublicKey(5n));
  measure('sign_slow_unsafe', () => _sign(msgh, priv));
  measure('verify_slow', () => _verify(sig, msgh, pub));

  console.log();
  measure('getPublicKey', () => getPublicKey(priv));
  measure('sign', () => sign(msgh, priv));
  measure('verify', () => verify(sig, msgh, pub));
};
test();

