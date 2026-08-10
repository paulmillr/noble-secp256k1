/*!MIT(c)paulmillr.com*/
// Minimal, unoptimized secp256k1 ECDSA + ECDH, for learning purposes.
// Affine coordinates, double-and-add multiplication, Fermat inversion:
// no projective coords, no precomputes, no wNAF, no endomorphism.
// Not constant-time and slow — use ../index.ts (noble-secp256k1) in production.

// secp256k1 curve parameters. Verify using https://www.secg.org/sec2-v2.pdf
const _256 = 2n ** 256n;
const P = _256 - 0x1000003d1n; // curve's field prime
const N = _256 - 0x14551231950b75fc4402da1732fc9bebfn; // curve (group) order
// Generator / base point x, y values, from the same document
const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
const err = (m: string): never => { throw new Error(m); }; // error helper
const M = (a: bigint, b: bigint = P) => {
  // mod division
  const r = a % b;
  return r >= 0n ? r : b + r;
};
// Modular inversion via Fermat's little theorem: a⁻¹ = a^(md-2) mod md.
// Requires md to be prime (P and N both are). Square-and-multiply exponentiation.
const inv = (a: bigint, md: bigint): bigint => {
  a = M(a, md);
  if (a === 0n) err('no inverse');
  let r = 1n;
  for (let e = md - 2n; e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * a) % md;
    a = (a * a) % md;
  }
  return r;
};
// Point in 2d affine (x, y) coordinates
interface AffinePoint {
  x: bigint;
  y: bigint;
}
const ZERO: AffinePoint = { x: 0n, y: 0n }; // point at infinity aka identity point aka zero
const G: AffinePoint = { x: Gx, y: Gy };
// Checks if a point is on curve: y² = x³ + 7. Zero point is not on curve.
const onCurve = (p: AffinePoint) => M(p.y * p.y - p.x ** 3n - 7n) === 0n;
// Validates a scalar (e.g. private key): must be in range [1, N-1]
const checkScalar = (d: bigint): bigint => (0n < d && d < N ? d : err('invalid scalar'));
// Adds two points. https://hyperelliptic.org/EFD/g1p/auto-shortw.html
// Doubling (a == b) uses the tangent-line slope, addition uses the chord-line slope.
const padd = (a: AffinePoint, b: AffinePoint): AffinePoint => {
  const { x: X1, y: Y1 } = a;
  const { x: X2, y: Y2 } = b;
  if (X1 === 0n && Y1 === 0n) return b; // 0 + b = b
  if (X2 === 0n && Y2 === 0n) return a; // a + 0 = a
  let lam;
  if (X1 === X2) {
    if (Y1 !== Y2) return ZERO; // opposite points, a + (-a) = 0
    lam = M(3n * X1 * X1 * inv(2n * Y1, P)); // λ = (3x₁² + a) / (2y₁), curve's a is 0
  } else {
    lam = M((Y2 - Y1) * inv(X2 - X1, P)); // λ = (y₂ - y₁) / (x₂ - x₁)
  }
  const X3 = M(lam * lam - X1 - X2); // x₃ = λ² - x₁ - x₂
  const Y3 = M(lam * (X1 - X3) - Y1); // y₃ = λ * (x₁ - x₃) - y₁
  return { x: X3, y: Y3 };
};
// Multiplies point by scalar: double-and-add. Not constant-time: leaks bits of n via timing.
const mul = (q: AffinePoint, n: bigint): AffinePoint => {
  let p = ZERO;
  for (; n > 0n; n >>= 1n, q = padd(q, q)) {
    if (n & 1n) p = padd(p, q);
  }
  return p;
};
// Convert Uint8Array to bigint, big endian
const bytesToNumBE = (bytes: Uint8Array): bigint =>
  bytes.reduce((n, byte) => (n << 8n) | BigInt(byte), 0n);
// Random k from CSPRNG. 48 bytes (not 32) are fetched to make modulo bias negligible;
// (mod N-1)+1 moves the result into range [1, N-1].
const randK = (): bigint => {
  const b = crypto.getRandomValues(new Uint8Array(48));
  return M(bytesToNumBE(b), N - 1n) + 1n;
};
interface Signature {
  r: bigint;
  s: bigint;
}
function getPublicKey(priv: bigint): AffinePoint {
  return mul(G, checkScalar(priv));
}
// ECDSA signing of a 32-byte prehashed message, with random (non-deterministic) k.
function sign(msgh: Uint8Array, priv: bigint): Signature {
  const m = bytesToNumBE(msgh);
  const d = checkScalar(priv);
  let r = 0n;
  let s = 0n;
  do {
    const k = randK();
    const R = mul(G, k);
    r = M(R.x, N); // r = Rx mod N
    s = M(inv(k, N) * M(m + d * r, N), N); // s = k⁻¹(m + dr) mod N
  } while (r === 0n || s === 0n); // negligible chance, but the spec requires retrying
  if (s > N >> 1n) s = N - s; // low-s: smaller of two valid s values, prevents malleability
  return { r, s };
}
function verify(sig: Signature, msgh: Uint8Array, pub: AffinePoint): boolean {
  const { r, s } = sig;
  if (r <= 0n || r >= N || s <= 0n || s >= N || !onCurve(pub)) return false;
  const m = M(bytesToNumBE(msgh), N);
  const is = inv(s, N);
  const u1 = M(m * is, N);
  const u2 = M(r * is, N);
  const R = padd(mul(G, u1), mul(pub, u2)); // R = u1×G + u2×pub
  if (R.x === 0n && R.y === 0n) return false;
  return M(R.x, N) === r;
}
// ECDH: shared secret between our private key and other party's public key
function getSharedSecret(priv: bigint, pub: AffinePoint): AffinePoint {
  if (!onCurve(pub)) err('point not on curve');
  return mul(pub, checkScalar(priv));
}
export { getPublicKey, getSharedSecret, sign, verify };

// TEST
const test = () => {
  const ok = (c: boolean, m: string) => { if (!c) err(m); };
  const eq = (a: AffinePoint, b: AffinePoint) => a.x === b.x && a.y === b.y;
  const throws = (fn: () => any) => { try { fn(); return false; } catch { return true; } };
  const G5 = { // known vector: G * 5
    x: 21505829891763648114329055987619236494102133314575206970830385799158076338148n,
    y: 98003708678762621233683240503080860129026887322874138805529884920309963580118n,
  };
  ok(eq(mul(G, 5n), G5), 'G * 5');
  const priv = 2n ** 253n - 1230n;
  const msgh = new Uint8Array(32).fill(0xca);
  const pub = getPublicKey(priv);
  const sig = sign(msgh, priv);
  ok(verify(sig, msgh, pub), 'verify(sign())');
  ok(!verify(sig, new Uint8Array(32).fill(1), pub), 'tampered msg');
  ok(!verify({ r: 0n, s: sig.s }, msgh, pub), 'r=0');
  ok(!verify({ r: sig.r, s: 0n }, msgh, pub), 's=0');
  ok(!verify({ r: sig.r, s: sig.s + N }, msgh, pub), 's>N');
  ok(!verify(sig, msgh, { x: 2n, y: 3n }), 'pub not on curve');
  ok(!verify(sig, msgh, ZERO), 'pub is zero');
  ok(throws(() => getPublicKey(0n)), 'priv=0 throws');
  ok(throws(() => getPublicKey(N)), 'priv=N throws');
  ok(throws(() => getSharedSecret(priv, { x: 2n, y: 3n })), 'ecdh bad point throws');
  ok(eq(padd(pub, { x: pub.x, y: M(-pub.y) }), ZERO), 'P + (-P) = 0');
  ok(eq(getSharedSecret(priv, G5), mul(G5, priv)), 'ecdh');
  console.log('1kb-v2 self-test OK');
  console.time('getPublicKey');
  getPublicKey(priv);
  console.timeEnd('getPublicKey');
  console.time('sign');
  sign(msgh, priv);
  console.timeEnd('sign');
  console.time('verify');
  verify(sig, msgh, pub);
  console.timeEnd('verify');
};
test();
