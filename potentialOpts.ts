add(other: JacobianPoint): JacobianPoint {
    if (!(other instanceof JacobianPoint)) {
      throw new TypeError('JacobianPoint#add: expected JacobianPoint');
    }
    if (other.x === 0n || other.y === 0n) return this;
    if (this.x === 0n || this.y === 0n) return other;
    const Z1Z1 = mod(this.z * this.z);
    const Z2Z2 = mod(other.z * other.z);
    const U1 = mod(this.x * Z2Z2);
    const U2 = mod(other.x * Z1Z1);
    const S1 = mod(this.y * other.z * Z2Z2);
    const S2 = mod(other.y * this.z * Z1Z1);
    const H = mod(U2 - U1);
    const r = mod(S2 - S1);
    // H = 0 meaning it's the same point.
    if (H === 0n) {
      return (r === 0n) ? this.double() : JacobianPoint.ZERO;
    }
    const HH = mod(H * H);
    const HHH = mod(H * HH);
    const V = mod(U1 * HH);
    const X3 = mod(r * r - HHH - (V + V));
    return new JacobianPoint(X3, mod(r * (V - X3) - S1 * HHH), mod(this.z * other.z * H));
  }

  // Inverses number over modulo
function invert(number: bigint, modulo: bigint = CURVE.P): bigint {
  if (number === 0n || modulo <= 0n) {
    throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
  }
  // Euclidian GCD https://brilliant.org/wiki/extended-euclidean-algorithm/
  let a = mod(number, modulo),
    b = modulo,
    x = 0n,
    y = 1n,
    u = 1n,
    v = 0n,
    q,
    r,
    m,
    n;
  while (true) {
    q = b / a;
    r = b % a;
    m = x - u * q;
    n = y - v * q;
    b = a;
    a = r;
    x = u;
    y = v;
    if (a === 0n) {
      break;
    }
    u = m;
    v = n;
  }
  if (b !== 1n) throw new Error('invert: does not exist');
  return mod(x, modulo);
}
static toAffineBatch(points: JacobianPoint[]): Point[] {
    const len = points.length;
    const scratch = new Array(len);
    let acc = 1n;
    const result: Point[] = new Array(len);
    for (let i = 0; i < len; i++) {
      if (points[i].z === 0n) continue;
      scratch[i] = acc;
      acc = mod(acc * points[i].z);
    }
    acc = invert(acc);
    for (let i = len - 1; i >= 0; i--) {
      if (points[i].z === 0n) continue;
      result[i] = points[i].toAffine(mod(acc * scratch[i]));
      acc = mod(acc * points[i].z);
    }
    return result;
  }
  private precomputeWindow(W: number): JacobianPoint[] {
    // splitScalarEndo could return 129-bit numbers, so we need at least 128 / W + 1
    const windows = USE_ENDOMORPHISM ? 128 / W + 1 : 256 / W + 1;
    const W1 = 2 ** (W - 1);
    const points: JacobianPoint[] = new Array(W1 * windows);
    let p: JacobianPoint = this;
    let base = p;
    points[0] = base;
    for (let i = 1, il = W1 * windows; i < il; i++) {
      if (i % W1) {
        base = base.add(p);
      } else {
        p = base.double();
        base = p;
      }
      points[i] = base;
    }
    return points;
  }