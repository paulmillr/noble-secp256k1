import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { numberToBytesBE, schnorr, secp } from './secp256k1.helpers.ts';

const { p: P, n: N } = secp.Point.CURVE();
const { bytesToHex, concatBytes, hexToBytes } = secp.etc;

// Targeted regressions for size-golf refactors whose safety rests on
// equivalence arguments rather than structure: hex parsing, SEC1 branch
// returns, low-S algebra, positional option tuples, and fail-closed
// handling of degenerate double-scalar results.
describe('golf regressions', () => {
  it('hexToBytes accepts exactly ASCII hex across all 256 char codes', () => {
    for (let c = 0; c < 256; c++) {
      const ch = String.fromCharCode(c);
      if (/^[0-9a-fA-F]$/.test(ch)) {
        // exercise the nibble arithmetic in both positions
        eql(hexToBytes('0' + ch)[0], Number.parseInt(ch, 16));
        eql(hexToBytes(ch + '0')[0], Number.parseInt(ch, 16) * 16);
      } else {
        throws(() => hexToBytes('0' + ch), RangeError);
        throws(() => hexToBytes(ch + '0'), RangeError);
      }
    }
    eql(hexToBytes(''), Uint8Array.of());
    throws(() => hexToBytes('abc'), RangeError); // odd length
  });

  it('Point.fromBytes handles every SEC1 branch strictly', () => {
    const G = secp.Point.BASE;
    // Round-trip both compressed prefixes (0x02 even / 0x03 odd) and uncompressed.
    let seen2 = false;
    let seen3 = false;
    for (let p = G, i = 0; i < 20 && !(seen2 && seen3); i++, p = p.add(G)) {
      const c = p.toBytes(true);
      if (c[0] === 0x02) seen2 = true;
      else seen3 = true;
      eql(secp.Point.fromBytes(c).equals(p), true);
      eql(secp.Point.fromBytes(p.toBytes(false)).equals(p), true);
    }
    eql(seen2 && seen3, true);

    const bad = (b: Uint8Array) => throws(() => secp.Point.fromBytes(b), /bad point/);
    const comp = G.toBytes(true);
    const uncomp = G.toBytes(false);
    bad(Uint8Array.of(0x00)); // SEC1 infinity encoding stays rejected
    bad(new Uint8Array(33)); // zero prefix, zero x
    bad(new Uint8Array(65));
    let t = comp.slice(); // wrong prefix for the length
    t[0] = 0x04;
    bad(t);
    t = comp.slice();
    t[0] = 0x01;
    bad(t);
    t = uncomp.slice();
    t[0] = 0x02;
    bad(t);
    bad(comp.subarray(0, 32)); // truncated / padded
    bad(concatBytes(comp, Uint8Array.of(0)));
    bad(uncomp.subarray(0, 64));
    bad(concatBytes(Uint8Array.of(0x02), new Uint8Array(32))); // x = 0
    bad(concatBytes(Uint8Array.of(0x02), numberToBytesBE(P))); // x = p
    t = uncomp.slice(); // off-curve y in the uncompressed branch
    t[64] ^= 1;
    bad(t);

    // Small-x sweep: non-residues throw, residues honor the requested parity.
    let residues = 0;
    let nonresidues = 0;
    for (let x = 1n; x <= 20n; x++) {
      for (const prefix of [0x02, 0x03]) {
        const b = concatBytes(Uint8Array.of(prefix), numberToBytesBE(x));
        try {
          const pt = secp.Point.fromBytes(b);
          eql(pt.x, x);
          eql(pt.y & 1n, BigInt(prefix - 2)); // 0x02 => even y, 0x03 => odd y
          residues++;
        } catch (e) {
          nonresidues++;
        }
      }
    }
    eql(residues > 0 && nonresidues > 0, true);
  });

  it('__TEST.lift_x returns the canonical even-y point', () => {
    eql(secp.__TEST.lift_x(secp.Point.BASE.x).equals(secp.Point.BASE), true);
  });

  it('specialized point-add matches the reference RCB formula', () => {
    // Reference: unspecialized Renes-Costello-Batina algo 1 (2015/1060) with a=0, b3=21,
    // kept verbatim here so any future edit to the specialized Point.add is checked
    // against the published step sequence, including its complete-formula edge cases.
    const M = (a: bigint) => secp.etc.mod(a);
    type Proj = [bigint, bigint, bigint];
    // prettier-ignore
    const refAdd = ([X1, Y1, Z1]: Proj, [X2, Y2, Z2]: Proj): Proj => {
      const a = 0n, b3 = 21n;
      let X3 = 0n, Y3 = 0n, Z3 = 0n;
      let t0 = M(X1 * X2), t1 = M(Y1 * Y2), t2 = M(Z1 * Z2), t3 = M(X1 + Y1); // step 1
      let t4 = M(X2 + Y2); // step 5
      t3 = M(t3 * t4); t4 = M(t0 + t1); t3 = M(t3 - t4); t4 = M(X1 + Z1);
      let t5 = M(X2 + Z2); // step 10
      t4 = M(t4 * t5); t5 = M(t0 + t2); t4 = M(t4 - t5); t5 = M(Y1 + Z1);
      X3 = M(Y2 + Z2); // step 15
      t5 = M(t5 * X3); X3 = M(t1 + t2); t5 = M(t5 - X3); Z3 = M(a * t4);
      X3 = M(b3 * t2); // step 20
      Z3 = M(X3 + Z3); X3 = M(t1 - Z3); Z3 = M(t1 + Z3); Y3 = M(X3 * Z3);
      t1 = M(t0 + t0); // step 25
      t1 = M(t1 + t0); t2 = M(a * t2); t4 = M(b3 * t4); t1 = M(t1 + t2);
      t2 = M(t0 - t2); // step 30
      t2 = M(a * t2); t4 = M(t4 + t2); t0 = M(t1 * t4); Y3 = M(Y3 + t0);
      t0 = M(t5 * t4); // step 35
      X3 = M(t3 * X3); X3 = M(X3 - t0); t0 = M(t3 * t1); Z3 = M(t5 * Z3);
      Z3 = M(Z3 + t0); // step 40
      return [X3, Y3, Z3];
    };
    const projEq = ([X1, Y1, Z1]: Proj, [X2, Y2, Z2]: Proj): boolean => {
      if ((Z1 === 0n) !== (Z2 === 0n)) return false;
      if (Z1 === 0n) return M(X1 * Y2) === M(X2 * Y1); // compare (X:Y) ray at infinity
      return M(X1 * Z2) === M(X2 * Z1) && M(Y1 * Z2) === M(Y2 * Z1);
    };
    const randScalar = () => (secp.etc.bytesToNumberBE(secp.etc.randomBytes(40)) % (N - 1n)) + 1n;
    const randFp = () => (secp.etc.bytesToNumberBE(secp.etc.randomBytes(40)) % (P - 1n)) + 1n;
    const scaled = (p: InstanceType<typeof secp.Point>, l: bigint) =>
      new secp.Point(M(p.X * l), M(p.Y * l), M(p.Z * l));
    const check = (p: InstanceType<typeof secp.Point>, q: InstanceType<typeof secp.Point>) => {
      const r = p.add(q);
      eql(projEq([r.X, r.Y, r.Z], refAdd([p.X, p.Y, p.Z], [q.X, q.Y, q.Z])), true);
    };
    const G = secp.Point.BASE;
    const I = secp.Point.ZERO;
    // complete-formula edge cases: identity, doubling, inverse (result at infinity)
    check(I, I);
    check(G, I);
    check(I, G);
    check(G, G);
    check(G, G.negate());
    for (let i = 0; i < 250; i++) {
      const p = scaled(G.multiply(randScalar(), false), randFp());
      const q = scaled(G.multiply(randScalar(), false), randFp());
      check(p, q); // random projective pair
      check(p, p); // doubling via add
      check(p, scaled(p.negate(), randFp())); // P + (-P) -> infinity
      check(p, secp.Point.fromAffine(q.toAffine())); // mixed projective/affine (Z2=1)
    }
  });

  it('ECDSA low-S uses N - s; verify honors the lowS option slot', () => {
    const sk = secp.utils.randomSecretKey();
    const pub = secp.getPublicKey(sk);
    const msg = new TextEncoder().encode('golf medium risk');
    const sig = secp.sign(msg, sk);
    const { r, s } = secp.Signature.fromBytes(sig);
    eql(s <= N >> 1n, true);
    const hiS = new secp.Signature(r, N - s).toBytes(); // malleated high-S twin
    eql(secp.verify(sig, msg, pub), true);
    eql(secp.verify(hiS, msg, pub), false); // default lowS: true rejects it
    eql(secp.verify(hiS, msg, pub, { lowS: false }), true); // still a valid signature
    eql(secp.verify(sig, msg, pub, { lowS: false }), true);
  });

  it('ECDSA prehash option slot: digest path equals hashed path', () => {
    const sk = secp.utils.randomSecretKey();
    const pub = secp.getPublicKey(sk);
    const msg = new TextEncoder().encode('golf medium risk');
    const digest = secp.hash(msg);
    eql(secp.sign(digest, sk, { prehash: false }), secp.sign(msg, sk));
    eql(secp.verify(secp.sign(msg, sk), digest, pub, { prehash: false }), true);
  });

  it('ECDSA format and extraEntropy option slots', () => {
    const sk = secp.utils.randomSecretKey();
    const pub = secp.getPublicKey(sk);
    const msg = new TextEncoder().encode('golf medium risk');
    const sig = secp.sign(msg, sk);
    const rec = secp.sign(msg, sk, { format: 'recovered' });
    eql(rec.length, 65);
    eql(rec.subarray(1), sig); // recovered = recovery byte || compact
    throws(() => secp.sign(msg, sk, { format: 'der' }), /not supported/);
    throws(() => secp.verify(sig, msg, pub, { format: 'der' }), /not supported/);
    eql(secp.recoverPublicKey(rec, msg), pub);
    eql(secp.recoverPublicKey(rec, secp.hash(msg), { prehash: false }), pub);
    const badRec = rec.slice();
    badRec[0] = 4;
    throws(() => secp.recoverPublicKey(badRec, msg), /invalid recovery/);

    eql(secp.sign(msg, sk, { extraEntropy: false }), sig);
    eql(secp.sign(msg, sk, { extraEntropy: undefined }), sig);
    const ent = new Uint8Array(32).fill(7);
    const sigE = secp.sign(msg, sk, { extraEntropy: ent });
    eql(sigE, secp.sign(msg, sk, { extraEntropy: ent })); // deterministic per entropy
    eql(bytesToHex(sigE) !== bytesToHex(sig), true); // entropy actually entered the DRBG seed
    eql(secp.verify(sigE, msg, pub), true);
    eql(secp.verify(secp.sign(msg, sk, { extraEntropy: true }), msg, pub), true);
    throws(() => secp.sign(msg, sk, { extraEntropy: 'nope' as any }), TypeError);
  });

  it('verify/recover fail closed when the double-scalar result is infinity', () => {
    // verify: Q = -G and h ≡ r (mod n) give R = (h - r)·s⁻¹·G = O.
    const Qb = secp.Point.BASE.negate().toBytes();
    const sig = new secp.Signature(2n, 5n).toBytes();
    eql(secp.verify(sig, numberToBytesBE(2n), Qb, { prehash: false }), false);
    // recover: r = G.x with even-y recovery bit makes R = G; h ≡ s gives O.
    const sigRec = concatBytes(
      Uint8Array.of(0),
      numberToBytesBE(secp.Point.BASE.x),
      numberToBytesBE(5n)
    );
    throws(() => secp.recoverPublicKey(sigRec, numberToBytesBE(5n), { prehash: false }));
  });

  it('schnorr verify bounds the 32-byte public key to x in [1, p-1]', () => {
    const sk = secp.utils.randomSecretKey();
    const pk = schnorr.getPublicKey(sk);
    const msg = new TextEncoder().encode('bip340');
    const sig = schnorr.sign(msg, sk, new Uint8Array(32));
    eql(schnorr.verify(sig, msg, pk), true);
    eql(schnorr.verify(sig, msg, new Uint8Array(32)), false); // x = 0
    eql(schnorr.verify(sig, msg, numberToBytesBE(P)), false); // x = p
    eql(schnorr.verify(sig, msg, numberToBytesBE(P + 1n)), false);
    const flip = pk.slice();
    flip[31] ^= 1;
    eql(schnorr.verify(sig, msg, flip), false); // challenge is bound to the exact key bytes
  });
});
