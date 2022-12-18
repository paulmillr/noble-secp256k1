/*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
import { secp256k1, schnorr as schnorr_secp } from 'micro-curve-definitions/lib/secp256k1';
import * as genUtils from '@noble/curves/utils';

/**
 * Changes required in @noble/curves to make @noble/secp256k1@1.7 test suite pass:
 * - Adjust errors: Point.assertValidity() vs Point.fromHex()
 *   have "is not on elliptic curve" vs "is not on curve"
 * - Remove this line=> key = key.padStart(2 * groupLen, '0'); // Eth-like hexes
 * -
 *
 * Possible future changes for backwards compatibility:
 * - precomputes
 * - allow/ban setting hashes
 * - ban non-Hex inputs to sign() / verify(): hard to check types
 */

const { getPublicKey, sign: sign_secp, verify: verify_secp, getSharedSecret, Point, JacobianPoint, utils: utilsc, CURVE, Signature } = secp256k1;
export const _JacobianPoint = JacobianPoint;
export const utils = Object.assign({
  sha256(data: Uint8Array) {
    return secp256k1.CURVE.hash(data);
  },
  sha256Sync: (data: Uint8Array) => {
    return secp256k1.CURVE.hash(data);
  },
  _JacobianPoint: JacobianPoint,
  precompute(a: number) {},
  _bigintTo32Bytes: (n: bigint) => {
    const bytes = utilsc._bigintToBytes(n);
    genUtils.ensureBytes(bytes, 32);
    return bytes;
  }
}, utilsc, genUtils);
export { getPublicKey, getSharedSecret, Point, CURVE, Signature };

type U8A = Uint8Array;
type Hex = Uint8Array | string;
type PrivKey = Hex | bigint;
type Entropy = Hex | true;
type OptsOther = { canonical?: boolean; der?: boolean; extraEntropy?: Entropy };
type OptsRecov = { recovered: true } & OptsOther;
type OptsNoRecov = { recovered?: false } & OptsOther;
type Opts = { recovered?: boolean } & OptsOther;
type SignOutput = Uint8Array | [Uint8Array, number];

async function sign(msgHash: Hex, privKey: PrivKey, opts: OptsRecov): Promise<[U8A, number]>;
async function sign(msgHash: Hex, privKey: PrivKey, opts?: OptsNoRecov): Promise<U8A>;
async function sign(msgHash: Hex, privKey: PrivKey, opts: Opts = {}): Promise<SignOutput> {
  const secp_opts: Record<any, any> = {};
  if (opts.canonical === false) throw new Error('Canonical: false is not supported');
  if ('extraEntropy' in opts) secp_opts.extraEntropy = opts.extraEntropy;
  const res = sign_secp(msgHash, privKey, secp_opts);
  const raw = (opts.der === false) ? res.toCompactRawBytes() : res.toDERRawBytes();
  const rec = res.recovery!;
  return opts.recovered ? [raw, rec] : raw;
}

type VOpts = { strict?: boolean };
const vopts: VOpts = { strict: true };
// type PubKey = Hex | PubKey;

interface RS { r: bigint, s: bigint }
interface XY { x: bigint, s: bigint }
function verify(signature: Hex | RS, msgHash: Hex, publicKey: Hex, opts = vopts): boolean {
  const secp_opts: Record<any, any> = {};
  secp_opts.lowS = (opts.strict === false) ? false : true;
  return verify_secp(signature as Hex, msgHash, genUtils.ensureBytes(publicKey), secp_opts);
}
export function recoverPublicKey(
  msgHash: Hex,
  signature: Hex,
  recovery: number,
  isCompressed = false
): Uint8Array {
  let sig;
  try { sig = Signature.fromDER(signature); } catch (e) { sig = Signature.fromCompact(signature); }
  sig = sig.copyWithRecoveryBit(recovery);
  return sig.recoverPublicKey(msgHash).toRawBytes(isCompressed)
}
export const signSync = sign;
export { sign, verify };
export const schnorr = {
  getPublicKey: schnorr_secp.getPublicKey,
  sign: schnorr_secp.sign,
  signSync: schnorr_secp.sign,
  verify: schnorr_secp.verify,
  verifySync: schnorr_secp.verify
};
