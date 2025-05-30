import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import * as secp256k1 from '../index.js';
import * as secp_1 from '../index.js';
export { secp_1 as secp };
secp256k1.etc.hmacSha256Sync = (key, ...msgs) => hmac(sha256, key, secp256k1.etc2.concatBytes(...msgs));
if ('sha256Sync' in secp256k1.etc) {
    secp256k1.etc.sha256Sync = sha256;
}
const { bytesToNumberBE: b2n, hexToBytes: h2b } = secp256k1.etc2;
export const DER = {
    // asn.1 DER encoding utils
    Err: class DERErr extends Error {
        constructor(m = '') {
            super(m);
        }
    },
    _parseInt(data) {
        const { Err: E } = DER;
        if (data.length < 2 || data[0] !== 0x02)
            throw new E('Invalid signature integer tag');
        const len = data[1];
        const res = data.subarray(2, len + 2);
        if (!len || res.length !== len)
            throw new E('Invalid signature integer: wrong length');
        // https://crypto.stackexchange.com/a/57734 Leftmost bit of first byte is 'negative' flag,
        // since we always use positive integers here. It must always be empty:
        // - add zero byte if exists
        // - if next byte doesn't have a flag, leading zero is not allowed (minimal encoding)
        if (res[0] & 0b10000000)
            throw new E('Invalid signature integer: negative');
        if (res[0] === 0x00 && !(res[1] & 0b10000000))
            throw new E('Invalid signature integer: unnecessary leading zero');
        return { d: b2n(res), l: data.subarray(len + 2) }; // d is data, l is left
    },
    toSig(hex) {
        // parse DER signature
        const { Err: E } = DER;
        const data = typeof hex === 'string' ? h2b(hex) : hex;
        if (!(data instanceof Uint8Array))
            throw new Error('ui8a expected');
        let l = data.length;
        if (l < 2 || data[0] != 0x30)
            throw new E('Invalid signature tag');
        if (data[1] !== l - 2)
            throw new E('Invalid signature: incorrect length');
        const { d: r, l: sBytes } = DER._parseInt(data.subarray(2));
        const { d: s, l: rBytesLeft } = DER._parseInt(sBytes);
        if (rBytesLeft.length)
            throw new E('Invalid signature: left bytes after parsing');
        return { r, s };
    },
    hexFromSig(sig) {
        const slice = (s) => (Number.parseInt(s[0], 16) >= 8 ? '00' + s : s); // slice DER
        const h = (num) => {
            const hex = num.toString(16);
            return hex.length & 1 ? `0${hex}` : hex;
        };
        const s = slice(h(sig.s));
        const r = slice(h(sig.r));
        const shl = s.length / 2;
        const rhl = r.length / 2;
        const sl = h(shl);
        const rl = h(rhl);
        return `30${h(rhl + shl + 4)}02${rl}${r}02${sl}${s}`;
    },
};
export const sigFromDER = (der) => {
    const { r, s } = DER.toSig(der);
    return new secp256k1.Signature(r, s).toCompactRawBytes();
};
export const sigToDER = (sig) => DER.hexFromSig(sig);
export const selectHash = (secp) => sha256;
export const normVerifySig = (s) => DER.toSig(s);
export const bytesToNumberBE = secp256k1.etc2.bytesToNumberBE;
export const numberToBytesBE = secp256k1.etc2.numberToBytesBE;
export const mod = secp256k1.etc2.mod;
