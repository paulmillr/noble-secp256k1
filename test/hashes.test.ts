import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, throws } from 'node:assert';
import * as secp256k1 from '../index.ts';

describe('hashes', () => {
  it('hash() rejects a non-Uint8Array message before calling the configured SHA-256 provider', () => {
    const prev = secp256k1.hashes.sha256;
    let called = false;
    try {
      secp256k1.hashes.sha256 = () => {
        called = true;
        return new Uint8Array(32);
      };
      throws(() => secp256k1.hash('abc' as unknown as Uint8Array), /"message" expected Uint8Array/);
      eql(called, false);
    } finally {
      secp256k1.hashes.sha256 = prev;
    }
  });

  it('hash()/sign() reject configured SHA-256 providers that return digests not exactly 32 bytes', () => {
    const msg = Uint8Array.of(9);
    const secretKey = Uint8Array.of(...Array(31).fill(0), 1);
    const prev = secp256k1.hashes.sha256;
    try {
      secp256k1.hashes.sha256 = () => new Uint8Array([1, 2, 3]);
      throws(() => secp256k1.hash(msg), /digest/);
      throws(() => secp256k1.sign(msg, secretKey), /digest/);
    } finally {
      secp256k1.hashes.sha256 = prev;
    }
  });

  it('signAsync()/verifyAsync() reject configured async SHA-256 providers that return digests not exactly 32 bytes', async () => {
    const msg = Uint8Array.of(9);
    const secretKey = Uint8Array.of(...Array(31).fill(0), 1);
    const publicKey = secp256k1.getPublicKey(secretKey);
    const prevSha = secp256k1.hashes.sha256;
    const prevHmac = secp256k1.hashes.hmacSha256;
    secp256k1.hashes.sha256 = sha256;
    secp256k1.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);
    const signature = secp256k1.sign(msg, secretKey);
    const prev = secp256k1.hashes.sha256Async;
    try {
      secp256k1.hashes.sha256Async = async () => new Uint8Array([1, 2, 3]);
      await rejects(() => secp256k1.signAsync(msg, secretKey), /digest/);
      await rejects(() => secp256k1.verifyAsync(signature, msg, publicKey), /digest/);
    } finally {
      secp256k1.hashes.sha256Async = prev;
      secp256k1.hashes.sha256 = prevSha;
      secp256k1.hashes.hmacSha256 = prevHmac;
    }
  });

  it('sign()/signAsync() reject configured HMAC-SHA256 providers that return digests not exactly 32 bytes', async () => {
    const msg = Uint8Array.of(9);
    const secretKey = Uint8Array.of(...Array(31).fill(0), 1);
    const prevSha = secp256k1.hashes.sha256;
    secp256k1.hashes.sha256 = sha256;
    const prevSync = secp256k1.hashes.hmacSha256;
    try {
      secp256k1.hashes.hmacSha256 = () => new Uint8Array([1, 2, 3]);
      throws(() => secp256k1.sign(msg, secretKey), /digest/);
    } finally {
      secp256k1.hashes.hmacSha256 = prevSync;
      secp256k1.hashes.sha256 = prevSha;
    }
    const prevAsync = secp256k1.hashes.hmacSha256Async;
    try {
      secp256k1.hashes.hmacSha256Async = async () => new Uint8Array([1, 2, 3]);
      await rejects(() => secp256k1.signAsync(msg, secretKey), /digest/);
    } finally {
      secp256k1.hashes.hmacSha256Async = prevAsync;
    }
  });
});

it.runWhen(import.meta.url);
