import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, throws } from 'node:assert';
import * as secp256k1 from '../index.ts';

const filled = (value: number) => new Uint8Array(32).fill(value);

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

  it('signAsync() snapshots a prehashed message before its first await', async () => {
    const stateA = filled(0x41);
    const stateB = filled(0x42);
    const message = stateA.slice();
    const secretKey = filled(7);
    const publicKey = secp256k1.getPublicKey(secretKey);
    const signing = secp256k1.signAsync(message, secretKey, { prehash: false });
    message.set(stateB);
    const signature = await signing;
    eql(message, stateB, 'test mutation occurred');
    eql(
      secp256k1.verify(signature, stateA, publicKey, { prehash: false }),
      true,
      'bound to invocation-time state'
    );
    eql(
      secp256k1.verify(signature, stateB, publicKey, { prehash: false }),
      false,
      'not bound to mutated state'
    );
  });

  it('signAsync() snapshots the secret key and extra entropy before its first await', async () => {
    const message = filled(9);
    const secretA = filled(7);
    const secretB = filled(8);
    const entropyA = filled(0x31);
    const entropyB = filled(0x32);
    const secretKey = secretA.slice();
    const extraEntropy = entropyA.slice();
    const signing = secp256k1.signAsync(message, secretKey, {
      prehash: false,
      extraEntropy,
    });
    secretKey.set(secretB);
    extraEntropy.set(entropyB);
    const signature = await signing;
    const expected = await secp256k1.signAsync(message, secretA, {
      prehash: false,
      extraEntropy: entropyA,
    });
    eql(signature, expected, 'bound to invocation-time secret key and entropy');
    eql(
      secp256k1.verify(signature, message, secp256k1.getPublicKey(secretA), { prehash: false }),
      true
    );
    eql(
      secp256k1.verify(signature, message, secp256k1.getPublicKey(secretB), { prehash: false }),
      false
    );
  });

  it('verifyAsync() and recoverPublicKeyAsync() snapshot inputs before their first await', async () => {
    const message = filled(0x41);
    const secretKey = filled(7);
    const publicKey = secp256k1.getPublicKey(secretKey);
    const recoveredSig = await secp256k1.signAsync(message, secretKey, {
      prehash: false,
      format: 'recovered',
    });

    const verifySig = recoveredSig.slice();
    const verifyMsg = message.slice();
    const verifyPub = publicKey.slice();
    const verifying = secp256k1.verifyAsync(verifySig, verifyMsg, verifyPub, {
      prehash: false,
      format: 'recovered',
    });
    verifySig.fill(0);
    verifyMsg.fill(0x42);
    verifyPub.fill(0);
    eql(await verifying, true, 'verification uses invocation-time bytes');

    const recoverSig = recoveredSig.slice();
    const recoverMsg = message.slice();
    const recoverOpts = { prehash: false, isCompressed: true };
    const recovering = secp256k1.recoverPublicKeyAsync(recoverSig, recoverMsg, recoverOpts);
    recoverSig.fill(0);
    recoverMsg.fill(0x42);
    recoverOpts.isCompressed = false;
    eql(await recovering, publicKey, 'recovery uses invocation-time bytes');
  });

  it('async ECDSA validates bounded inputs before copying them', async () => {
    const copyMustNotRun = (length: number) => {
      const bytes = new Uint8Array(length);
      Object.defineProperty(bytes, Symbol.iterator, {
        value: () => {
          throw new Error('copied before validation');
        },
      });
      return bytes;
    };
    const message = filled(9);
    const secretKey = filled(7);
    const publicKey = secp256k1.getPublicKey(secretKey);
    const signature = await secp256k1.signAsync(message, secretKey, { prehash: false });
    const recovered = await secp256k1.signAsync(message, secretKey, {
      prehash: false,
      format: 'recovered',
    });

    await rejects(() => secp256k1.signAsync(message, copyMustNotRun(33)), /length 32/);
    await rejects(() => secp256k1.verifyAsync(copyMustNotRun(66), message, publicKey), /length 64/);
    eql(await secp256k1.verifyAsync(signature, message, copyMustNotRun(66)), false);
    await rejects(() => secp256k1.recoverPublicKeyAsync(copyMustNotRun(66), message), /length 65/);
    eql(
      await secp256k1.verifyAsync(signature, copyMustNotRun(8193), publicKey, {
        prehash: false,
      }),
      false
    );
    await rejects(
      () => secp256k1.recoverPublicKeyAsync(recovered, copyMustNotRun(8193), { prehash: false }),
      /input is too large/
    );
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

  it('schnorr.sign() snapshots the message before re-entrant hashing', () => {
    const originalHash = secp256k1.hashes.sha256;
    const stateA = filled(0x41);
    const stateB = filled(0x42);
    const message = stateA.slice();
    const secretKey = filled(7);
    const auxRand = new Uint8Array(32);
    const publicKey = secp256k1.schnorr.getPublicKey(secretKey);
    let calls = 0;
    try {
      secp256k1.hashes.sha256 = (data) => {
        const digest = sha256(data);
        if (++calls === 4) message.set(stateB);
        return digest;
      };
      const signature = secp256k1.schnorr.sign(message, secretKey, auxRand);
      eql(calls, 8, 'aux, nonce, challenge, and self-verification tagged hashes');
      eql(message, stateB, 'test mutation occurred');
      secp256k1.hashes.sha256 = sha256;
      eql(
        secp256k1.schnorr.verify(signature, stateA, publicKey),
        true,
        'bound to invocation-time state'
      );
      eql(
        secp256k1.schnorr.verify(signature, stateB, publicKey),
        false,
        'not bound to mutated state'
      );
    } finally {
      secp256k1.hashes.sha256 = originalHash;
    }
  });

  it('schnorr.signAsync() snapshots the message across awaited hashing', async () => {
    const originalHash = secp256k1.hashes.sha256;
    const originalHashAsync = secp256k1.hashes.sha256Async;
    const stateA = filled(0x41);
    const stateB = filled(0x42);
    const message = stateA.slice();
    const secretKey = filled(7);
    const auxRand = new Uint8Array(32);
    const publicKey = secp256k1.schnorr.getPublicKey(secretKey);
    let calls = 0;
    let nonceStarted: (() => void) | undefined;
    let resumeNonce: (() => void) | undefined;
    const started = new Promise<void>((resolve) => (nonceStarted = resolve));
    const resume = new Promise<void>((resolve) => (resumeNonce = resolve));
    try {
      secp256k1.hashes.sha256Async = async (data) => {
        const digest = sha256(data);
        if (++calls === 4) {
          nonceStarted!();
          await resume;
        }
        return digest;
      };
      const signing = secp256k1.schnorr.signAsync(message, secretKey, auxRand);
      await started;
      message.set(stateB);
      resumeNonce!();
      const signature = await signing;
      eql(calls, 8, 'aux, nonce, challenge, and self-verification tagged hashes');
      eql(message, stateB, 'test mutation occurred');
      secp256k1.hashes.sha256 = sha256;
      eql(
        secp256k1.schnorr.verify(signature, stateA, publicKey),
        true,
        'bound to invocation-time state'
      );
      eql(
        secp256k1.schnorr.verify(signature, stateB, publicKey),
        false,
        'not bound to mutated state'
      );
    } finally {
      resumeNonce?.();
      secp256k1.hashes.sha256 = originalHash;
      secp256k1.hashes.sha256Async = originalHashAsync;
    }
  });
});

it.runWhen(import.meta.url);
