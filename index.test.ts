import * as fc from "fast-check";
import * as secp256k1 from "./index";
const SignResult = secp256k1.SignResult;

const bigIntToHex = (num: bigint): string => {
  let hex = num.toString(16);
  if (hex.length < 64) hex = hex.padStart(64, "0");
  return hex;
};

const PRIVATE_KEY = bigIntToHex(
  60915644994268724639141444668491785949011881302943832872016721211779089794926n
);
const MESSAGE = "63262f29f0c9c0abc347b5c519f646d6ff683760";
const WRONG_MESSAGE = "ab9c7f26c71e9d442bccd5fdc9747b3b74c8d587";

const toLEHex = (n: bigint) =>
  n
    .toString(16)
    .padStart(64, "0")
    .replace(/\w\w/gi, a => `${a},`)
    .split(",")
    .reverse()
    .slice(1)
    .join("");

describe("secp256k1", () => {
  it("should verify just signed message", () => {
    fc.assert(
      fc.property(
        fc.hexa(),
        fc.bigInt(1n, secp256k1.PRIME_ORDER),
        (message, privateKey) => {
          const signature = secp256k1.sign(message, privateKey);
          const publicKey = secp256k1.getPublicKey(privateKey).toHex(true);
          expect(publicKey.length).toBe(66);
          expect(secp256k1.verify(signature, message, publicKey)).toBe(true);
        }
      )
    );
  });
  it("should not verify sign with wrong message", () => {
    fc.assert(
      fc.property(
        fc.hexa(),
        fc.hexa(),
        fc.bigInt(1n, secp256k1.PRIME_ORDER),
        (message, wrongMessage, privateKey) => {
          const signature = secp256k1.sign(message, privateKey);
          const publicKey = secp256k1.getPublicKey(privateKey);
          expect(secp256k1.verify(signature, wrongMessage, publicKey)).toBe(
            message === wrongMessage
          );
        }
      )
    );
  });
  it("should decode right encoded point with compresed hex", () => {
    fc.assert(
      fc.property(
        fc.bigUint(secp256k1.PRIME_ORDER),
        fc.integer(2, 3),
        (x, prefix) => {
          const compresedHex = `0${prefix}${toLEHex(x)}`;
          const point = secp256k1.Point.fromHex(compresedHex);
          expect(point.toHex(true)).toBe(compresedHex);
        }
      )
    );
  });
  it("should decode right encoded signature with hex", () => {
    fc.assert(
      fc.property(
        fc.bigUint(secp256k1.PRIME_ORDER),
        fc.bigUint(secp256k1.PRIME_ORDER),
        (r, s) => {
          const signature = new secp256k1.SignResult(r, s);
          const hex = signature.toHex();
          expect(SignResult.fromHex(hex)).toEqual(signature);
        }
      )
    );
  });
  it("should resove valid curve point", () => {
    fc.assert(
      fc.property(
        fc.bigUint(secp256k1.PRIME_ORDER),
        fc.integer(2, 3),
        (x, prefix) => {
          const compresedHex = `0${prefix}${toLEHex(x)}`;
          const point = secp256k1.Point.fromHex(compresedHex);
          const uncompressedHex = point.toHex();
          expect(secp256k1.Point.fromHex(uncompressedHex)).toEqual(point);
        }
      )
    );
  });
  it("should reject invalid curve point", () => {
    fc.assert(
      fc.property(
        fc.bigUint(secp256k1.PRIME_ORDER),
        fc.integer(2, 3),
        (x, prefix) => {
          const compresedHex = `0${prefix}${toLEHex(x)}`;
          const point = secp256k1.Point.fromHex(compresedHex);
          point.x = secp256k1.PRIME_ORDER + 6n;
          const uncompressedHex = point.toHex();
          expect(() => secp256k1.Point.fromHex(uncompressedHex)).toThrow(
            new Error("secp256k1: Point is not on elliptic curve")
          );
        }
      )
    );
  });
  it("should recovery public key from recovery bit", () => {
    fc.assert(
      fc.property(
        fc.hexa(),
        fc.bigInt(1n, secp256k1.PRIME_ORDER),
        (message, privateKey) => {
          const [signature, recovery] = secp256k1.sign(message, privateKey, { recovered: true });
          const recoveredPublicKey = secp256k1.recoverPublicKey(message, signature, recovery);
          const publicKey = secp256k1.getPublicKey(privateKey);
          expect(recoveredPublicKey).not.toBe(null);
          expect(secp256k1.verify(signature, message, publicKey)).toBe(true);
        }
      )
    );
  });
  it("should sign and verify", () => {
    const signature = secp256k1.sign(MESSAGE, PRIVATE_KEY);
    const publicKey = secp256k1.getPublicKey(PRIVATE_KEY, true);
    expect(publicKey.length).toBe(66);
    expect(secp256k1.verify(signature, MESSAGE, publicKey)).toBe(true);
  });
  it("should not verify signature with wrong public key", () => {
    const signature = secp256k1.sign(MESSAGE, PRIVATE_KEY);
    const publicKey = secp256k1.getPublicKey(12).toHex(true);
    expect(publicKey.length).toBe(66);
    expect(secp256k1.verify(signature, MESSAGE, publicKey)).toBe(false);
  });
  it("should not verify signature with wrong hash", () => {
    const signature = secp256k1.sign(MESSAGE, PRIVATE_KEY);
    const publicKey = secp256k1.getPublicKey(PRIVATE_KEY, true);
    expect(publicKey.length).toBe(66);
    expect(secp256k1.verify(signature, WRONG_MESSAGE, publicKey)).toBe(false);
  });
  it("should create right signature for TEST VECTOR 1", () => {
    const k = 88005553535n;
    const privateKey = 52179536764755337545612199095990232116695286674335986683196321064261036834363n;
    const message = new Uint8Array([]);
    const publicKey = secp256k1.getPublicKey(privateKey).toHex(true);
    const signature = SignResult.fromHex(secp256k1.sign(message, privateKey, { k }));
    expect(publicKey).toBe("02e957ff73876ed52eae898a6223866783d43ab12f91c8ddc7c0317dd74c1509fd");
    expect(signature.r.toString(16)).toBe("cf3cde1e07861eb16117b5c79fcce067a3c4bb0410126e4acd9c39fb9f848b8a");
    expect(signature.s.toString(16)).toBe("feaf86fbe4d36eca248b5376e64ea72b7db29663ccb8ea410e09ebf96f22511f");
    expect(secp256k1.verify(signature, message, publicKey)).toBe(true);
  });
  it("should create right signature for TEST VECTOR 2", () => {
    const k = 455128135n;
    const privateKey = 28163224383907981895957726884843002432056516602481622413775195760927139115301n;
    const message = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const publicKey = secp256k1.getPublicKey(privateKey).toHex(true);
    const signature = SignResult.fromHex(secp256k1.sign(message.reverse(), privateKey, { k }));
    expect(publicKey).toBe("038e9d2a3d55cd703ad6a66c23a27f85d47f895a45afa7f327cb9f1926314c829c");
    expect(signature.r.toString(16)).toBe("ae64bb3fca49db620ca62db8abc78ec7bf8baa16f105f9bbabb8e113b46976f0");
    expect(signature.s.toString(16)).toBe("a5f95bf4fbe39fe2e9ed4338f19282466fd59c1fe41caa81d150b23930a8183b");
    expect(secp256k1.verify(signature, message, publicKey)).toBe(true);
  });
  it("should create right signature for TEST VECTOR 3", () => {
    const k = 9379992n;
    const privateKey = 17371927689979660365655983724961483924512590677652725421570212323241872772858n;
    const message = new Uint8Array([11, 220, 157, 45, 37, 107, 62, 233, 218, 174, 52, 123, 230, 244, 220, 131, 90, 70, 127, 254]);
    const publicKey = secp256k1.getPublicKey(privateKey).toHex(true);
    const signature = SignResult.fromHex(secp256k1.sign(message.reverse(), privateKey, { k }));
    expect(publicKey).toBe("02b59710f9cfcee4c43032d600004d39902dc2574e9a389c742dd4a1ed30a2b6cc");
    expect(signature.r.toString(16)).toBe("21f7506d30791c6dddd41e9b50aaafd34413517ae26d3a1f03fc79075142be6f");
    expect(signature.s.toString(16)).toBe("d3f621c612a7224ceb3b89c4bbbd087a545b84504cfc96e8054958c19113c3d9");
    expect(secp256k1.verify(signature, message, publicKey)).toBe(true);
  });
  it("should create right signature for TEST VECTOR 4", () => {
    const k = 0xdeadbeafn;
    const privateKey = 78671493187874088132994244235828421211366948348464548136778854069460533125502n;
    const publicKey = secp256k1.getPublicKey(privateKey).toHex(true);
    const message = new Uint8Array([8,184,178,183,51,66,66,67,118,15,228,38,164,181,73,8,99,33,16,166,108,47,101,145,234,189,51,69,227,228,235,152,250,110,38,75,240,158,254,18,238,80,248,245,78,159,119,177,227,85,246,197,5,68,226,63,177,67,61,223,115,190,132,216,121,222,124,0,70,220,73,150,217,231,115,244,188,158,254,87,56,130,154,219,38,200,27,55,201,58,27,39,11,32,50,157,101,134,117,252,110,165,52,224,129,10,68,50,130,107,245,140,148,30,251,101,213,122,51,139,189,46,38,100,15,137,255,188,26,133,142,252,184,85,14,227,165,225,153,139,209,119,233,58,115,99,195,68,254,107,25,158,229,208,46,130,213,34,196,254,186,21,69,47,128,40,138,130,26,87,145,22,236,109,173,43,59,49,13,169,3,64,26,166,33,0,171,93,26,54,85,62,6,32,59,51,137,12,201,184,50,247,158,248,5,96,204,185,163,156,231,103,150,126,214,40,198,173,87,60,177,22,219,239,239,215,84,153,218,150,189,104,168,169,123,146,138,139,188,16,59,102,33,252,222,43,236,161,35,29,32,107,230,205,158,199,175,246,246,201,79,205,114,4,237,52,85,198,140,131,244,164,29,164,175,43,116,239,92,83,241,216,172,112,189,203,126,209,133,206,129,189,132,53,157,68,37,77,149,98,158,152,85,169,74,124,25,88,209,248,173,165,208,83,46,216,165,170,63,178,209,123,167,14,182,36,142,89,78,26,34,151,172,187,179,157,80,47,26,140,110,182,241,206,34,179,222,26,31,64,204,36,85,65,25,168,49,169,170,214,7,156,173,136,66,93,230,189,225,169,24,126,187,96,146,207,103,191,43,19,253,101,242,112,136,215,139,126,136,60,135,89,210,196,245,198,90,219,117,83,135,138,213,117,249,250,216,120,232,10,12,155,166,59,203,204,39,50,230,148,133,187,201,201,11,251,214,36,129,217,8,155,236,207,128,207,226,223,22,162,207,101,189,146,221,89,123,7,7,224,145,122,244,139,187,117,254,212,19,210,56,245,85,90,122,86,157,128,195,65,74,141,8,89,220,101,164,97,40,186,178,122,248,122,113,49,79,49,140,120,43,35,235,254,128,139,130,176,206,38,64,29,46,34,240,77,131,209,37,93,197,26,221,211,183,90,43,26,224,120,69,4,223,84,58,248,150,155,227,234,112,130,255,127,201,136,140,20,77,162,175,88,66,158,201,96,49,219,202,211,218,217,175,13,203,170,175,38,140,184,252,255,234,217,79,60,124,164,149,224,86,169,180,122,205,183,81,251,115,230,102,198,198,85,173,232,41,114,151,208,122,209,186,94,67,241,188,163,35,1,101,19,57,226,41,4,204,140,66,245,140,48,192,74,175,219,3,141,218,8,71,221,152,141,205,166,243,191,209,92,75,76,69,37,0,74,160,110,239,248,202,97,120,58,172,236,87,251,61,31,146,176,254,47,209,168,95,103,36,81,123,101,230,20,173,104,8,214,246,238,52,223,247,49,15,220,130,174,191,217,4,176,30,29,197,75,41,39,9,75,45,182,141,111,144,59,104,64,26,222,191,90,126,8,215,143,244,239,93,99,101,58,101,4,12,249,191,212,172,167,152,74,116,211,113,69,152,103,128,252,11,22,172,69,22,73,222,97,136,167,219,223,25,31,100,181,252,94,42,180,123,87,247,247,39,108,212,25,193,122,60,168,225,185,57,174,73,228,136,172,186,107,150,86,16,181,72,1,9,200,177,123,128,225,183,183,80,223,199,89,141,93,80,17,253,45,204,86,0,163,46,245,181,42,30,204,130,14,48,138,163,66,114,26,172,9,67,191,102,134,182,75,37,121,55,101,4,204,196,147,217,126,106,237,63,176,249,205,113,164,61,212,151,240,31,23,192,226,203,55,151,170,42,47,37,102,86,22,142,108,73,106,252,95,185,50,70,246,177,17,99,152,163,70,241,166,65,243,176,65,233,137,247,145,79,144,204,44,127,255,53,120,118,229,6,181,13,51,75,167,124,34,91,195,7,186,83,113,82,243,241,97,14,78,175,229,149,246,217,217,13,17,250,169,51,161,94,241,54,149,70,134,138,127,58,69,169,103,104,212,15,217,208,52,18,192,145,198,49,92,244,253,231,203,104,96,105,55,56,13,178,234,170,112,123,76,65,133,195,46,221,205,211,6,112,94,77,193,255,200,114,238,238,71,90,100,223,172,134,171,164,28,6,24,152,63,135,65,197,239,104,211,161,1,232,163,184,202,198,12,144,92,21,252,145,8,64,185,76,0,160,185,208]);
    const signature = SignResult.fromHex(secp256k1.sign(message.reverse(), privateKey, { k }));
    expect(publicKey).toBe("038bbf959f30d2181235cf47a6766daa7e633c6c15d177bceac96da2abee1dec13");
    expect(signature.r.toString(16)).toBe("18890b33eab6bb64cefae530401025664a289b9971a5df97c0d11071b93fb7c3");
    expect(signature.s.toString(16)).toBe("d1a08bae4572606f8e924863f454b554179df440524e6a1eecf8512aba8a5601");
    expect(secp256k1.verify(signature, message, publicKey)).toBe(true);
  });
  it("should create right canonical signature for TEST VECTOR 1", () => {
    const k = 88005553535n;
    const privateKey = 52179536764755337545612199095990232116695286674335986683196321064261036834363n;
    const message = new Uint8Array([]);
    const publicKey = secp256k1.getPublicKey(privateKey).toHex(true);
    const signature = SignResult.fromHex(secp256k1.sign(message, privateKey, { k, canonical: true }));
    expect(publicKey).toBe("02e957ff73876ed52eae898a6223866783d43ab12f91c8ddc7c0317dd74c1509fd");
    expect(signature.r.toString(16)).toBe("cf3cde1e07861eb16117b5c79fcce067a3c4bb0410126e4acd9c39fb9f848b8a");
    expect(signature.s.toString(16)).toBe("15079041b2c9135db74ac8919b158d33cfc4682e28fb5fab1c872936113f022");
    expect(secp256k1.verify(signature, message, publicKey)).toBe(true);
  });
  it("should create right canonical signature for TEST VECTOR 2", () => {
    const k = 455128135n;
    const privateKey = 28163224383907981895957726884843002432056516602481622413775195760927139115301n;
    const message = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const publicKey = secp256k1.getPublicKey(privateKey).toHex(true);
    const signature = SignResult.fromHex(secp256k1.sign(message.reverse(), privateKey, { k, canonical: true }));
    expect(publicKey).toBe("038e9d2a3d55cd703ad6a66c23a27f85d47f895a45afa7f327cb9f1926314c829c");
    expect(signature.r.toString(16)).toBe("ae64bb3fca49db620ca62db8abc78ec7bf8baa16f105f9bbabb8e113b46976f0");
    expect(signature.s.toString(16)).toBe("5a06a40b041c601d1612bcc70e6d7db84ad940c6cb2bf5b9ee81ac539f8e2906");
    expect(secp256k1.verify(signature, message, publicKey)).toBe(true);
  });
  it("should create right signature for TEST VECTOR 3", () => {
    const k = 9379992n;
    const privateKey = 17371927689979660365655983724961483924512590677652725421570212323241872772858n;
    const message = new Uint8Array([11, 220, 157, 45, 37, 107, 62, 233, 218, 174, 52, 123, 230, 244, 220, 131, 90, 70, 127, 254]);
    const publicKey = secp256k1.getPublicKey(privateKey).toHex(true);
    const signature = SignResult.fromHex(secp256k1.sign(message.reverse(), privateKey, { k, canonical: true }));
    expect(publicKey).toBe("02b59710f9cfcee4c43032d600004d39902dc2574e9a389c742dd4a1ed30a2b6cc");
    expect(signature.r.toString(16)).toBe("21f7506d30791c6dddd41e9b50aaafd34413517ae26d3a1f03fc79075142be6f");
    expect(signature.s.toString(16)).toBe("2c09de39ed58ddb314c4763b4442f78466535896624c0953ba8905cb3f227d68");
    expect(secp256k1.verify(signature, message, publicKey)).toBe(true);
  });
  it("should create right signature for TEST VECTOR 4", () => {
    const k = 0xdeadbeafn;
    const privateKey = 78671493187874088132994244235828421211366948348464548136778854069460533125502n;
    const publicKey = secp256k1.getPublicKey(privateKey).toHex(true);
    const message = new Uint8Array([8,184,178,183,51,66,66,67,118,15,228,38,164,181,73,8,99,33,16,166,108,47,101,145,234,189,51,69,227,228,235,152,250,110,38,75,240,158,254,18,238,80,248,245,78,159,119,177,227,85,246,197,5,68,226,63,177,67,61,223,115,190,132,216,121,222,124,0,70,220,73,150,217,231,115,244,188,158,254,87,56,130,154,219,38,200,27,55,201,58,27,39,11,32,50,157,101,134,117,252,110,165,52,224,129,10,68,50,130,107,245,140,148,30,251,101,213,122,51,139,189,46,38,100,15,137,255,188,26,133,142,252,184,85,14,227,165,225,153,139,209,119,233,58,115,99,195,68,254,107,25,158,229,208,46,130,213,34,196,254,186,21,69,47,128,40,138,130,26,87,145,22,236,109,173,43,59,49,13,169,3,64,26,166,33,0,171,93,26,54,85,62,6,32,59,51,137,12,201,184,50,247,158,248,5,96,204,185,163,156,231,103,150,126,214,40,198,173,87,60,177,22,219,239,239,215,84,153,218,150,189,104,168,169,123,146,138,139,188,16,59,102,33,252,222,43,236,161,35,29,32,107,230,205,158,199,175,246,246,201,79,205,114,4,237,52,85,198,140,131,244,164,29,164,175,43,116,239,92,83,241,216,172,112,189,203,126,209,133,206,129,189,132,53,157,68,37,77,149,98,158,152,85,169,74,124,25,88,209,248,173,165,208,83,46,216,165,170,63,178,209,123,167,14,182,36,142,89,78,26,34,151,172,187,179,157,80,47,26,140,110,182,241,206,34,179,222,26,31,64,204,36,85,65,25,168,49,169,170,214,7,156,173,136,66,93,230,189,225,169,24,126,187,96,146,207,103,191,43,19,253,101,242,112,136,215,139,126,136,60,135,89,210,196,245,198,90,219,117,83,135,138,213,117,249,250,216,120,232,10,12,155,166,59,203,204,39,50,230,148,133,187,201,201,11,251,214,36,129,217,8,155,236,207,128,207,226,223,22,162,207,101,189,146,221,89,123,7,7,224,145,122,244,139,187,117,254,212,19,210,56,245,85,90,122,86,157,128,195,65,74,141,8,89,220,101,164,97,40,186,178,122,248,122,113,49,79,49,140,120,43,35,235,254,128,139,130,176,206,38,64,29,46,34,240,77,131,209,37,93,197,26,221,211,183,90,43,26,224,120,69,4,223,84,58,248,150,155,227,234,112,130,255,127,201,136,140,20,77,162,175,88,66,158,201,96,49,219,202,211,218,217,175,13,203,170,175,38,140,184,252,255,234,217,79,60,124,164,149,224,86,169,180,122,205,183,81,251,115,230,102,198,198,85,173,232,41,114,151,208,122,209,186,94,67,241,188,163,35,1,101,19,57,226,41,4,204,140,66,245,140,48,192,74,175,219,3,141,218,8,71,221,152,141,205,166,243,191,209,92,75,76,69,37,0,74,160,110,239,248,202,97,120,58,172,236,87,251,61,31,146,176,254,47,209,168,95,103,36,81,123,101,230,20,173,104,8,214,246,238,52,223,247,49,15,220,130,174,191,217,4,176,30,29,197,75,41,39,9,75,45,182,141,111,144,59,104,64,26,222,191,90,126,8,215,143,244,239,93,99,101,58,101,4,12,249,191,212,172,167,152,74,116,211,113,69,152,103,128,252,11,22,172,69,22,73,222,97,136,167,219,223,25,31,100,181,252,94,42,180,123,87,247,247,39,108,212,25,193,122,60,168,225,185,57,174,73,228,136,172,186,107,150,86,16,181,72,1,9,200,177,123,128,225,183,183,80,223,199,89,141,93,80,17,253,45,204,86,0,163,46,245,181,42,30,204,130,14,48,138,163,66,114,26,172,9,67,191,102,134,182,75,37,121,55,101,4,204,196,147,217,126,106,237,63,176,249,205,113,164,61,212,151,240,31,23,192,226,203,55,151,170,42,47,37,102,86,22,142,108,73,106,252,95,185,50,70,246,177,17,99,152,163,70,241,166,65,243,176,65,233,137,247,145,79,144,204,44,127,255,53,120,118,229,6,181,13,51,75,167,124,34,91,195,7,186,83,113,82,243,241,97,14,78,175,229,149,246,217,217,13,17,250,169,51,161,94,241,54,149,70,134,138,127,58,69,169,103,104,212,15,217,208,52,18,192,145,198,49,92,244,253,231,203,104,96,105,55,56,13,178,234,170,112,123,76,65,133,195,46,221,205,211,6,112,94,77,193,255,200,114,238,238,71,90,100,223,172,134,171,164,28,6,24,152,63,135,65,197,239,104,211,161,1,232,163,184,202,198,12,144,92,21,252,145,8,64,185,76,0,160,185,208]);
    const signature = SignResult.fromHex(secp256k1.sign(message.reverse(), privateKey, { k, canonical: true }));
    expect(publicKey).toBe("038bbf959f30d2181235cf47a6766daa7e633c6c15d177bceac96da2abee1dec13");
    expect(signature.r.toString(16)).toBe("18890b33eab6bb64cefae530401025664a289b9971a5df97c0d11071b93fb7c3");
    expect(signature.s.toString(16)).toBe("2e5f7451ba8d9f90716db79c0bab4aaaa310e8a65cfa361cd2da0d6215abeb40");
    expect(secp256k1.verify(signature, message, publicKey)).toBe(true);
  });
});
