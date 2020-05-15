import { getPublicKey, sign, verify, utils, CURVE, Point } from './index.ts';
import { hmac } from "https://denopkg.com/chiefbiiko/hmac/mod.ts";

utils.sha512 = async (message: Uint8Array): Promise<Uint8Array> => {
  return new SHA512().update(message).digest() as Uint8Array;
};

export { getPublicKey, sign, verify, utils, CURVE, Point, ExtendedPoint };
