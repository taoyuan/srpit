import * as crypto from "crypto";

export function sha(hash) {
  return crypto.createHash(hash);
}
