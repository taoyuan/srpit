import {randomBytes as _randomBytes} from "crypto";

export async function randomBytes(size): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    _randomBytes(size, (err, result) => {
      if (err) return reject(err);
      resolve(result);
    })
  });
}

