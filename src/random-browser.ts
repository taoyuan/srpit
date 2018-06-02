import * as _randomBytes from "randombytes/browser";

export async function randomBytes(size): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    _randomBytes(size, (err, result) => {
      if (err) return reject(err);
      resolve(result);
    })
  });
}
