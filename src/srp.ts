import * as assert from 'assert';
import * as bn from './bignum';
import {sha} from "./sha";
import {randomBytes} from "./random";
import {Params, PARAMS} from "./params";
import {BigInteger} from "jsbn";

const zero = bn.create(0);

function _assert(val: any, msg: string) {
  if (!val) throw new Error(msg || "assertion");
}

/*
 * If a conversion is explicitly specified with the operator PAD(),
 * the integer will first be implicitly converted, then the resultant
 * byte-string will be left-padded with zeros (if necessary) until its
 * length equals the implicitly-converted length of N.
 *
 * params:
 *         n (buffer)       Number to pad
 *         len (int)        length of the resulting Buffer
 *
 * returns: buffer
 */
function padTo(n, len): Buffer {
  assertIsBuffer(n, "n");
  const padding = len - n.length;
  _assert(padding > -1, "Negative padding.  Very uncomfortable.");
  const result = new Buffer(len);
  result.fill(0, 0, padding);
  n.copy(result, padding);
  assert.strictEqual(result.length, len);
  return result;
}

function padToN(n: BigInteger, params: Params): Buffer {
  assertIsBN(n);
  return padTo(n.toBuffer(), params.N_length_bits / 8);
}

function padToH(n: BigInteger, params: Params) {
  assertIsBN(n);
  let bits;
  if (params.hash === "sha1")
    bits = 160;
  else if (params.hash === "sha256")
    bits = 256;
  else if (params.hash === "sha512")
    bits = 512;
  else
    throw Error("cannot determine length of hash '" + params.hash + "'");

  return padTo(n.toBuffer(), bits / 8);
}

export function assertIsBuffer(arg: any, name: string) {
  name = name || "arg";
  _assert(Buffer.isBuffer(arg), "Type error: " + name + " must be a buffer");
}

export function assertIsNBuffer(arg: any, params: Params, name: string) {
  name = name || "arg";
  _assert(Buffer.isBuffer(arg), "Type error: " + name + " must be a buffer");
  if (arg.length != params.N_length_bits / 8)
    _assert(false, name + " was " + arg.length + ", expected " + (params.N_length_bits / 8));
}

export function assertIsBN(arg: any) {
  assert.strictEqual(arg.__bignum, true);
}

/*
 * compute the intermediate value x as a hash of three buffers:
 * salt, identity, and password.  And a colon.  FOUR buffers.
 *
 *      x = H(s | H(I | ":" | P))
 *
 * params:
 *         salt (buffer)    salt
 *         I (buffer)       user identity
 *         P (buffer)       user password
 *
 * returns: x (bignum)      user secret
 */
export function getx(params: Params, salt: Buffer, I: Buffer, P: Buffer): BigInteger {
  assertIsBuffer(salt, "salt (salt)");
  assertIsBuffer(I, "identity (I)");
  assertIsBuffer(P, "password (P)");
  const hashIP = sha(params.hash)
    .update(Buffer.concat([I, Buffer.from(':'), P]))
    .digest();
  const hashX = sha(params.hash)
    .update(salt)
    .update(hashIP)
    .digest();
  return bn.fromBuffer(hashX);
}

/*
 * The verifier is calculated as described in Section 3 of [SRP-RFC].
 * We give the algorithm here for convenience.
 *
 * The verifier (v) is computed based on the salt (s), user name (I),
 * password (P), and group parameters (N, g).
 *
 *         x = H(s | H(I | ":" | P))
 *         v = g^x % N
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         salt (buffer)    salt
 *         I (buffer)       user identity
 *         P (buffer)       user password
 *
 * returns: buffer
 */
export function computeVerifier(params: number | Params, salt: Buffer, I: Buffer, P: Buffer): Buffer {
  assertIsBuffer(salt, "salt (salt)");
  assertIsBuffer(I, "identity (I)");
  assertIsBuffer(P, "password (P)");

  params = typeof params === 'number' ? PARAMS[params]: params;
  const v = params.g.powm(getx(params, salt, I, P), params.N);
  return padToN(v, params);
}

/*
 * calculate the SRP-6 multiplier
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *
 * returns: bignum
 */
export function getk(params: Params) {
  const k = sha(params.hash)
    .update(padToN(params.N, params))
    .update(padToN(params.g, params))
    .digest();
  return bn.fromBuffer(k);
}

/*
 * Generate a random key
 *
 * params:
 *         bytes (int)      length of key (default=32)
 *         callback (func)  function to call with err,key
 *
 * returns: nothing, but runs callback with a Buffer
 */
export async function genKey(bytes: number = 32): Promise<Buffer> {
  return randomBytes(bytes);
}

/*
 * The server key exchange message also contains the server's public
 * value (B).  The server calculates this value as B = k*v + g^b % N,
 * where b is a random number that SHOULD be at least 256 bits in length
 * and k = H(N | PAD(g)).
 *
 * Note: as the tests imply, the entire expression is mod N.
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         v (bignum)       verifier (stored)
 *         b (bignum)       server secret exponent
 *
 * returns: B (buffer)      the server public message
 */
export function getB(params: Params, k: BigInteger, v: BigInteger, b: BigInteger): Buffer {
  assertIsBN(v);
  assertIsBN(k);
  assertIsBN(b);
  const N = params.N;
  const r = k.mul(v).add(params.g.powm(b, N)).mod(N);
  return padToN(r, params);
}

/*
 * The client key exchange message carries the client's public value
 * (A).  The client calculates this value as A = g^a % N, where a is a
 * random number that SHOULD be at least 256 bits in length.
 *
 * Note: for this implementation, we take that to mean 256/8 bytes.
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         a (bignum)       client secret exponent
 *
 * returns A (bignum)       the client public message
 */
export function getA(params: Params, a: BigInteger): Buffer {
  assertIsBN(a);
  if (Math.ceil(a.bitLength() / 8) < 256 / 8) {
    console.warn("getA: client key length", a.bitLength(), "is less than the recommended 256");
  }
  return padToN(params.g.powm(a, params.N), params);
}

/*
 * getu() hashes the two public messages together, to obtain a scrambling
 * parameter "u" which cannot be predicted by either party ahead of time.
 * This makes it safe to use the message ordering defined in the SRP-6a
 * paper, in which the server reveals their "B" value before the client
 * commits to their "A" value.
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         A (Buffer)       client ephemeral public key
 *         B (Buffer)       server ephemeral public key
 *
 * returns: u (bignum)      shared scrambling parameter
 */
export function getu(params: Params, A: Buffer, B: Buffer): BigInteger {
  assertIsNBuffer(A, params, "A");
  assertIsNBuffer(B, params, "B");
  const u = sha(params.hash)
    .update(A).update(B)
    .digest();
  return bn.fromBuffer(u);
}

/*
 * The TLS premaster secret as calculated by the client
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         salt (buffer)    salt (read from server)
 *         I (buffer)       user identity (read from user)
 *         P (buffer)       user password (read from user)
 *         a (bignum)       ephemeral private key (generated for session)
 *         B (bignum)       server ephemeral public key (read from server)
 *
 * returns: buffer
 */

export function getClientS(params: Params, k: BigInteger, x: BigInteger, a: BigInteger, B: BigInteger, u: BigInteger): Buffer {
  assertIsBN(k);
  assertIsBN(x);
  assertIsBN(a);
  assertIsBN(B);
  assertIsBN(u);
  const g = params.g;
  const N = params.N;
  if (zero.ge(B) || N.le(B))
    throw new Error("invalid server-supplied 'B', must be 1..N-1");
  const S = B.sub(k.mul(g.powm(x, N))).powm(a.add(u.mul(x)), N).mod(N);
  return padToN(S, params);
}

/*
 * The TLS premastersecret as calculated by the server
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         v (bignum)       verifier (stored on server)
 *         A (bignum)       ephemeral client public key (read from client)
 *         b (bignum)       server ephemeral private key (generated for session)
 *
 * returns: bignum
 */

export function getServerS(params: Params, v: BigInteger, A: BigInteger, b: BigInteger, u: BigInteger): Buffer {
  assertIsBN(v);
  assertIsBN(A);
  assertIsBN(b);
  assertIsBN(u);
  const N = params.N;
  if (zero.ge(A) || N.le(A))
    throw new Error("invalid client-supplied 'A', must be 1..N-1");
  const S = A.mul(v.powm(u, N)).powm(b, N).mod(N);
  return padToN(S, params);
}

/*
 * Compute the shared session key K from S
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         S (buffer)       Session key
 *
 * returns: buffer
 */
export function getK(params: Params, S: Buffer): Buffer {
  assertIsNBuffer(S, params, "S");
  return sha(params.hash)
    .update(S)
    .digest();
}

export function getM1(params: Params, A: Buffer, B: Buffer, S: Buffer): Buffer {
  assertIsNBuffer(A, params, "A");
  assertIsNBuffer(B, params, "B");
  assertIsNBuffer(S, params, "S");
  return sha(params.hash)
    .update(A).update(B).update(S)
    .digest();
}

export function getM2(params: Params, A: Buffer, M: Buffer, K: Buffer): Buffer {
  assertIsNBuffer(A, params, "A");
  assertIsBuffer(M, "M");
  assertIsBuffer(K, "K");
  return sha(params.hash)
    .update(A).update(M).update(K)
    .digest();
}

export function equal(buf1?: ArrayLike<number>, buf2?: ArrayLike<number>): boolean {
  if (buf1 == null && buf2 == null) {
    return true;
  }

  if ((buf1 == null && buf2 != null) || (buf1 != null && buf2 == null)) {
    return false;
  }

  buf1 = <Buffer>buf1;
  buf2 = <Buffer>buf2;

  // constant-time comparison. A drop in the ocean compared to our
  // non-constant-time modexp operations, but still good practice.
  let mismatch = buf1.length - buf2.length;
  if (mismatch) {
    return false;
  }
  for (let i = 0; i < buf1.length; i++) {
    mismatch |= buf1[i] ^ buf2[i];
  }
  return mismatch === 0;
}
