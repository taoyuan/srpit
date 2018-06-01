import * as assert from "assert";
import * as bn from "./bignum";
import {assertIsBuffer, equal, getB, getK, getk, getM1, getM2, getu, getServerS} from "./srp";
import {Params, PARAMS} from "./params";
import {BigInteger} from "jsbn";

const ZERO_BUF = Buffer.allocUnsafe(0);

export interface ServerData {
  params: Params;
  k: BigInteger;
  b: BigInteger;
  v: BigInteger;
  B: Buffer;
  K?: Buffer;
  M1?: Buffer;
  M2?: Buffer;
  u?: BigInteger;
  S?: Buffer;
}

export class Server {

  private readonly _data: ServerData;

  static create(bits, verifier, secret) {
    return new Server(bits, verifier, secret);
  }

  constructor(params: number | Params, verifier, secret) {
    assertIsBuffer(verifier, "verifier");
    assertIsBuffer(secret, "secret2");

    params = typeof params === 'number' ? PARAMS[params] : params;
    this._data = {
      params: params,
      k: getk(params),
      b: bn.fromBuffer(secret),
      v: bn.fromBuffer(verifier),
      B: ZERO_BUF
    };
    this._data.B = getB(params, this._data.k, this._data.v, this._data.b);
  }

  get data() {
    return this._data;
  }

  computeB(): Buffer {
    return <Buffer>this._data.B;
  }

  setA(value: Buffer) {
    const data = this._data;
    const A = bn.fromBuffer(value);
    const u = getu(data.params, value, data.B);
    const S = getServerS(data.params, data.v, A, data.b, u);
    data.K = getK(data.params, S);
    data.M1 = getM1(data.params, value, data.B, S);
    data.M2 = getM2(data.params, value, data.M1, data.K);
    data.u = u; // only for tests
    data.S = S; // only for tests
  }

  checkM1(target): Buffer {
    if (this._data.M1 === undefined)
      throw new Error("incomplete protocol");
    if (!equal(this._data.M1, target))
      throw new Error("client did not use the same password");
    return <Buffer>this._data.M2;
  }

  computeK(): Buffer {
    if (this._data.K === undefined)
      throw new Error("incomplete protocol");
    return this._data.K;
  }

}
