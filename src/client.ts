import * as assert from "assert";
import * as bn from "./bignum";
import {assertIsBuffer, getClientS, equal, getA, getK, getk, getM1, getM2, getu, getx} from "./srp";
import {Params, PARAMS} from "./params";
import {BigInteger} from "jsbn";

const ZERO_BUF = Buffer.allocUnsafe(0);

export interface ClientData {
  params: Params;
  k: BigInteger;
  x: BigInteger;
  a: BigInteger;
  A: Buffer;
  K?: Buffer;
  M1?: Buffer;
  M2?: Buffer;
  u?: BigInteger;
  S?: Buffer;
}

export class Client {
  private readonly _data: ClientData;

  static create(bits, salt, identity, password, secret) {
    return new Client(bits, salt, identity, password, secret);
  }

  get data() {
    return this._data;
  }

  constructor(params: number | Params, salt, identity, password, secret) {
    assertIsBuffer(salt, "salt (salt)");
    assertIsBuffer(identity, "identity (I)");
    assertIsBuffer(password, "password (P)");
    assertIsBuffer(secret, "secret");

    params = typeof params === 'number' ? PARAMS[params] : params;
    this._data = {
      params: params,
      k: getk(params),
      x: getx(params, salt, identity, password),
      a: bn.fromBuffer(secret),
      A: ZERO_BUF
    };
    this._data.A = getA(params, this._data.a);
  }

  computeA() {
    return this._data.A;
  }

  setB(B) {
    const data = this._data;
    const B_num = bn.fromBuffer(B);
    const u = getu(data.params, data.A, B);
    const S = getClientS(data.params, data.k, data.x, data.a, B_num, u);
    data.K = getK(data.params, S);
    data.M1 = getM1(data.params, data.A, B, S);
    data.M2 = getM2(data.params, data.A, data.M1, data.K);
    data.S = S; // only for tests
    data.u = u; // only for tests
  }

  computeM1() {
    if (this._data.M1 === undefined)
      throw new Error("incomplete protocol");
    return this._data.M1;
  }

  checkM2(target: ArrayLike<any>) {
    if (!equal(this._data.M2, target))
      throw new Error("server is not authentic");
  }

  computeK() {
    if (this._data.K === undefined)
      throw new Error("incomplete protocol");
    return this._data.K;
  }
}
