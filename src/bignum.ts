import {BigInteger} from "jsbn";

declare module "jsbn" {
  export interface BigInteger {
    __bignum: boolean;

    toBuffer(): Buffer;

    add(n: number | BigInteger): BigInteger;

    mul(n: number | BigInteger): BigInteger;

    sub(n: number | BigInteger): BigInteger;

    powm(n: number | BigInteger, m: number | BigInteger): BigInteger;

    eq(n: number | BigInteger): boolean;

    ge(n: number | BigInteger): boolean;

    le(n: number | BigInteger): boolean;
  }
}

BigInteger.prototype.__bignum = true;
BigInteger.prototype.toBuffer = function () {
  let h = this.toString(16);

  // Fix odd-length hex values from BigInteger
  if (h.length % 2 === 1) {
    h = '0' + h;
  }

  return new Buffer(h, 'hex');
};

function ensureBI(n: any) {
  if (!n.__bignum) {
    n = create(n);
  }

  return n;
}

const _add = BigInteger.prototype.add;
BigInteger.prototype.add = function (n) {
  return _add.call(this, ensureBI(n));
};

BigInteger.prototype.mul = function (n) {
  return this.multiply(ensureBI(n));
};

BigInteger.prototype.sub = function (n) {
  return this.subtract(ensureBI(n));
};

BigInteger.prototype.powm = function (n, m) {
  return this.modPow(ensureBI(n), ensureBI(m));
};

BigInteger.prototype.eq = function (n) {
  return this.equals(ensureBI(n));
};

BigInteger.prototype.ge = function (n) {
  return this.compareTo(n) >= 0;
};

BigInteger.prototype.le = function (n) {
  return this.compareTo(n) <= 0;
};

export function fromBuffer(b: Buffer): BigInteger {
  const hex = b.toString('hex');
  return new BigInteger(hex, 16);
}

export function create(v: string | number | BigInteger, r?: number): BigInteger {
  return new BigInteger(v.toString(), r)
}
