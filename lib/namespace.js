const sodium = require('sodium-universal')
const b4a = require('b4a')

module.exports = class Namespace {
  constructor (ns) {
    this.ns = ns

    this._signable = b4a.allocUnsafe(64)
    this._signable.set(ns, 0)
    this._hash = this._signable.subarray(32)
  }

  sign (payload, secretKey, out = b4a.allocUnsafe(64)) {
    sodium.crypto_generichash(this._hash, payload)
    sodium.crypto_sign_detached(out, this._signable, secretKey)
    return out
  }

  verify (signature, payload, publicKey) {
    sodium.crypto_generichash(this._hash, payload)
    return sodium.crypto_sign_verify_detached(signature, this._signable, publicKey)
  }

  hash (payload, out = b4a.allocUnsafe(32)) {
    sodium.crypto_generichash(out, this.ns, payload)
    return out
  }
}
