const sodium = require('sodium-universal')
const b4a = require('b4a')

module.exports = class Namespace {
  constructor (ns) {
    this.ns = ns
  }

  sign (payload, secretKey, out = b4a.allocUnsafe(64)) {
    const signable = b4a.allocUnsafe(32 + payload.byteLength)
    signable.set(this.ns)
    signable.set(payload, 32)

    sodium.crypto_sign_detached(out, signable, secretKey)

    return out
  }

  verify (signature, payload, publicKey) {
    const signable = b4a.allocUnsafe(32 + payload.byteLength)
    signable.set(this.ns)
    signable.set(payload, 32)

    return sodium.crypto_sign_verify_detached(signature, signable, publicKey)
  }

  hash (payload, out = b4a.allocUnsafe(32)) {
    sodium.crypto_generichash_batch(out, [this.ns, payload])

    return out
  }
}
