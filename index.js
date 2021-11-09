const sodium = require('sodium-universal')
const c = require('compact-encoding')
const b4a = require('b4a')

// https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
const LEAF_TYPE = b4a.from([0])
const PARENT_TYPE = b4a.from([1])
const ROOT_TYPE = b4a.from([2])
const CAP_TYPE = b4a.from([3])

const HYPERCORE = b4a.from('hypercore')
const HYPERCORE_CAP = b4a.from('hypercore capability')

exports.writerCapability = function (key, secretKey, split) {
  if (!split) return null

  const out = b4a.allocUnsafe(32)
  sodium.crypto_generichash_batch(out, [
    CAP_TYPE,
    HYPERCORE_CAP,
    split.tx.subarray(0, 32),
    key
  ], split.rx.subarray(0, 32))

  return exports.sign(out, secretKey)
}

exports.verifyRemoteWriterCapability = function (key, cap, split) {
  if (!split) return null

  const out = b4a.allocUnsafe(32)
  sodium.crypto_generichash_batch(out, [
    CAP_TYPE,
    HYPERCORE_CAP,
    split.rx.subarray(0, 32),
    key
  ], split.tx.subarray(0, 32))

  return exports.verify(out, cap, key)
}

// TODO: add in the CAP_TYPE in a future version
exports.capability = function (key, split) {
  if (!split) return null

  const out = b4a.allocUnsafe(32)
  sodium.crypto_generichash_batch(out, [
    HYPERCORE_CAP,
    split.tx.subarray(0, 32),
    key
  ], split.rx.subarray(0, 32))

  return out
}

// TODO: add in the CAP_TYPE in a future version
exports.remoteCapability = function (key, split) {
  if (!split) return null

  const out = b4a.allocUnsafe(32)
  sodium.crypto_generichash_batch(out, [
    HYPERCORE_CAP,
    split.rx.subarray(0, 32),
    key
  ], split.tx.subarray(0, 32))

  return out
}

exports.keyPair = function (seed) {
  const publicKey = b4a.allocUnsafe(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.allocUnsafe(sodium.crypto_sign_SECRETKEYBYTES)

  if (seed) sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
  else sodium.crypto_sign_keypair(publicKey, secretKey)

  return {
    publicKey,
    secretKey
  }
}

exports.validateKeyPair = function (keyPair) {
  const pk = b4a.allocUnsafe(sodium.crypto_sign_PUBLICKEYBYTES)
  sodium.crypto_sign_ed25519_sk_to_pk(pk, keyPair.secretKey)
  return pk.equals(keyPair.publicKey)
}

exports.sign = function (message, secretKey) {
  const signature = b4a.allocUnsafe(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, message, secretKey)
  return signature
}

exports.verify = function (message, signature, publicKey) {
  return sodium.crypto_sign_verify_detached(signature, message, publicKey)
}

exports.data = function (data) {
  const out = b4a.allocUnsafe(32)

  sodium.crypto_generichash_batch(out, [
    LEAF_TYPE,
    c.encode(c.uint64, data.byteLength),
    data
  ])

  return out
}

exports.leaf = function (leaf) {
  return exports.data(leaf.data)
}

exports.parent = function (a, b) {
  if (a.index > b.index) {
    const tmp = a
    a = b
    b = tmp
  }

  const out = b4a.allocUnsafe(32)

  sodium.crypto_generichash_batch(out, [
    PARENT_TYPE,
    c.encode(c.uint64, a.size + b.size),
    a.hash,
    b.hash
  ])

  return out
}

exports.tree = function (roots, out) {
  const buffers = new Array(3 * roots.length + 1)
  var j = 0

  buffers[j++] = ROOT_TYPE

  for (var i = 0; i < roots.length; i++) {
    const r = roots[i]
    buffers[j++] = r.hash
    buffers[j++] = c.encode(c.uint64, r.index)
    buffers[j++] = c.encode(c.uint64, r.size)
  }

  if (!out) out = b4a.allocUnsafe(32)
  sodium.crypto_generichash_batch(out, buffers)
  return out
}

exports.signable = function (roots, length) {
  const out = b4a.allocUnsafe(40)

  if (b4a.isBuffer(roots)) b4a.copy(roots, out)
  else exports.tree(roots, out.subarray(0, 32))

  c.uint64.encode({ start: 32, end: 40, buffer: out }, length)

  return out
}

exports.randomBytes = function (n) {
  const buf = b4a.allocUnsafe(n)
  sodium.randombytes_buf(buf)
  return buf
}

exports.discoveryKey = function (publicKey) {
  const digest = b4a.allocUnsafe(32)
  sodium.crypto_generichash(digest, HYPERCORE, publicKey)
  return digest
}

if (sodium.sodium_free) {
  exports.free = function (secureBuf) {
    if (secureBuf.secure) sodium.sodium_free(secureBuf)
  }
} else {
  exports.free = function () {}
}
