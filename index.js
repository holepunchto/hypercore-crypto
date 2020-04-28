const sodium = require('./sodium')
const uint64be = require('uint64be')

// https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
const LEAF_TYPE = Buffer.from([0])
const PARENT_TYPE = Buffer.from([1])
const ROOT_TYPE = Buffer.from([2])

const HYPERCORE = Buffer.from('hypercore')
const HYPERCORE_CAP = Buffer.from('hypercore capability')

exports.capability = function (key, split) {
  if (!split) return null

  const out = Buffer.allocUnsafe(32)
  sodium.crypto_generichash_batch(out, [
    HYPERCORE_CAP,
    split.tx.slice(0, 32),
    key
  ], split.rx.slice(0, 32))

  return out
}

exports.remoteCapability = function (key, split) {
  if (!split) return null

  const out = Buffer.allocUnsafe(32)
  sodium.crypto_generichash_batch(out, [
    HYPERCORE_CAP,
    split.rx.slice(0, 32),
    key
  ], split.tx.slice(0, 32))

  return out
}

exports.keyPair = function (seed) {
  const publicKey = Buffer.allocUnsafe(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = Buffer.allocUnsafe(sodium.crypto_sign_SECRETKEYBYTES)

  if (seed) sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
  else sodium.crypto_sign_keypair(publicKey, secretKey)

  return {
    publicKey,
    secretKey
  }
}

exports.sign = function (message, secretKey) {
  const signature = Buffer.allocUnsafe(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, message, secretKey)
  return signature
}

exports.verify = function (message, signature, publicKey) {
  return sodium.crypto_sign_verify_detached(signature, message, publicKey)
}

exports.data = function (data) {
  return blake2b([
    LEAF_TYPE,
    encodeUInt64(data.length),
    data
  ])
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

  return blake2b([
    PARENT_TYPE,
    encodeUInt64(a.size + b.size),
    a.hash,
    b.hash
  ])
}

exports.tree = function (roots) {
  var buffers = new Array(3 * roots.length + 1)
  var j = 0

  buffers[j++] = ROOT_TYPE

  for (var i = 0; i < roots.length; i++) {
    var r = roots[i]
    buffers[j++] = r.hash
    buffers[j++] = encodeUInt64(r.index)
    buffers[j++] = encodeUInt64(r.size)
  }

  return blake2b(buffers)
}

exports.randomBytes = function (n) {
  var buf = Buffer.allocUnsafe(n)
  sodium.randombytes_buf(buf)
  return buf
}

exports.discoveryKey = function (publicKey) {
  var digest = Buffer.allocUnsafe(32)
  sodium.crypto_generichash(digest, HYPERCORE, publicKey)
  return digest
}

function encodeUInt64 (n) {
  return uint64be.encode(n, Buffer.allocUnsafe(8))
}

function blake2b (buffers) {
  var digest = Buffer.allocUnsafe(32)
  sodium.crypto_generichash_batch(digest, buffers)
  return digest
}
