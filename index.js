const sodium = require('sodium-universal')
const c = require('compact-encoding')
const b4a = require('b4a')

// https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
const LEAF_TYPE = b4a.from([0])
const PARENT_TYPE = b4a.from([1])
const ROOT_TYPE = b4a.from([2])

const HYPERCORE = b4a.from('hypercore')

// Scratch input for the fixed-layout hashes below (type byte, uint64s, child hashes).
// Each use writes it and hashes it synchronously, so no caller can observe it, and no
// per-call array, uint64 buffer or batch call is needed.
const MAX_SCRATCH_ROOTS = 64
const SCRATCH = b4a.allocUnsafeSlow(1 + 48 * MAX_SCRATCH_ROOTS)
const LEAF_HEADER = SCRATCH.subarray(0, 9)
const PARENT_INPUT = SCRATCH.subarray(0, 73)

exports.keyPair = function (seed) {
  // key pairs might stay around for a while, so better not to use a default slab to avoid retaining it completely
  const slab = b4a.allocUnsafeSlow(
    sodium.crypto_sign_PUBLICKEYBYTES + sodium.crypto_sign_SECRETKEYBYTES
  )
  const publicKey = slab.subarray(0, sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = slab.subarray(sodium.crypto_sign_PUBLICKEYBYTES)

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
  return b4a.equals(pk, keyPair.publicKey)
}

exports.sign = function (message, secretKey) {
  // Dedicated slab for the signature, to avoid retaining unneeded mem and for security
  const signature = b4a.allocUnsafeSlow(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, message, secretKey)
  return signature
}

exports.verify = function (message, signature, publicKey) {
  if (signature.byteLength !== sodium.crypto_sign_BYTES) return false
  if (publicKey.byteLength !== sodium.crypto_sign_PUBLICKEYBYTES) return false
  return sodium.crypto_sign_verify_detached(signature, message, publicKey)
}

exports.encrypt = function (message, publicKey) {
  const ciphertext = b4a.alloc(message.byteLength + sodium.crypto_box_SEALBYTES)
  sodium.crypto_box_seal(ciphertext, message, publicKey)
  return ciphertext
}

exports.decrypt = function (ciphertext, keyPair) {
  if (ciphertext.byteLength < sodium.crypto_box_SEALBYTES) return null

  const plaintext = b4a.alloc(ciphertext.byteLength - sodium.crypto_box_SEALBYTES)

  if (!sodium.crypto_box_seal_open(plaintext, ciphertext, keyPair.publicKey, keyPair.secretKey)) {
    return null
  }

  return plaintext
}

exports.encryptionKeyPair = function (seed) {
  const publicKey = b4a.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_box_SECRETKEYBYTES)

  if (seed) {
    sodium.crypto_box_seed_keypair(publicKey, secretKey, seed)
  } else {
    sodium.crypto_box_keypair(publicKey, secretKey)
  }

  return {
    publicKey,
    secretKey
  }
}

exports.data = function (data) {
  const out = b4a.allocUnsafe(32)
  const len = 9 + data.byteLength

  SCRATCH[0] = LEAF_TYPE[0]
  writeUint64(SCRATCH, 1, data.byteLength)

  if (len <= SCRATCH.byteLength && data.length === data.byteLength) {
    SCRATCH.set(data, 9)
    sodium.crypto_generichash(out, SCRATCH.subarray(0, len))
  } else {
    sodium.crypto_generichash_batch(out, [LEAF_HEADER, data])
  }

  return out
}

exports.parent = function (a, b) {
  if (a.index > b.index) {
    const tmp = a
    a = b
    b = tmp
  }

  const out = b4a.allocUnsafe(32)

  if (!isHash(a.hash) || !isHash(b.hash)) {
    sodium.crypto_generichash_batch(out, [
      PARENT_TYPE,
      c.encode(c.uint64, a.size + b.size),
      a.hash,
      b.hash
    ])
    return out
  }

  PARENT_INPUT[0] = PARENT_TYPE[0]
  writeUint64(PARENT_INPUT, 1, a.size + b.size)
  PARENT_INPUT.set(a.hash, 9)
  PARENT_INPUT.set(b.hash, 41)

  sodium.crypto_generichash(out, PARENT_INPUT)

  return out
}

exports.tree = function (roots, out) {
  if (!out) out = b4a.allocUnsafe(32)

  const len = 1 + 48 * roots.length
  const input = roots.length <= MAX_SCRATCH_ROOTS ? SCRATCH : b4a.allocUnsafe(len)

  input[0] = ROOT_TYPE[0]

  for (let i = 0, j = 1; i < roots.length; i++, j += 48) {
    const r = roots[i]
    if (!isHash(r.hash)) return treeBatch(roots, out)
    input.set(r.hash, j)
    writeUint64(input, j + 32, r.index)
    writeUint64(input, j + 40, r.size)
  }

  sodium.crypto_generichash(out, input.subarray(0, len))
  return out
}

function treeBatch(roots, out) {
  const buffers = new Array(3 * roots.length + 1)
  let j = 0

  buffers[j++] = ROOT_TYPE

  for (let i = 0; i < roots.length; i++) {
    const r = roots[i]
    buffers[j++] = r.hash
    buffers[j++] = c.encode(c.uint64, r.index)
    buffers[j++] = c.encode(c.uint64, r.size)
  }

  sodium.crypto_generichash_batch(out, buffers)
  return out
}

exports.hash = function (data, out) {
  if (!out) out = b4a.allocUnsafe(32)
  if (!Array.isArray(data)) data = [data]

  sodium.crypto_generichash_batch(out, data)

  return out
}

exports.randomBytes = function (n) {
  const buf = b4a.allocUnsafe(n)
  sodium.randombytes_buf(buf)
  return buf
}

exports.discoveryKey = function (key) {
  if (!key || key.byteLength !== 32) throw new Error('Must pass a 32 byte buffer')
  // Discovery keys might stay around for a while, so better not to use slab memory (for better gc)
  const digest = b4a.allocUnsafeSlow(32)
  sodium.crypto_generichash(digest, HYPERCORE, key)
  return digest
}

if (sodium.sodium_free) {
  exports.free = function (secureBuf) {
    if (secureBuf.secure) sodium.sodium_free(secureBuf)
  }
} else {
  exports.free = function () {}
}

exports.namespace = function (name, count) {
  const ids = typeof count === 'number' ? range(count) : count

  // Namespaces are long-lived, so better to use a dedicated slab
  const buf = b4a.allocUnsafeSlow(32 * ids.length)

  const list = new Array(ids.length)

  // ns is ephemeral, so default slab
  const ns = b4a.allocUnsafe(33)
  sodium.crypto_generichash(ns.subarray(0, 32), typeof name === 'string' ? b4a.from(name) : name)

  for (let i = 0; i < list.length; i++) {
    list[i] = buf.subarray(32 * i, 32 * i + 32)
    ns[32] = ids[i]
    sodium.crypto_generichash(list[i], ns)
  }

  return list
}

// 32 one-byte elements, so .set() copies it byte for byte
function isHash(h) {
  return h.byteLength === 32 && h.length === 32
}

// Same bytes and range check as c.encode(c.uint64, n)
function writeUint64(buf, offset, n) {
  if (!(n >= 0 && n <= Number.MAX_SAFE_INTEGER)) {
    throw new Error(`uint must be between 0 and ${Number.MAX_SAFE_INTEGER}, use biguint`)
  }
  const hi = Math.floor(n / 0x100000000)
  buf[offset] = n
  buf[offset + 1] = n >>> 8
  buf[offset + 2] = n >>> 16
  buf[offset + 3] = n >>> 24
  buf[offset + 4] = hi
  buf[offset + 5] = hi >>> 8
  buf[offset + 6] = hi >>> 16
  buf[offset + 7] = hi >>> 24
}

function range(count) {
  const arr = new Array(count)
  for (let i = 0; i < count; i++) arr[i] = i
  return arr
}
