const tape = require('tape')
const crypto = require('./')

tape('randomBytes', function (t) {
  const buffer = crypto.randomBytes(100)
  t.ok(Buffer.isBuffer(buffer))
  t.notSame(crypto.randomBytes(100), buffer)
  t.end()
})

tape('key pair', function (t) {
  const keyPair = crypto.keyPair()

  t.same(keyPair.publicKey.length, 32)
  t.same(keyPair.secretKey.length, 64)
  t.end()
})

tape('validate key pair', function (t) {
  const keyPair1 = crypto.keyPair()
  const keyPair2 = crypto.keyPair()

  t.false(crypto.validateKeyPair({ publicKey: keyPair1.publicKey, secretKey: keyPair2.secretKey }))
  t.true(crypto.validateKeyPair({ publicKey: keyPair1.publicKey, secretKey: keyPair1.secretKey }))
  t.end()
})

tape('sign', function (t) {
  const keyPair = crypto.keyPair()
  const message = Buffer.from('hello world')

  const sig = crypto.sign(message, keyPair.secretKey)

  t.same(sig.length, 64)
  t.ok(crypto.verify(message, sig, keyPair.publicKey))
  t.notOk(crypto.verify(message, Buffer.alloc(64), keyPair.publicKey))
  t.end()
})

tape('hash leaf', function (t) {
  const data = Buffer.from('hello world')

  t.same(crypto.data(data), Buffer.from('9f1b578fd57a4df015493d2886aec9600eef913c3bb009768c7f0fb875996308', 'hex'))
  t.end()
})

tape('hash parent', function (t) {
  const data = Buffer.from('hello world')

  const parent = crypto.parent({
    index: 0,
    size: 11,
    hash: crypto.data(data)
  }, {
    index: 2,
    size: 11,
    hash: crypto.data(data)
  })

  t.same(parent, Buffer.from('3ad0c9b58b771d1b7707e1430f37c23a23dd46e0c7c3ab9c16f79d25f7c36804', 'hex'))
  t.end()
})

tape('tree', function (t) {
  const roots = [
    { index: 3, size: 11, hash: Buffer.alloc(32) },
    { index: 9, size: 2, hash: Buffer.alloc(32) }
  ]

  t.same(crypto.tree(roots), Buffer.from('0e576a56b478cddb6ffebab8c494532b6de009466b2e9f7af9143fc54b9eaa36', 'hex'))
  t.end()
})
