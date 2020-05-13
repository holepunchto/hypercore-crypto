try {
  module.exports = require('sodium-native')
} catch (_) {
  module.exports = require('sodium-javascript')
}
