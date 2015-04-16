var crypto = require('crypto')
  , querystring = require('querystring');

var bcrypt = require('bcrypt');

function DeaconCrypto(options) {
  options = options || {};
  this.options = {
      rounds: 10
    , resetAlgo: 'sha1'
    , resetTimeout: 3600000
    , timestampEncoding: 16
  };
  for (var k in options) {
    if (k in this.options) {
      this.options[k] = options[k];
    }
    else {
      throw new Error('Invalid option "' + k + '"');
    }
  }
}

DeaconCrypto.prototype.hash = function(str, callback) {
  // TODO: ensure hash returned is the requisite 60 characters
  var _this = this;
  bcrypt.genSalt(_this.options.rounds, function(err, salt) {
    if (err) return callback(err);
    bcrypt.hash(str, salt, function(err, hash) {
      if (err) return callback(err);
      callback(null, hash);
    });
  });
};

DeaconCrypto.prototype.hashPassword = function(password, callback) {
  this.hash(password, callback);
};

DeaconCrypto.prototype.validateHash = function(hash, str, callback) {
  var _this = this;
  bcrypt.compare(str, hash, function(err, valid) {
    if (err) return callback(err);
    callback(null, valid);
  });
};

DeaconCrypto.prototype.validatePasswordHash = function(passwordHash, password, callback) {
  this.validateHash(passwordHash, password, callback);
};

DeaconCrypto.prototype.sign = function(message, key) {
  return crypto.createHmac(this.options.resetAlgo, key).update(message).digest('hex');
};

DeaconCrypto.prototype.signPasswordReset = function(passwordHash, timestamp) {
  timestamp = (timestamp || new Date().getTime()).toString(this.options.timestampEncoding);
  var signature = this.sign(timestamp, passwordHash);
  return {
      timestamp: timestamp
    , signature: signature
    , querystring: querystring.stringify({ t: timestamp, s: signature })
  };
};

DeaconCrypto.prototype.validateSignature = function(message, key, signature) {
  var compare = this.sign(message, key);
  return compare === signature;
};

DeaconCrypto.prototype.validatePasswordResetSignature = function(passwordHash, passwordReset) {
  var match = this.validateSignature(passwordReset.timestamp, passwordHash, passwordReset.signature)
    , noTimeout = (new Date().getTime() - parseInt(passwordReset.timestamp, this.options.timestampEncoding)) < this.options.resetTimeout;
  return match && noTimeout;
};

DeaconCrypto.prototype.validatePasswordResetQuerystring = function(passwordHash, qs) {
  var parsed = querystring.parse(qs, null, null, { maxKeys: 2 });
  return !parsed.r || !parsed.t ? false : this.validatePasswordResetSignature(passwordHash, {
      timestamp: parsed.t
    , signature: parsed.s
  });
};

module.exports = DeaconCrypto;
