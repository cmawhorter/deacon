var bcrypt = require('bcrypt');

var HASH_SEPARATOR = ':';

var OptionDefaults = {
    cryptoRounds: 10
  , databaseEmailColumn: 'email'
  , databasePasswordColumn: 'password'
};

function Deacon(userProvider, options) {
  this.userProvider = userProvider;
  this.options = options || {};
}

Deacon.prototype.createUser = function(email, password, properties, callback) {
  var _this = this;
  if (typeof properties === 'function') {
    callback = properties;
    properties = {};
  }
  var user = Object.create(properties || {});
  user[_this.options.databaseEmailColumn] = email;
  Deacon.hash(password, _this.options.cryptoRounds, function(err, hash) {
    if (err) return callback(err);
    user[_this.options.databasePasswordColumn] = _this.options.cryptoRounds + HASH_SEPARATOR + hash;
    _this.userProvider.create(user, callback);
  });
};

Deacon.prototype.validateUser = function(email, password, callback) {
  var _this = this;
  _this.userProvider.get(email, function(err, user) {
    if (err) return callback(err);
    var toks = user[_this.options.databasePasswordColumn].split(':');
    bcrypt.compare(password, toks[3], function(err, valid) {
      if (err) return callback(err);
      callback(null, valid);
    });
  });
};

Deacon.prototype.generatePasswordReset = function(email, callback) {
  var _this = this;
  _this.userProvider.get(email, function(err, user) {
    if (err) return callback(err);
    // TODO: generate and return a single hmac signed nonce message
  });
};

Deacon.prototype.validatePasswordReset = function(email, password, callback) {
  var _this = this;
  _this.userProvider.get(email, function(err, user) {
    if (err) return callback(err);
    var toks = user[_this.options.databasePasswordColumn].split(':');
    bcrypt.compare(password, toks[3], function(err, valid) {
      if (err) return callback(err);
      // TODO: validate nonce and hmac message timeout
      // nonce = existing hashed password +
      // databaseResetNonceColumn
      // TODO: update user password
      // TODO: ensure password is not the same
      // TODO: prevent last N passwords?
    });
  });
};

Deacon.hash = function hash(password, rounds, callback) {
  rounds = rounds || OptionDefaults.cryptoRounds;
  bcrypt.genSalt(rounds, function(err, salt) {
    if (err) return callback(err);
    bcrypt.hash(password, salt, function(err, hash) {
      if (err) return callback(err);
      callback(null, salt + HASH_SEPARATOR + hash);
    });
  });
};

module.exports = Deacon;
