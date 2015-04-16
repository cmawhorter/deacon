var DeaconCrypto = require('./lib/crypto.js');

function Deacon(options) {
  options = options || {};
  this.options = {
      crypto: null
    , db: null
  };
  for (var k in options) {
    if (k in this.options) {
      this.options[k] = options[k];
    }
    else {
      throw new Error('Invalid option "' + k + '"');
    }
  }
  this.crypto = new DeaconCrypto(this.options.crypto);
  this.db = this.options.db;
}

Deacon.prototype.create = function(email, password, properties, callback) {
  var _this = this;
  if (typeof properties === 'function') {
    callback = properties;
    properties = {};
  }
  properties[_this.db.columnNames.email] = email;
  _this.crypto.hashPassword(password, function(err) {
    if (err) return callback(err);
    properties[_this.db.columnNames.password] = password;
    _this.db.create(properties, callback);
  });
};

Deacon.prototype.verify = function(email, callback) {
  this.db.activate(email, callback);
};

Deacon.prototype.createVerified = function(email, password, properties, callback) {
  if (typeof properties === 'function') {
    callback = properties;
    properties = {};
  }
  properties[this.db.columnNames.verified] = true;
  this.create(email, password, properties, callback);
};

Deacon.prototype.reset = function(email, callback) {
  var _this = this;
  _this.db.get(email, function(err, user) {
    if (err) return callback(err);
    var signed = _this.crypto.signPasswordReset(user.password);
    // TODO: create mailer and option
    callback(null, signed);
  });
};

Deacon.prototype.authenticate = function(email, password, callback) {
  var _this = this;
  _this.db.get(email, function(err, user) {
    if (err) return callback(err);
    _this.crypto.validatePasswordHash(user.password, password, callback);
  });
};

Deacon.prototype.disable = function(email, callback) {
  this.db.remove(email, callback);
};

Deacon.Crypto = DeaconCrypto;

module.exports = Deacon;
