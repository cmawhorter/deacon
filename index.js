var DeaconCrypto = require('./lib/crypto.js');

var defaultColumnNames = {
    email: 'email'
  , password: 'password'
  , verified: 'verified'
};

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
  this.columnNames = this.db.columnNames || defaultColumnNames;
}

Deacon.prototype.create = function(email, password, properties, callback) {
  var _this = this;
  if (typeof properties === 'function') {
    callback = properties;
    properties = {};
  }
  properties[_this.columnNames.email || defaultColumnNames.email] = (email || '').trim().toLowerCase();
  _this.crypto.hashPassword(password, function(err, passwordHash) {
    if (err) return callback(err);
    properties[_this.columnNames.password || defaultColumnNames.password] = passwordHash;
    _this.db.create(properties, callback);
  });
};

Deacon.prototype.verify = function(email, callback) {
  this.db.activate((email || '').trim().toLowerCase(), callback);
};

Deacon.prototype.createVerified = function(email, password, properties, callback) {
  if (typeof properties === 'function') {
    callback = properties;
    properties = {};
  }
  properties[this.columnNames.verified || defaultColumnNames.verified] = true;
  this.create((email || '').trim().toLowerCase(), password, properties, callback);
};

Deacon.prototype.reset = function(email, callback) {
  var _this = this;
  _this.db.get((email || '').trim().toLowerCase(), function(err, user) {
    if (err) return callback(err);
    var signed = _this.crypto.signPasswordReset(user.password);
    // TODO: create mailer and option
    callback(null, signed);
  });
};

Deacon.prototype.authenticate = function(email, password, callback) {
  var _this = this;
  _this.db.get((email || '').trim().toLowerCase(), function(err, user) {
    if (err) return callback(err);
    _this.crypto.validatePasswordHash(user.password, password, callback);
  });
};

Deacon.prototype.disable = function(email, callback) {
  this.db.remove((email || '').trim().toLowerCase(), callback);
};

Deacon.Crypto = DeaconCrypto;

module.exports = Deacon;
