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
  // TODO: put constraints on password.  IIRC a pw length > some amount could make passwords less secure. not sure about bcrypt?
  // FIXME: yup. bcrypt has 72 char limit http://security.stackexchange.com/questions/21524/bcrypts-72-character-limit-and-using-it-as-a-general-digest-algorithm
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

Deacon.prototype.changePassword = function(email, currentPassword, newPassword, callback) {
  var _this = this;
  _this.authenticate(email, currentPassword, function(err, valid) {
    if (err) return callback(err);
    if (valid) {
      _this.forcePasswordChange(email, newPassword, callback);
    }
    else {
      callback(new Error('invalid password'));
    }
  });
};

Deacon.prototype.forcePasswordChange = function(email, newPassword, callback) {
  var _this = this;
  _this.crypto.hashPassword(newPassword, function(err, passwordHash) {
    if (err) return callback(err);
    _this.db.password((email || '').trim().toLowerCase(), passwordHash, callback);
  });
};

Deacon.prototype.createVerified = function(email, password, properties, callback) {
  if (typeof properties === 'function') {
    callback = properties;
    properties = {};
  }
  properties[this.columnNames.verified || defaultColumnNames.verified] = true;
  this.create((email || '').trim().toLowerCase(), password, properties, callback);
};

Deacon.prototype.authenticate = function(email, password, callback) {
  var _this = this;
  _this.db.get((email || '').trim().toLowerCase(), function(err, user) {
    if (err) return callback(err);
    _this.crypto.validatePasswordHash(user.password, password, callback);
  });
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

Deacon.prototype.authenticateReset = function(email, data, callback) {
  var _this = this;
  _this.db.get((email || '').trim().toLowerCase(), function(err, user) {
    if (err) return callback(err);
    if (typeof data === 'object') {
      callback(null, _this.crypto.validatePasswordResetSignature(user.password, data));
    }
    else {
      callback(null, _this.crypto.validatePasswordResetQuerystring(user.password, data));
    }
  });
};

Deacon.prototype.disable = function(email, callback) {
  this.db.remove((email || '').trim().toLowerCase(), callback);
};

Deacon.Crypto = DeaconCrypto;

module.exports = Deacon;
