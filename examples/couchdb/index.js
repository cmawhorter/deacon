if (!process.argv[2]) {
  throw new Error('Pass couchdb url as first argument');
}

if (!process.argv[3]) {
  throw new Error('Pass couchdb database as second argument');
}

var nano = require('nano')(process.argv[2]);
var db = nano.use(process.argv[3]);

var Deacon = require('../../index.js');

var deacon = new Deacon({
  db: {
    create: function(data, callback) {
      db.insert(data, data.email, callback);
    },

    get: function(email, callback) {
      db.get(email, callback);
    },

    remove: function(email, callback) {
      // of course, this could also just set status to disabled instead of destroying
      db.get(email, function(err, body) {
        if (err) return callback(err);
        db.destroy(email, body._rev, callback);
      });
    },

    activate: function(email, callback) {
      db.get(email, function(err, body) {
        if (err) return callback(err);
        body.verified = true;
        db.insert(body, email, callback);
      });
    }
  }
});

var email = 'test' + Math.floor(Math.random() * 100000) + '@example.com';
var password = 'abcd1234';
deacon.create(email, password, { a: 'property', goes: 'here' }, function(err, result) {
  if (err) throw err;
  console.log('created %s', email, result);
  deacon.authenticate(email, password, function(err, valid) {
    if (err) throw err;
    console.log('user is %s', valid ? 'valid' : 'INVALID!');
    deacon.verify(email, function(err) {
      if (err) throw err;
      deacon.reset(email, function(err, message) {
        if (err) throw err;
        console.log('user reset message', message);
      });
    });
  });
});
