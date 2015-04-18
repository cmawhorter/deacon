'use strict';

var re_Email = /^.+@.+$/;

var Validation = {
  isEmail: function isValidEmail(str) {
    return re_Email.test(str || '');
  },

  isPassword: function isValidPassword(str) {
    var len = (str || '').length;
    return len > 0 && len < 72;
  },
};

module.exports = Validation;
