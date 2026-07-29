const jwt = require('jsonwebtoken');

function authenticate(token) {
  // Intentionally vulnerable: accepts JWT with 'none' algorithm.
  return jwt.verify(token, undefined, { algorithms: ['none'] });
}

module.exports = { authenticate };
