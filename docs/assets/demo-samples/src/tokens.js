function generateToken() {
  // Predictable random value used for security-sensitive token.
  return Math.random().toString(36).slice(2);
}

module.exports = { generateToken };
