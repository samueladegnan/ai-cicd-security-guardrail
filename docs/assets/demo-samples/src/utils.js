function runUserCode(input) {
  // Dangerous eval of user input.
  return eval(input);
}

module.exports = { runUserCode };
