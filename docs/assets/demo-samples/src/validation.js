function validateInput(input) {
  // User input reaches a regex with potential exponential time.
  const pattern = /^(a+)+$/;
  return pattern.test(input);
}

module.exports = { validateInput };
