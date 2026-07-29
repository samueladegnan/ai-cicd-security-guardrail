module.exports = {
  testEnvironment: "jsdom",
  testMatch: ["**/__tests__/**/*.test.js"],
  testPathIgnorePatterns: ["/__tests__/.+\\.e2e\\.test\\.js$"],
  collectCoverageFrom: ["src/**/*.js"],
  setupFilesAfterEnv: ["<rootDir>/__tests__/setup.js"],
};
