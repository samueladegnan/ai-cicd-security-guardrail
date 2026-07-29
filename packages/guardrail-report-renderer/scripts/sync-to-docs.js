/**
 * Sync the canonical renderer source into the docs site.
 *
 * This lets the Jekyll/GitHub Pages site consume the same source files that
 * are published to npm, without maintaining two copies by hand.
 */

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "../../..");
const srcDir = path.resolve(__dirname, "../src");
const docsJsDir = path.join(root, "docs", "assets", "js");
const docsCssDir = path.join(root, "docs", "assets", "css");

function syncWithHeader(src, dest, header) {
  const content = fs.readFileSync(src, "utf8");
  fs.writeFileSync(dest, `${header}\n\n${content}`, "utf8");
}

function main() {
  if (!fs.existsSync(docsJsDir)) {
    throw new Error(`Docs JS directory not found: ${docsJsDir}`);
  }
  if (!fs.existsSync(docsCssDir)) {
    throw new Error(`Docs CSS directory not found: ${docsCssDir}`);
  }

  syncWithHeader(
    path.join(srcDir, "index.js"),
    path.join(docsJsDir, "guardrail-report-renderer.js"),
    "/* AUTO-GENERATED from packages/guardrail-report-renderer/src/index.js — do not edit directly. */"
  );
  syncWithHeader(
    path.join(srcDir, "style.css"),
    path.join(docsCssDir, "guardrail-report.css"),
    "/* AUTO-GENERATED from packages/guardrail-report-renderer/src/style.css — do not edit directly. */"
  );

  console.log("Synced renderer source to docs/assets/");
}

if (require.main === module) {
  main();
}

module.exports = { main };
