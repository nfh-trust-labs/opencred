/**
 * Renames all .js files in dist/preload/ to .cjs and fixes require() paths.
 * This is needed because package.json has "type": "module", which makes
 * Node.js treat .js files as ESM. Electron preload scripts must be CJS.
 */
const fs = require("fs");
const path = require("path");

const preloadDir = path.join(__dirname, "..", "dist", "preload");

function processDir(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      processDir(fullPath);
    } else if (entry.name.endsWith(".js")) {
      // Fix require paths: .js → .cjs
      let content = fs.readFileSync(fullPath, "utf-8");
      content = content.replace(/require\("([^"]+)\.js"\)/g, 'require("$1.cjs")');
      // Rename file
      const newPath = fullPath.replace(/\.js$/, ".cjs");
      fs.writeFileSync(newPath, content, "utf-8");
      fs.unlinkSync(fullPath);
    }
  }
}

processDir(preloadDir);
console.log("Preload files renamed to .cjs");
