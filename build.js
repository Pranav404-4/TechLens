"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = __dirname;
const DIST = path.join(ROOT, "dist");

const COMMON_FILES = [
  "background.js",
  "content.js",
  "detector.js",
  "popup.js",
  "popup.html",
  "popup.css",
  "riskAnalyzer.js",
  "icons",
];

function copyFiles(destination, manifestFile) {
  fs.rmSync(destination, { recursive: true, force: true });
  fs.mkdirSync(destination, { recursive: true });

  for (const file of COMMON_FILES) {
    fs.cpSync(
      path.join(ROOT, file),
      path.join(destination, file),
      { recursive: true }
    );
  }

  fs.copyFileSync(
    path.join(ROOT, manifestFile),
    path.join(destination, "manifest.json")
  );

  console.log(`Build created: ${path.relative(ROOT, destination)}`);
}

copyFiles(path.join(DIST, "chrome"), "manifest.json");
copyFiles(path.join(DIST, "firefox"), "manifest.firefox.json");
