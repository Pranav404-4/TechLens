const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const contentScript = fs.readFileSync("content.js", "utf8");

let messageListener;

let generatorContent = "WordPress 6.7.1";

const generatorMeta = {
  getAttribute(name) {
    if (name === "name") return "generator";
    return null;
  },
  get content() {
    return generatorContent;
  },
};

const document = {
  scripts: [],
  title: "WordPress Test",
  cookie: "",
  querySelector(selector) {
    if (selector === 'meta[name="generator"]') {
      return generatorMeta;
    }
    return null;
  },
  querySelectorAll(selector) {
    if (selector === "meta") return [generatorMeta];
    return [];
  },
};

const context = {
  document,
  window: {},
  location: {
    href: "https://example.test/",
    hostname: "example.test",
  },
  performance: {
    getEntriesByType() {
      return [];
    },
  },
  chrome: {
    runtime: {
      onMessage: {
        addListener(callback) {
          messageListener = callback;
        },
      },
    },
  },
  console: {
    log() {},
  },
  Date,
  Set,
};

vm.runInNewContext(contentScript, context);

assert.equal(typeof messageListener, "function");

let response;

const keepChannelOpen = messageListener(
  { type: "TECHLENS_SCAN" },
  {},
  (result) => {
    response = result;
  },
);

(async () => {
  // Wait for the asynchronous scan to complete.
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(keepChannelOpen, true);
  assert.equal(response.ok, true);

  const wordpressHint = response.page.versionHints.find(
    (hint) => hint.name === "WordPress",
  );

  assert.ok(wordpressHint, "WordPress version hint should exist");
  assert.equal(wordpressHint.version, "6.7.1");
  assert.equal(wordpressHint.source, "meta");
  assert.equal(wordpressHint.confidence, 90);

  assert.match(
    wordpressHint.version,
    /^\d+(?:\.\d+)*$/,
    "WordPress version should use a supported numeric format",
  );

  console.log("PASS: WordPress version extracted from generator metadata");

  // Verify that missing version metadata does not create a false version.
  generatorContent = "WordPress";

  let missingVersionResponse;

  messageListener({ type: "TECHLENS_SCAN" }, {}, (result) => {
    missingVersionResponse = result;
  });

  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(missingVersionResponse.ok, true);

  const missingWordPressHint = missingVersionResponse.page.versionHints.find(
    (hint) => hint.name === "WordPress",
  );

  assert.equal(missingWordPressHint, undefined);

  console.log("PASS: Missing WordPress version is not invented");
})();
