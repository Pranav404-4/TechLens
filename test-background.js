"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const listeners = {
  beforeRequest: null,
  headersReceived: null,
  tabRemoved: null,
  message: null,
};

const mockBrowser = {
  webRequest: {
    onBeforeRequest: {
      addListener(callback) {
        listeners.beforeRequest = callback;
      },
    },
    onHeadersReceived: {
      addListener(callback) {
        listeners.headersReceived = callback;
      },
    },
  },
  tabs: {
    onRemoved: {
      addListener(callback) {
        listeners.tabRemoved = callback;
      },
    },
  },
  runtime: {
    onMessage: {
      addListener(callback) {
        listeners.message = callback;
      },
    },
  },
};

const context = vm.createContext({
  browser: mockBrowser,
  fetch: async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      totalResults: 0,
      vulnerabilities: [],
    }),
  }),
  URLSearchParams,
  console,
});

// Simulate the browser's importScripts() function.
context.importScripts = (...files) => {
  for (const file of files) {
    const source = fs.readFileSync(file, "utf8");
    vm.runInContext(source, context, { filename: file });
  }
};

// Load background.js and its imported CVE client.
const backgroundSource = fs.readFileSync("background.js", "utf8");
vm.runInContext(backgroundSource, context, {
  filename: "background.js",
});

assert.ok(listeners.message, "Message listener should be registered");

// Test 1: Existing header handler.
listeners.headersReceived({
  tabId: 5,
  type: "main_frame",
  frameId: 0,
  responseHeaders: [
    { name: "Server", value: "nginx" },
    { name: "Content-Type", value: "text/html" },
  ],
});

let headerResponse;

listeners.message(
  { type: "TECHLENS_GET_HEADERS", tabId: 5 },
  {},
  (response) => {
    headerResponse = response;
  },
);

assert.deepEqual(JSON.parse(JSON.stringify(headerResponse)), {
  headers: [{ name: "Server", value: "nginx" }],
  captured: true,
});

console.log("PASS: Header message handler test");

// Test 2: Reject a technology with an unmapped CPE.
let invalidResponse;

const invalidReturn = listeners.message(
  {
    type: "TECHLENS_GET_CVES",
    technologyId: "fathom-analytics",
  },
  {},
  (response) => {
    invalidResponse = response;
  },
);

assert.equal(invalidReturn, undefined);
assert.equal(invalidResponse.success, false);
assert.match(invalidResponse.error, /no verified CPE mapping/i);

console.log("PASS: Unmapped technology rejection test");

// Test 2.1: Reject a fabricated CPE supplied directly by the popup.
let fabricatedResponse;

const fabricatedReturn = listeners.message(
  {
    type: "TECHLENS_GET_CVES",
    technologyId: "fathom-analytics",
    product: {
      cpe: "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
    },
  },
  {},
  (response) => {
    fabricatedResponse = response;
  },
);

assert.equal(fabricatedReturn, undefined);
assert.equal(fabricatedResponse.success, false);
assert.match(fabricatedResponse.error, /no verified CPE mapping/i);

console.log("PASS: Fabricated CPE rejection test");

// Test 2.2: Reject invalid technology IDs.
for (const technologyId of [null, 123, {}, "   ", "a".repeat(101)]) {
  let response;

  const returnValue = listeners.message(
    {
      type: "TECHLENS_GET_CVES",
      technologyId,
    },
    {},
    (result) => {
      response = result;
    },
  );

  assert.equal(returnValue, undefined);
  assert.equal(response.success, false);
}

console.log("PASS: Invalid technology ID tests");

// Add a synthetic verified product to the test catalogue.
context.TechLensDetector.RULES.push({
  id: "test-verified-tech",
  product: {
    cpe: "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
    cpeStatus: "verified",
  },
});

// Test 3: Accept a trusted technology ID and return NVD data.
async function testValidCveRequest() {
  let cveResponse;

  const returnValue = listeners.message(
    {
      type: "TECHLENS_GET_CVES",
      technologyId: "test-verified-tech",
      version: "1.2.3",
    },
    {},
    (response) => {
      cveResponse = response;
    },
  );

  assert.equal(returnValue, true);

  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(cveResponse.success, true);
  assert.equal(cveResponse.data.totalResults, 0);

  console.log("PASS: Valid CVE request test");
}

testValidCveRequest().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
