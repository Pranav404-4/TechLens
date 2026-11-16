"use strict";

const assert = require("node:assert/strict");

require("./cveClient.js");

const { searchByCpe, isValidCpe23 } = globalThis.TechLensCVE;

async function runTests() {
  // Test 1: Reject an unmapped product.
  await assert.rejects(
    searchByCpe({
      cpe: null,
      cpeStatus: "unmapped",
    }),
    /verified CPE identifier is required/i,
  );

  // Test 2: Reject an unverified CPE.
  await assert.rejects(
    searchByCpe({
      cpe: "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
      cpeStatus: "unmapped",
    }),
    /verified CPE identifier is required/i,
  );

  // Test 3: Reject an invalid CPE format.
  await assert.rejects(
    searchByCpe({
      cpe: "example-product",
      cpeStatus: "verified",
    }),
    /verified CPE identifier is required/i,
  );

  // Test 3.1: Validate CPE 2.3 structure.
  const validCpe = "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*";

  assert.equal(isValidCpe23(validCpe), true);

  assert.equal(isValidCpe23("example-product"), false);

  assert.equal(isValidCpe23("cpe:2.3:a:example"), false);

  assert.equal(isValidCpe23("cpe:2.3:x:example:product:*:*:*:*:*:*:*"), false);

  assert.equal(isValidCpe23("cpe:2.3:a::product:*:*:*:*:*:*:*"), false);

  assert.equal(isValidCpe23("cpe:2.3:a:example:product:*:*:*:*:*:*:*:"), false);

  console.log("PASS: CPE 2.3 validation tests passed");

  // Test 4: Handle a successful NVD response.
  const originalFetch = globalThis.fetch;
  let requestedUrl = "";

  try {
    globalThis.fetch = async (url) => {
      requestedUrl = String(url);

      return {
        ok: true,
        status: 200,
        json: async () => ({
          totalResults: 0,
          vulnerabilities: [],
        }),
      };
    };

    const result = await searchByCpe({
      cpe: "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
    });

    assert.equal(result.totalResults, 0);
    assert.ok(requestedUrl.includes("cpeName="));
    assert.ok(requestedUrl.includes("resultsPerPage=100"));

    console.log("PASS: Successful NVD response test passed");
  } finally {
    globalThis.fetch = originalFetch;
  }

  // Test 5: Handle NVD rate limits and server errors.
  const originalFetchErrors = globalThis.fetch;

  try {
    globalThis.fetch = async () => ({
      ok: false,
      status: 429,
    });

    await assert.rejects(
      searchByCpe({
        cpe: "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
        cpeStatus: "verified",
      }),
      /rate limit reached/i,
    );

    globalThis.fetch = async () => ({
      ok: false,
      status: 403,
    });

    await assert.rejects(
      searchByCpe({
        cpe: "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
        cpeStatus: "verified",
      }),
      /rate limit reached/i,
    );

    globalThis.fetch = async () => ({
      ok: false,
      status: 500,
    });

    await assert.rejects(
      searchByCpe({
        cpe: "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
        cpeStatus: "verified",
      }),
      /HTTP 500/,
    );

    // Test escaped characters in a CPE component.
    assert.equal(
      isValidCpe23("cpe:2.3:a:example:product\\:edition:*:*:*:*:*:*:*:*"),
      true,
    );

    // Test an invalid trailing escape.
    assert.equal(
      isValidCpe23("cpe:2.3:a:example:product:*:*:*:*:*:*:*:*\\"),
      false,
    );
    console.log("PASS: NVD error handling tests passed");
  } finally {
    globalThis.fetch = originalFetchErrors;
  }

  console.log("PASS: CVE client validation tests passed");
}

runTests().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
