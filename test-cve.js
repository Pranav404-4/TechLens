"use strict";

const assert = require("node:assert/strict");

require("./cveClient.js");

const {
  searchByCpe,
  isValidCpe23,
  parseCveRecord,
  getCvssMetric,
  parseNvdResponse,
} = globalThis.TechLensCVE;

const {
  compareVersions,
  matchesVersionRange,
  matchesProductIdentity,
  assessCveVersion,
} = globalThis.TechLensCVE;

async function runTests() {
  // Test 0: Parse a realistic NVD vulnerability record.
  const mockCve = {
    cve: {
      id: "CVE-2025-12345",
      vulnStatus: "Analyzed",
      published: "2025-01-10T10:00:00.000",
      lastModified: "2025-02-10T10:00:00.000",
      descriptions: [
        {
          lang: "en",
          value: "A sample security vulnerability.",
        },
      ],
      metrics: {
        cvssMetricV31: [
          {
            cvssData: {
              version: "3.1",
              baseScore: 8.5,
              baseSeverity: "HIGH",
              vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            },
          },
        ],
      },
      references: [
        {
          url: "https://example.com/security-advisory",
          tags: ["Vendor Advisory"],
        },
      ],
      configurations: [],
    },
  };

  const parsed = parseCveRecord(mockCve);

  assert.equal(parsed.id, "CVE-2025-12345");
  assert.equal(parsed.description, "A sample security vulnerability.");
  assert.equal(parsed.cvss.version, "3.1");
  assert.equal(parsed.cvss.score, 8.5);
  assert.equal(parsed.cvss.severity, "HIGH");
  assert.equal(parsed.references.length, 1);
  assert.deepEqual(parsed.configurations, []);

  console.log("PASS: CVE record parsing test");

  // Test 0.1: Reject malformed CVE records.
  assert.equal(parseCveRecord(null), null);
  assert.equal(parseCveRecord({}), null);
  assert.equal(parseCveRecord({ cve: { id: 123 } }), null);

  console.log("PASS: Invalid CVE record tests");

  // Test 0.2: Handle missing CVSS metrics.
  assert.equal(getCvssMetric({}), null);

  console.log("PASS: Missing CVSS metrics test");

  // Test 0.3: Parse multiple CVEs from an NVD response.
  const parsedResponse = parseNvdResponse({
    totalResults: 2,
    vulnerabilities: [
      mockCve,
      {
        cve: {
          id: "CVE-2025-67890",
          descriptions: [
            {
              lang: "en",
              value: "Another sample vulnerability.",
            },
          ],
        },
      },
    ],
  });

  assert.equal(parsedResponse.totalResults, 2);
  assert.equal(parsedResponse.vulnerabilities.length, 2);
  assert.equal(parsedResponse.vulnerabilities[0].id, "CVE-2025-12345");
  assert.equal(parsedResponse.vulnerabilities[1].id, "CVE-2025-67890");

  console.log("PASS: Multiple CVE response parsing test");

  // Test 0.4: Reject malformed NVD responses.
  assert.throws(() => parseNvdResponse(null), /invalid NVD response format/i);

  assert.throws(
    () => parseNvdResponse({ vulnerabilities: {} }),
    /invalid NVD response format/i,
  );

  console.log("PASS: Invalid NVD response tests");

  // Test 1: Reject an unmapped product.
  await assert.rejects(
    searchByCpe({
      cpe: null,
      cpeStatus: "unmapped",
    }),
    /verified CPE identifier is required/i,
  );

  // Test 0.5: Compare numeric versions.
  assert.equal(compareVersions("2.4.57", "2.4.56"), 1);
  assert.equal(compareVersions("2.4.57", "2.4.57"), 0);
  assert.equal(compareVersions("2.4.9", "2.4.10"), -1);
  assert.equal(compareVersions("2.4", "2.4.0"), 0);
  assert.equal(compareVersions("2.4.x", "2.4.0"), null);

  console.log("PASS: Version comparison tests");

  // Test 0.6: NVD inclusive and exclusive version boundaries.
  const versionRange = {
    criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    versionStartIncluding: "2.4.50",
    versionEndExcluding: "2.4.60",
  };

  assert.equal(matchesVersionRange(versionRange, "2.4.50"), true);
  assert.equal(matchesVersionRange(versionRange, "2.4.55"), true);
  assert.equal(matchesVersionRange(versionRange, "2.4.60"), false);
  assert.equal(matchesVersionRange(versionRange, "2.4.49"), false);

  console.log("PASS: NVD version boundary tests");

  // Test 0.7: Match Apache product identity.
  const apacheProduct = {
    cpe: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    cpeStatus: "verified",
  };

  assert.equal(
    matchesProductIdentity(
      "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
      apacheProduct.cpe,
    ),
    true,
  );

  assert.equal(
    matchesProductIdentity(
      "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
      apacheProduct.cpe,
    ),
    false,
  );

  console.log("PASS: Product identity tests");

  // Test 0.8: Assess whether an Apache version is affected.
  const apacheCve = {
    configurations: [
      {
        nodes: [
          {
            operator: "OR",
            cpeMatch: [
              {
                vulnerable: true,
                criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                versionStartIncluding: "2.4.50",
                versionEndExcluding: "2.4.60",
              },
            ],
          },
        ],
      },
    ],
  };

  assert.equal(
    assessCveVersion(apacheCve, apacheProduct, "2.4.55"),
    "affected",
  );

  assert.equal(
    assessCveVersion(apacheCve, apacheProduct, "2.4.60"),
    "not_affected",
  );

  assert.equal(
    assessCveVersion({ configurations: [] }, apacheProduct, "2.4.55"),
    "unconfirmed",
  );

  console.log("PASS: CVE applicability tests");

  // Test 0.9: Environmental CPE conditions must not be ignored.
  const environmentalCve = {
    configurations: [
      {
        nodes: [
          {
            operator: "AND",
            cpeMatch: [
              {
                vulnerable: true,
                criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                versionStartIncluding: "2.4.50",
                versionEndExcluding: "2.4.60",
              },
              {
                vulnerable: false,
                criteria: "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
              },
            ],
          },
        ],
      },
    ],
  };

  assert.equal(
    assessCveVersion(environmentalCve, apacheProduct, "2.4.55"),
    "unconfirmed",
  );

  console.log("PASS: Environmental CPE safety test");

  // Test 0.10: Nested AND/OR configuration logic.
  const nestedCve = {
    configurations: [
      {
        nodes: [
          {
            operator: "OR",
            nodes: [
              {
                operator: "AND",
                cpeMatch: [
                  {
                    vulnerable: true,
                    criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                    versionStartIncluding: "2.4.50",
                    versionEndExcluding: "2.4.60",
                  },
                ],
              },
              {
                operator: "AND",
                cpeMatch: [
                  {
                    vulnerable: true,
                    criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                    versionStartIncluding: "2.4.70",
                    versionEndExcluding: "2.4.80",
                  },
                ],
              },
            ],
          },
        ],
      },
    ],
  };

  assert.equal(
    assessCveVersion(nestedCve, apacheProduct, "2.4.55"),
    "affected",
  );

  console.log("PASS: Nested AND/OR configuration test");

  // Test 0.11: Unsupported version boundaries must remain unconfirmed.
  const unsupportedRangeCve = {
    configurations: [
      {
        nodes: [
          {
            operator: "OR",
            cpeMatch: [
              {
                vulnerable: true,
                criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                versionStartIncluding: "2.4.x",
              },
            ],
          },
        ],
      },
    ],
  };

  assert.equal(
    assessCveVersion(unsupportedRangeCve, apacheProduct, "2.4.55"),
    "unconfirmed",
  );

  console.log("PASS: Unsupported version range safety test");

  // Test 0.12: Negated configuration nodes.
  const negatedCve = {
    configurations: [
      {
        nodes: [
          {
            operator: "OR",
            negate: true,
            cpeMatch: [
              {
                vulnerable: true,
                criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                versionStartIncluding: "2.4.50",
                versionEndExcluding: "2.4.60",
              },
            ],
          },
        ],
      },
    ],
  };

  assert.equal(
    assessCveVersion(negatedCve, apacheProduct, "2.4.55"),
    "not_affected",
  );

  assert.equal(
    assessCveVersion(negatedCve, apacheProduct, "2.4.65"),
    "affected",
  );

  console.log("PASS: Negated configuration test");

  // Test 0.13: Invalid CPE identity must remain unconfirmed.
  const invalidIdentityCve = {
    configurations: [
      {
        nodes: [
          {
            operator: "OR",
            cpeMatch: [
              {
                vulnerable: true,
                criteria: "invalid-cpe-format",
              },
            ],
          },
        ],
      },
    ],
  };

  assert.equal(
    assessCveVersion(invalidIdentityCve, apacheProduct, "2.4.55"),
    "unconfirmed",
  );

  console.log("PASS: Invalid CPE identity safety test");

  // Test 0.14: Version comparison edge cases.
  assert.equal(compareVersions("2.4", "2.4.0"), 0);
  assert.equal(compareVersions("2.4.1", "2.4"), 1);
  assert.equal(compareVersions("2.4.0", "2.4.1"), -1);

  // Large numeric components must not overflow.
  assert.equal(
    compareVersions("999999999999999999999", "1000000000000000000000"),
    -1,
  );

  // Unsupported version formats must remain unknown.
  assert.equal(compareVersions("2.4.1-beta", "2.4.1"), null);
  assert.equal(compareVersions("v2.4.1", "2.4.1"), null);
  assert.equal(compareVersions("2..4", "2.4"), null);

  console.log("PASS: Version comparison edge-case tests");

  // Test 0.15: Invalid versions must never be classified as affected.
  assert.equal(assessCveVersion(apacheCve, apacheProduct, ""), "unconfirmed");

  assert.equal(
    assessCveVersion(apacheCve, apacheProduct, "2.4.x"),
    "unconfirmed",
  );

  assert.equal(assessCveVersion(apacheCve, apacheProduct, null), "unconfirmed");

  console.log("PASS: Invalid version assessment tests");

  // Test 0.16: Undefined CPE version must not match every version.
  const undefinedCpeVersion = {
    configurations: [
      {
        nodes: [
          {
            operator: "OR",
            cpeMatch: [
              {
                vulnerable: true,
                criteria: "cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*",
              },
            ],
          },
        ],
      },
    ],
  };

  assert.equal(
    assessCveVersion(undefinedCpeVersion, apacheProduct, "2.4.55"),
    "unconfirmed",
  );

  console.log("PASS: Undefined CPE version safety test");

  // Test 0.17: Multiple top-level configuration alternatives.
  const multipleConfigurationsCve = {
    configurations: [
      {
        nodes: [
          {
            operator: "OR",
            cpeMatch: [
              {
                vulnerable: true,
                criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                versionStartIncluding: "2.4.50",
                versionEndExcluding: "2.4.60",
              },
            ],
          },
        ],
      },
      {
        nodes: [
          {
            operator: "OR",
            cpeMatch: [
              {
                vulnerable: true,
                criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                versionStartIncluding: "2.4.70",
                versionEndExcluding: "2.4.80",
              },
            ],
          },
        ],
      },
    ],
  };

  assert.equal(
    assessCveVersion(multipleConfigurationsCve, apacheProduct, "2.4.55"),
    "affected",
  );

  console.log("PASS: Multiple configuration alternatives test");

  // Test 0.18: Confirmed match alongside an unknown alternative.
  const mixedConfigurationsCve = {
    configurations: [
      {
        nodes: [
          {
            operator: "OR",
            cpeMatch: [
              {
                vulnerable: true,
                criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                versionStartIncluding: "2.4.50",
                versionEndExcluding: "2.4.60",
              },
            ],
          },
        ],
      },
      {
        nodes: [
          {
            operator: "OR",
            cpeMatch: [
              {
                vulnerable: false,
                criteria: "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
              },
            ],
          },
        ],
      },
    ],
  };

  assert.equal(
    assessCveVersion(mixedConfigurationsCve, apacheProduct, "2.4.55"),
    "affected",
  );

  console.log("PASS: Mixed configuration result test");

  // Test 0.19: Unknown-only configurations must remain unconfirmed.
  const unknownOnlyCve = {
    configurations: [
      {
        nodes: [
          {
            operator: "AND",
            cpeMatch: [
              {
                vulnerable: true,
                criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                versionStartIncluding: "2.4.50",
                versionEndExcluding: "2.4.60",
              },
              {
                vulnerable: false,
                criteria: "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
              },
            ],
          },
        ],
      },
    ],
  };

  assert.equal(
    assessCveVersion(unknownOnlyCve, apacheProduct, "2.4.55"),
    "unconfirmed",
  );

  console.log("PASS: Unknown-only configuration test");

  // Test 0.20: Missing operators must remain unconfirmed.
  const missingOperatorCve = {
    configurations: [
      {
        nodes: [
          {
            cpeMatch: [
              {
                vulnerable: true,
                criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                versionStartIncluding: "2.4.50",
                versionEndExcluding: "2.4.60",
              },
            ],
          },
        ],
      },
    ],
  };

  assert.equal(
    assessCveVersion(missingOperatorCve, apacheProduct, "2.4.55"),
    "unconfirmed",
  );

  console.log("PASS: Missing configuration operator test");

  // Test 0.21: Configuration-level negation.
  const negatedConfigurationCve = {
    configurations: [
      {
        negate: true,
        nodes: [
          {
            operator: "OR",
            cpeMatch: [
              {
                vulnerable: true,
                criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                versionStartIncluding: "2.4.50",
                versionEndExcluding: "2.4.60",
              },
            ],
          },
        ],
      },
    ],
  };

  assert.equal(
    assessCveVersion(negatedConfigurationCve, apacheProduct, "2.4.55"),
    "not_affected",
  );

  assert.equal(
    assessCveVersion(negatedConfigurationCve, apacheProduct, "2.4.65"),
    "affected",
  );

  console.log("PASS: Configuration-level negation test");

  // Test 1.1: Reject a missing version.
  await assert.rejects(
    searchByCpe({
      cpe: "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
    }),
    /supported confirmed version is required/i,
  );

  // Test 1.2: Reject an unsupported version.
  await assert.rejects(
    searchByCpe(
      {
        cpe: "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
        cpeStatus: "verified",
      },
      { version: "latest" },
    ),
    /supported confirmed version is required/i,
  );

  console.log("PASS: Confirmed version validation tests");

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

    const result = await searchByCpe(
      {
        cpe: "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
        cpeStatus: "verified",
      },
      { version: "1.2.3" },
    );

    assert.equal(result.totalResults, 0);
    const requestedCpe = new URL(requestedUrl).searchParams.get("cpeName");

    assert.equal(requestedCpe, "cpe:2.3:a:example:product:1.2.3:*:*:*:*:*:*:*");

    assert.ok(requestedUrl.includes("resultsPerPage=2000"));
    assert.ok(requestedUrl.includes("startIndex=0"));

    console.log("PASS: Successful NVD response test passed");
  } finally {
    globalThis.fetch = originalFetch;
  }

  // Test 4.0: Verify Nginx CPE identity and concrete NVD query
  const nginxProduct = {
    cpe: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
    cpeStatus: "verified",
  };

  assert.equal(isValidCpe23(nginxProduct.cpe), true);

  assert.equal(
    matchesProductIdentity(
      "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
      nginxProduct.cpe,
    ),
    true,
  );

  const originalFetchNginx = globalThis.fetch;
  let nginxRequestedUrl = "";

  try {
    globalThis.fetch = async (url) => {
      nginxRequestedUrl = String(url);

      return {
        ok: true,
        status: 200,
        json: async () => ({
          totalResults: 0,
          vulnerabilities: [],
        }),
      };
    };

    const nginxCveResult = await searchByCpe(nginxProduct, {
      version: "1.24.0",
      pause: 0,
    });

    const nginxRequestedCpe = new URL(nginxRequestedUrl).searchParams.get(
      "cpeName",
    );

    assert.equal(nginxCveResult.totalResults, 0);
    assert.equal(nginxRequestedCpe, "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*");

    console.log("PASS: Nginx CPE identity and NVD query test");
  } finally {
    globalThis.fetch = originalFetchNginx;
  }

  // Test 4.0.1: Verify Apache HTTP Server CPE identity and concrete NVD query
  const apacheNvdProduct = {
    cpe: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    cpeStatus: "verified",
  };

  assert.equal(isValidCpe23(apacheNvdProduct.cpe), true);

  assert.equal(
    matchesProductIdentity(
      "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
      apacheNvdProduct.cpe,
    ),
    true,
  );

  const originalFetchApache = globalThis.fetch;
  let apacheRequestedUrl = "";

  try {
    globalThis.fetch = async (url) => {
      apacheRequestedUrl = String(url);

      return {
        ok: true,
        status: 200,
        json: async () => ({
          totalResults: 0,
          vulnerabilities: [],
        }),
      };
    };

    const apacheCveResult = await searchByCpe(apacheNvdProduct, {
      version: "2.4.58",
      pause: 0,
    });

    const apacheRequestedCpe = new URL(apacheRequestedUrl).searchParams.get(
      "cpeName",
    );

    assert.equal(apacheCveResult.totalResults, 0);
    assert.equal(
      apacheRequestedCpe,
      "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*",
    );

    console.log("PASS: Apache HTTP Server CPE identity and NVD query test");
  } finally {
    globalThis.fetch = originalFetchApache;
  }

  // Test 4.0.2: Verify PHP CPE identity and concrete NVD query
  const phpNvdProduct = {
    cpe: "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
    cpeStatus: "verified",
  };

  assert.equal(isValidCpe23(phpNvdProduct.cpe), true);

  assert.equal(
    matchesProductIdentity(
      "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
      phpNvdProduct.cpe,
    ),
    true,
  );

  const originalFetchPhp = globalThis.fetch;
  let phpRequestedUrl = "";

  try {
    globalThis.fetch = async (url) => {
      phpRequestedUrl = String(url);

      return {
        ok: true,
        status: 200,
        json: async () => ({
          totalResults: 0,
          vulnerabilities: [],
        }),
      };
    };

    const phpCveResult = await searchByCpe(phpNvdProduct, {
      version: "8.2.12",
      pause: 0,
    });

    const phpRequestedCpe = new URL(phpRequestedUrl).searchParams.get(
      "cpeName",
    );

    assert.equal(phpCveResult.totalResults, 0);
    assert.equal(phpRequestedCpe, "cpe:2.3:a:php:php:8.2.12:*:*:*:*:*:*:*");

    console.log("PASS: PHP CPE identity and NVD query test");
  } finally {
    globalThis.fetch = originalFetchPhp;
  }

  // Test 4.0.3: Verify Drupal CPE identity and concrete NVD query
  const drupalNvdProduct = {
    cpe: "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*",
    cpeStatus: "verified",
  };

  assert.equal(isValidCpe23(drupalNvdProduct.cpe), true);

  assert.equal(
    matchesProductIdentity(
      "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*",
      drupalNvdProduct.cpe,
    ),
    true,
  );

  const originalFetchDrupal = globalThis.fetch;
  let drupalRequestedUrl = "";

  try {
    globalThis.fetch = async (url) => {
      drupalRequestedUrl = String(url);

      return {
        ok: true,
        status: 200,
        json: async () => ({
          totalResults: 0,
          vulnerabilities: [],
        }),
      };
    };

    const drupalCveResult = await searchByCpe(drupalNvdProduct, {
      version: "10.3.6",
      pause: 0,
    });

    const drupalRequestedCpe = new URL(drupalRequestedUrl).searchParams.get(
      "cpeName",
    );

    assert.equal(drupalCveResult.totalResults, 0);
    assert.equal(
      drupalRequestedCpe,
      "cpe:2.3:a:drupal:drupal:10.3.6:*:*:*:*:*:*:*",
    );

    console.log("PASS: Drupal CPE identity and NVD query test");
  } finally {
    globalThis.fetch = originalFetchDrupal;
  }

  // Test 4.0.4: Verify Joomla CPE identity and concrete NVD query
  const joomlaNvdProduct = {
    cpe: "cpe:2.3:a:joomla:joomla\\!:*:*:*:*:*:*:*:*",
    cpeStatus: "verified",
  };

  assert.equal(isValidCpe23(joomlaNvdProduct.cpe), true);

  assert.equal(
    matchesProductIdentity(
      "cpe:2.3:a:joomla:joomla\\!:*:*:*:*:*:*:*:*",
      joomlaNvdProduct.cpe,
    ),
    true,
  );

  const originalFetchJoomla = globalThis.fetch;
  let joomlaRequestedUrl = "";

  try {
    globalThis.fetch = async (url) => {
      joomlaRequestedUrl = String(url);

      return {
        ok: true,
        status: 200,
        json: async () => ({
          totalResults: 0,
          vulnerabilities: [],
        }),
      };
    };

    const joomlaCveResult = await searchByCpe(joomlaNvdProduct, {
      version: "5.2.3",
      pause: 0,
    });

    const joomlaRequestedCpe = new URL(joomlaRequestedUrl).searchParams.get(
      "cpeName",
    );

    assert.equal(joomlaCveResult.totalResults, 0);
    assert.equal(
      joomlaRequestedCpe,
      "cpe:2.3:a:joomla:joomla\\!:5.2.3:*:*:*:*:*:*:*",
    );

    console.log("PASS: Joomla CPE identity and NVD query test");
  } finally {
    globalThis.fetch = originalFetchJoomla;
  }

  // Test 4.0.5: Verify Magento CPE identity and concrete NVD query
  const magentoNvdProduct = {
    cpe: "cpe:2.3:a:adobe:magento:*:*:*:*:open_source:*:*:*",
    cpeStatus: "verified",
  };

  assert.equal(isValidCpe23(magentoNvdProduct.cpe), true);

  assert.equal(
    matchesProductIdentity(
      "cpe:2.3:a:adobe:magento:*:*:*:*:open_source:*:*:*",
      magentoNvdProduct.cpe,
    ),
    true,
  );

  const originalFetchMagento = globalThis.fetch;
  let magentoRequestedUrl = "";

  try {
    globalThis.fetch = async (url) => {
      magentoRequestedUrl = String(url);

      return {
        ok: true,
        status: 200,
        json: async () => ({
          totalResults: 0,
          vulnerabilities: [],
        }),
      };
    };

    const magentoCveResult = await searchByCpe(magentoNvdProduct, {
      version: "2.4.7",
      pause: 0,
    });

    const magentoRequestedCpe = new URL(magentoRequestedUrl).searchParams.get(
      "cpeName",
    );

    assert.equal(magentoCveResult.totalResults, 0);
    assert.equal(
      magentoRequestedCpe,
      "cpe:2.3:a:adobe:magento:2.4.7:*:*:*:open_source:*:*:*",
    );

    console.log("PASS: Magento CPE identity and NVD query test");
  } finally {
    globalThis.fetch = originalFetchMagento;
  }

  // Test 4.0.6: Verify Apache Tomcat CPE identity and concrete NVD query
  const tomcatNvdProduct = {
    cpe: "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
    cpeStatus: "verified",
  };

  assert.equal(isValidCpe23(tomcatNvdProduct.cpe), true);

  assert.equal(
    matchesProductIdentity(
      "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
      tomcatNvdProduct.cpe,
    ),
    true,
  );

  const originalFetchTomcat = globalThis.fetch;
  let tomcatRequestedUrl = "";

  try {
    globalThis.fetch = async (url) => {
      tomcatRequestedUrl = String(url);

      return {
        ok: true,
        status: 200,
        json: async () => ({
          totalResults: 0,
          vulnerabilities: [],
        }),
      };
    };

    // Synthetic version used only to verify CPE query construction.
    const tomcatCveResult = await searchByCpe(tomcatNvdProduct, {
      version: "10.1.36",
      pause: 0,
    });

    const tomcatRequestedCpe = new URL(tomcatRequestedUrl).searchParams.get(
      "cpeName",
    );

    assert.equal(tomcatCveResult.totalResults, 0);
    assert.equal(
      tomcatRequestedCpe,
      "cpe:2.3:a:apache:tomcat:10.1.36:*:*:*:*:*:*:*",
    );

    console.log("PASS: Apache Tomcat CPE identity and NVD query test");
  } finally {
    globalThis.fetch = originalFetchTomcat;
  }

  // Test 4.0.7: Verify Django CPE identity and concrete NVD query
  const djangoNvdProduct = {
    cpe: "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*",
    cpeStatus: "verified",
  };

  assert.equal(isValidCpe23(djangoNvdProduct.cpe), true);

  assert.equal(
    matchesProductIdentity(
      "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*",
      djangoNvdProduct.cpe,
    ),
    true,
  );

  const originalFetchDjango = globalThis.fetch;
  let djangoRequestedUrl = "";

  try {
    globalThis.fetch = async (url) => {
      djangoRequestedUrl = String(url);

      return {
        ok: true,
        status: 200,
        json: async () => ({
          totalResults: 0,
          vulnerabilities: [],
        }),
      };
    };

    const djangoCveResult = await searchByCpe(djangoNvdProduct, {
      version: "5.1.6",
      pause: 0,
    });

    const djangoRequestedCpe = new URL(djangoRequestedUrl).searchParams.get(
      "cpeName",
    );

    assert.equal(djangoCveResult.totalResults, 0);
    assert.equal(
      djangoRequestedCpe,
      "cpe:2.3:a:djangoproject:django:5.1.6:*:*:*:*:*:*:*",
    );

    console.log("PASS: Django CPE identity and NVD query test");
  } finally {
    globalThis.fetch = originalFetchDjango;
  }

  // Test 4.0.8: Verify Laravel CPE identity and concrete NVD query
  const laravelNvdProduct = {
    cpe: "cpe:2.3:a:laravel:framework:*:*:*:*:*:*:*:*",
    cpeStatus: "verified",
  };

  assert.equal(isValidCpe23(laravelNvdProduct.cpe), true);

  assert.equal(
    matchesProductIdentity(
      "cpe:2.3:a:laravel:framework:*:*:*:*:*:*:*:*",
      laravelNvdProduct.cpe,
    ),
    true,
  );

  const originalFetchLaravel = globalThis.fetch;
  let laravelRequestedUrl = "";

  try {
    globalThis.fetch = async (url) => {
      laravelRequestedUrl = String(url);

      return {
        ok: true,
        status: 200,
        json: async () => ({
          totalResults: 0,
          vulnerabilities: [],
        }),
      };
    };

    const laravelCveResult = await searchByCpe(laravelNvdProduct, {
      version: "12.22.0",
      pause: 0,
    });

    const laravelRequestedCpe = new URL(laravelRequestedUrl).searchParams.get(
      "cpeName",
    );

    assert.equal(laravelCveResult.totalResults, 0);
    assert.equal(
      laravelRequestedCpe,
      "cpe:2.3:a:laravel:framework:12.22.0:*:*:*:*:*:*:*",
    );

    console.log("PASS: Laravel CPE identity and NVD query test");
  } finally {
    globalThis.fetch = originalFetchLaravel;
  }

  // Test 4.1: Fetch multiple NVD result pages.
  const originalFetchPagination = globalThis.fetch;
  const requestedPages = [];

  try {
    globalThis.fetch = async (url) => {
      const parsedUrl = new URL(String(url));
      const startIndex = Number(parsedUrl.searchParams.get("startIndex"));

      requestedPages.push(startIndex);

      return {
        ok: true,
        status: 200,
        json: async () => {
          if (startIndex === 0) {
            return {
              totalResults: 2,
              vulnerabilities: [
                {
                  cve: {
                    id: "CVE-2025-11111",
                    descriptions: [],
                  },
                },
              ],
            };
          }

          return {
            totalResults: 2,
            vulnerabilities: [
              {
                cve: {
                  id: "CVE-2025-22222",
                  descriptions: [],
                },
              },
            ],
          };
        },
      };
    };

    const result = await searchByCpe(
      {
        cpe: "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
        cpeStatus: "verified",
      },
      { pause: 0, version: "1.2.3" },
    );

    assert.deepEqual(requestedPages, [0, 1]);
    assert.equal(result.totalResults, 2);
    assert.equal(result.vulnerabilities.length, 2);
    assert.equal(result.vulnerabilities[0].id, "CVE-2025-11111");
    assert.equal(result.vulnerabilities[1].id, "CVE-2025-22222");

    console.log("PASS: Multi-page NVD pagination test");
  } finally {
    globalThis.fetch = originalFetchPagination;
  }

  // Test 4.2: Advance pagination when a malformed record is returned.
  const originalFetchMalformed = globalThis.fetch;
  const malformedPageOffsets = [];

  try {
    globalThis.fetch = async (url) => {
      const parsedUrl = new URL(String(url));
      const startIndex = Number(parsedUrl.searchParams.get("startIndex"));

      malformedPageOffsets.push(startIndex);

      if (startIndex === 0) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            totalResults: 3,
            vulnerabilities: [
              null,
              {
                cve: {
                  id: "CVE-2025-33333",
                  descriptions: [],
                },
              },
            ],
          }),
        };
      }

      return {
        ok: true,
        status: 200,
        json: async () => ({
          totalResults: 2,
          vulnerabilities: [
            {
              cve: {
                id: "CVE-2025-44444",
                descriptions: [],
              },
            },
          ],
        }),
      };
    };

    const result = await searchByCpe(
      {
        cpe: "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
        cpeStatus: "verified",
      },
      { pause: 0, version: "1.2.3" },
    );

    assert.deepEqual(malformedPageOffsets, [0, 2]);
    assert.equal(result.vulnerabilities.length, 2);
    assert.equal(result.vulnerabilities[0].id, "CVE-2025-33333");
    assert.equal(result.vulnerabilities[1].id, "CVE-2025-44444");

    console.log("PASS: Malformed-record pagination test");
  } finally {
    globalThis.fetch = originalFetchMalformed;
  }

  // Test 5: Handle NVD rate limits and server errors.
  const originalFetchErrors = globalThis.fetch;

  try {
    globalThis.fetch = async () => ({
      ok: false,
      status: 429,
    });

    await assert.rejects(
      searchByCpe(
        {
          cpe: "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
          cpeStatus: "verified",
        },
        { version: "1.2.3" },
      ),
      /rate limit reached/i,
    );

    globalThis.fetch = async () => ({
      ok: false,
      status: 403,
    });

    await assert.rejects(
      searchByCpe(
        {
          cpe: "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
          cpeStatus: "verified",
        },
        { version: "1.2.3" },
      ),
      /rate limit reached/i,
    );

    globalThis.fetch = async () => ({
      ok: false,
      status: 500,
    });

    await assert.rejects(
      searchByCpe(
        {
          cpe: "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
          cpeStatus: "verified",
        },
        { version: "1.2.3" },
      ),
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
