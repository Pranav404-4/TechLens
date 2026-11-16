"use strict";

const assert = require("node:assert/strict");
const { detect, RULES } = require("./detector.js");

function names(input) {
  return detect(input).map((item) => item.name);
}

// 1. Detect Fathom Analytics
assert.ok(
  names({
    page: {
      scripts: ["https://cdn.usefathom.com/script.js"],
    },
  }).includes("Fathom Analytics"),
);

// 2. Detect Umami
assert.ok(
  names({
    page: {
      scripts: ["https://cloud.umami.is/script.js"],
    },
  }).includes("Umami"),
);

// 3. Case-insensitive matching
assert.ok(
  names({
    page: {
      scripts: ["https://CDN.USEFATHOM.COM/SCRIPT.JS"],
    },
  }).includes("Fathom Analytics"),
);

// 4. Do not detect Fathom without matching evidence
assert.ok(
  !names({
    page: {
      scripts: ["https://example.com/analytics.js"],
    },
  }).includes("Fathom Analytics"),
);

// 5. Detect Nginx version from response header
const nginx = detect({
  page: {},
  headers: [{ name: "server", value: "nginx/1.26.2" }],
}).find((item) => item.name === "Nginx");

assert.ok(nginx, "Nginx should be detected");
assert.equal(nginx.version, "1.26.2");

// 6. Detect version from versionHints
const react = detect({
  page: {
    versionHints: [{ name: "React", version: "19.0.0" }],
    globals: ["React"],
  },
}).find((item) => item.name === "React");

assert.ok(react, "React should be detected");
assert.equal(react.version, "19.0.0");

// 7. Verify confidence never exceeds 99
const results = detect({
  page: {
    scripts: [
      "https://cdn.usefathom.com/script.js",
      "https://cdn.usefathom.com/script.js?extra=true",
    ],
  },
});

for (const result of results) {
  assert.ok(result.confidence <= 99);
}

// 8. Results must be sorted by confidence
for (let i = 1; i < results.length; i++) {
  assert.ok(results[i - 1].confidence >= results[i].confidence);
}

// 9. Django: CSRF cookie alone must not identify Django
assert.ok(
  !names({
    page: { cookies: ["csrftoken"] },
  }).includes("Django"),
);

// 10. Laravel: XSRF cookie alone must not identify Laravel
assert.ok(
  !names({
    page: { cookies: ["xsrf-token"] },
  }).includes("Laravel"),
);

// 11. Java / Spring: JSESSIONID alone must not identify Spring
assert.ok(
  !names({
    page: { cookies: ["JSESSIONID"] },
  }).includes("Java / Spring"),
);

// 12. Ruby on Rails: X-Runtime alone must not identify Rails
assert.ok(
  !names({
    page: {},
    headers: [{ name: "X-Runtime", value: "0.012" }],
  }).includes("Ruby on Rails"),
);

// 13. ASP.NET Core: X-AspNet-Version alone must not identify ASP.NET Core
assert.ok(
  !names({
    page: {},
    headers: [{ name: "X-AspNet-Version", value: "8.0" }],
  }).includes("ASP.NET Core"),
);

// 14. Django: specific cookie identifies Django
assert.ok(
  names({
    page: { cookies: ["django_language"] },
  }).includes("Django"),
);

// 15. Laravel: specific cookie identifies Laravel
assert.ok(
  names({
    page: { cookies: ["laravel_session"] },
  }).includes("Laravel"),
);

// 16. Java / Spring: specific header identifies Spring
assert.ok(
  names({
    page: {},
    headers: [{ name: "X-Application-Context", value: "application" }],
  }).includes("Java / Spring"),
);

// 17. Ruby on Rails: specific cookie identifies Rails
assert.ok(
  names({
    page: { cookies: ["_session_id"] },
  }).includes("Ruby on Rails"),
);

// 18. ASP.NET Core: specific cookie identifies ASP.NET Core
assert.ok(
  names({
    page: { cookies: [".AspNetCore.Session"] },
  }).includes("ASP.NET Core"),
);

// 19. Fathom exposes its new technology ID and product identity
const fathom = detect({
  page: {
    scripts: ["https://cdn.usefathom.com/script.js"],
  },
}).find((item) => item.name === "Fathom Analytics");

assert.equal(fathom.id, "fathom-analytics");
assert.equal(fathom.product.vendor, "Fathom");
assert.equal(fathom.product.name, "Fathom Analytics");

// 20. Umami supports its second script signature
const umami = detect({
  page: {
    scripts: ["https://analytics.umami.is/script.js"],
  },
}).find((item) => item.name === "Umami");

assert.equal(umami.id, "umami");

// 21. Simple Analytics exposes its product identity
const simpleAnalytics = detect({
  page: {
    scripts: ["https://scripts.simpleanalyticscdn.com/latest.js"],
  },
}).find((item) => item.name === "Simple Analytics");

assert.equal(simpleAnalytics.id, "simple-analytics");
assert.equal(simpleAnalytics.product.vendor, "Simple Analytics");

// 22. Legacy Django rule still works
assert.ok(
  names({
    page: { cookies: ["django_language"] },
  }).includes("Django"),
);

// 23. Exact signature matching detects an exact value
const equalsProbe = {
  id: "equals-probe",
  name: "Equals Probe",
  category: "Testing",
  confidence: 95,
  signatures: [
    {
      type: "global",
      pattern: "techlens-equals-probe",
      match: "equals",
      weight: 95,
    },
  ],
};

RULES.push(equalsProbe);

assert.ok(
  names({
    page: { globals: ["techlens-equals-probe"] },
  }).includes("Equals Probe"),
);

// 24. Exact signature matching rejects a longer value
assert.ok(
  !names({
    page: { globals: ["prefix-techlens-equals-probe"] },
  }).includes("Equals Probe"),
);

RULES.pop();

// 25. A single signature uses its configured weight
const weightProbe = {
  id: "weight-probe",
  name: "Weight Probe",
  category: "Testing",
  confidence: 95,
  signatures: [
    {
      type: "global",
      pattern: "weight-probe-one",
      match: "equals",
      weight: 95,
    },
    {
      type: "global",
      pattern: "weight-probe-two",
      match: "equals",
      weight: 70,
    },
  ],
};

RULES.push(weightProbe);

const singleWeight = detect({
  page: { globals: ["weight-probe-one"] },
}).find((item) => item.name === "Weight Probe");

assert.equal(singleWeight.confidence, 95);

// 26. Multiple matching signatures use their average weight
const multipleWeights = detect({
  page: {
    globals: ["weight-probe-one", "weight-probe-two"],
  },
}).find((item) => item.name === "Weight Probe");

assert.equal(multipleWeights.confidence, 83);

// 27. Missing weight defaults to 70
const missingWeightProbe = {
  id: "missing-weight-probe",
  name: "Missing Weight Probe",
  category: "Testing",
  signatures: [
    {
      type: "global",
      pattern: "missing-weight-probe",
      match: "equals",
    },
  ],
};

RULES.push(missingWeightProbe);

const missingWeight = detect({
  page: { globals: ["missing-weight-probe"] },
}).find((item) => item.name === "Missing Weight Probe");

assert.equal(missingWeight.confidence, 70);

// 28. Legacy rules retain their original confidence calculation
const legacyProbe = {
  name: "Legacy Probe",
  category: "Testing",
  confidence: 80,
  tests: [["global", "legacy-probe"]],
};

RULES.push(legacyProbe);

const legacyResult = detect({
  page: { globals: ["legacy-probe"] },
}).find((item) => item.name === "Legacy Probe");

assert.equal(legacyResult.confidence, 80);

RULES.pop();
RULES.pop();
RULES.pop();

// 29–33. Version resolver tests
const versionProbe = {
  id: "version-probe",
  name: "Version Resolver Probe",
  category: "Testing",
  signatures: [
    {
      type: "global",
      pattern: "version-resolver-probe",
      match: "equals",
      weight: 95,
    },
  ],
};

RULES.push(versionProbe);

// 29. Runtime evidence wins over weaker resource evidence
const runtimePreferred = detect({
  page: {
    globals: ["version-resolver-probe"],
    versionHints: [
      {
        name: "Version Resolver Probe",
        version: "2.0.0",
        source: "runtime",
        confidence: 95,
      },
      {
        name: "Version Resolver Probe",
        version: "1.5.0",
        source: "resource",
        confidence: 85,
      },
    ],
  },
}).find((item) => item.name === "Version Resolver Probe");

assert.equal(runtimePreferred.version, "2.0.0");
assert.equal(runtimePreferred.versionInfo.source, "runtime");
assert.equal(runtimePreferred.versionInfo.status, "confirmed");

// 30. Bundle evidence wins over weaker metadata
const bundlePreferred = detect({
  page: {
    globals: ["version-resolver-probe"],
    versionHints: [
      {
        name: "Version Resolver Probe",
        version: "3.0.0",
        source: "bundle",
        confidence: 95,
      },
      {
        name: "Version Resolver Probe",
        version: "2.5.0",
        source: "meta",
        confidence: 90,
      },
    ],
  },
}).find((item) => item.name === "Version Resolver Probe");

assert.equal(bundlePreferred.version, "3.0.0");
assert.equal(bundlePreferred.versionInfo.source, "bundle");

// 31. Equal-strength conflicting versions are ambiguous
const ambiguousVersion = detect({
  page: {
    globals: ["version-resolver-probe"],
    versionHints: [
      {
        name: "Version Resolver Probe",
        version: "4.0.0",
        source: "runtime",
        confidence: 95,
      },
      {
        name: "Version Resolver Probe",
        version: "4.1.0",
        source: "runtime",
        confidence: 95,
      },
    ],
  },
}).find((item) => item.name === "Version Resolver Probe");

assert.equal(ambiguousVersion.version, null);
assert.equal(ambiguousVersion.versionInfo.status, "ambiguous");

// 32. Missing version information returns unknown
const unknownVersion = detect({
  page: {
    globals: ["version-resolver-probe"],
  },
}).find((item) => item.name === "Version Resolver Probe");

assert.equal(unknownVersion.version, null);
assert.equal(unknownVersion.versionInfo.status, "unknown");

RULES.pop();

// 33. Existing server-header version detection still works
const nginxResult = detect({
  headers: [
    {
      name: "server",
      value: "nginx/1.24.0",
    },
  ],
}).find((item) => item.name === "Nginx");

assert.equal(nginxResult.version, "1.24.0");
assert.equal(nginxResult.versionInfo.status, "confirmed");

// 34. Product metadata validation
const migratedProducts = [
  "Fathom Analytics",
  "Umami",
  "Simple Analytics",
];

for (const name of migratedProducts) {
  const rule = RULES.find((item) => item.name === name);

  assert.ok(rule, `${name} rule should exist`);
  assert.ok(rule.product, `${name} should have product metadata`);
  assert.ok(rule.product.vendor, `${name} should have a vendor`);
  assert.ok(rule.product.name, `${name} should have a product name`);
  assert.equal(rule.product.cpe, null);
  assert.equal(rule.product.cpeStatus, "unmapped");
  assert.equal(rule.product.purl, null);
  assert.deepEqual(rule.product.aliases, []);
  assert.equal(rule.product.versionScope, "unknown");
}

console.log("PASS: Product metadata validation tests passed");

console.log("PASS: All detector baseline and false-positive tests passed");
