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

// 14.1. Django verified CPE metadata
const djangoRule = RULES.find((item) => item.name === "Django");

assert.ok(djangoRule, "Django rule should exist");
assert.equal(djangoRule.id, "django");
assert.equal(djangoRule.product.vendor, "djangoproject");
assert.equal(djangoRule.product.name, "django");
assert.equal(
  djangoRule.product.cpe,
  "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*",
);
assert.equal(djangoRule.product.cpeStatus, "verified");
assert.equal(djangoRule.product.versionScope, "server");

console.log("PASS: Django verified CPE metadata");

// Laravel verified CPE metadata
const laravelRule = RULES.find((item) => item.name === "Laravel");

assert.ok(laravelRule, "Laravel rule should exist");
assert.equal(laravelRule.id, "laravel");
assert.equal(laravelRule.product.vendor, "laravel");
assert.equal(laravelRule.product.name, "framework");
assert.equal(
  laravelRule.product.cpe,
  "cpe:2.3:a:laravel:framework:*:*:*:*:*:*:*:*",
);
assert.equal(laravelRule.product.cpeStatus, "verified");
assert.equal(laravelRule.product.purl, "pkg:composer/laravel/framework");
assert.equal(laravelRule.product.versionScope, "server");

console.log("PASS: Laravel verified CPE metadata");

// Laravel cookie detection must not invent a version
const laravelDetection = detect({
  page: {
    cookies: ["laravel_session"],
  },
}).find((item) => item.name === "Laravel");

assert.ok(laravelDetection, "Laravel should be detected");
assert.equal(laravelDetection.id, "laravel");
assert.equal(laravelDetection.version, null);
assert.equal(laravelDetection.versionInfo.status, "unknown");
assert.equal(laravelDetection.cve.eligible, false);
assert.equal(
  laravelDetection.cve.cpe,
  "cpe:2.3:a:laravel:framework:*:*:*:*:*:*:*:*",
);
assert.equal(laravelDetection.cve.version, null);
assert.equal(
  laravelDetection.cve.reason,
  "A confirmed technology version is required.",
);

console.log("PASS: Laravel cookie detection does not invent a version");

// Symfony metadata validation
const symfonyRule = RULES.find((item) => item.name === "Symfony");

assert.ok(symfonyRule, "Symfony rule should exist");
assert.equal(symfonyRule.id, "symfony");
assert.equal(symfonyRule.product.vendor, "sensiolabs");
assert.equal(symfonyRule.product.name, "symfony");
assert.equal(
  symfonyRule.product.cpe,
  "cpe:2.3:a:sensiolabs:symfony:*:*:*:*:*:*:*:*",
);
assert.equal(symfonyRule.product.cpeStatus, "verified");
assert.equal(symfonyRule.product.purl, "pkg:composer/symfony/symfony");
assert.equal(symfonyRule.product.versionScope, "server");

console.log("PASS: Symfony metadata");

// Symfony X-Debug-Token detection must not invent a version
const symfonyTokenDetection = detect({
  page: {},
  headers: [{ name: "X-Debug-Token", value: "abc123" }],
}).find((item) => item.name === "Symfony");

assert.ok(
  symfonyTokenDetection,
  "Symfony should be detected from X-Debug-Token",
);
assert.equal(symfonyTokenDetection.id, "symfony");
assert.equal(symfonyTokenDetection.version, null);
assert.equal(symfonyTokenDetection.versionInfo.status, "unknown");
assert.equal(symfonyTokenDetection.cve.eligible, false);
assert.equal(
  symfonyTokenDetection.cve.cpe,
  "cpe:2.3:a:sensiolabs:symfony:*:*:*:*:*:*:*:*",
);
assert.equal(symfonyTokenDetection.cve.version, null);

console.log("PASS: Symfony X-Debug-Token detection");

// Symfony X-Debug-Token-Link detection must not invent a version
const symfonyLinkDetection = detect({
  page: {},
  headers: [
    {
      name: "X-Debug-Token-Link",
      value: "/_profiler/abc123",
    },
  ],
}).find((item) => item.name === "Symfony");

assert.ok(
  symfonyLinkDetection,
  "Symfony should be detected from X-Debug-Token-Link",
);
assert.equal(symfonyLinkDetection.id, "symfony");
assert.equal(symfonyLinkDetection.version, null);
assert.equal(symfonyLinkDetection.versionInfo.status, "unknown");
assert.equal(symfonyLinkDetection.cve.eligible, false);
assert.equal(
  symfonyLinkDetection.cve.cpe,
  "cpe:2.3:a:sensiolabs:symfony:*:*:*:*:*:*:*:*",
);
assert.equal(symfonyLinkDetection.cve.version, null);

console.log("PASS: Symfony X-Debug-Token-Link detection");

// CodeIgniter metadata validation
const codeigniterRule = RULES.find((item) => item.name === "CodeIgniter");

assert.ok(codeigniterRule, "CodeIgniter rule should exist");
assert.equal(codeigniterRule.id, "codeigniter");
assert.equal(codeigniterRule.product.vendor, "codeigniter");
assert.equal(codeigniterRule.product.name, "codeigniter");
assert.equal(
  codeigniterRule.product.cpe,
  "cpe:2.3:a:codeigniter:codeigniter:*:*:*:*:*:*:*:*",
);
assert.equal(codeigniterRule.product.cpeStatus, "verified");
assert.equal(codeigniterRule.product.purl, null);
assert.equal(codeigniterRule.product.versionScope, "server");

console.log("PASS: CodeIgniter metadata");

// CodeIgniter cookie detection must not invent a version
const codeigniterDetection = detect({
  page: {
    cookies: ["ci_session"],
  },
}).find((item) => item.name === "CodeIgniter");

assert.ok(codeigniterDetection, "CodeIgniter should be detected");
assert.equal(codeigniterDetection.id, "codeigniter");
assert.equal(codeigniterDetection.version, null);
assert.equal(codeigniterDetection.versionInfo.status, "unknown");
assert.equal(codeigniterDetection.cve.eligible, false);
assert.equal(
  codeigniterDetection.cve.cpe,
  "cpe:2.3:a:codeigniter:codeigniter:*:*:*:*:*:*:*:*",
);
assert.equal(codeigniterDetection.cve.version, null);
assert.equal(
  codeigniterDetection.cve.reason,
  "A confirmed technology version is required.",
);
console.log("PASS: CodeIgniter cookie detection does not invent a version");

// 14.2. Django cookie detection must not invent a version
const djangoDetection = detect({
  page: {
    cookies: ["django_language"],
  },
}).find((item) => item.name === "Django");

assert.ok(djangoDetection, "Django should be detected");
assert.equal(djangoDetection.id, "django");
assert.equal(djangoDetection.version, null);
assert.equal(djangoDetection.versionInfo.status, "unknown");
assert.equal(djangoDetection.cve.eligible, false);
assert.equal(
  djangoDetection.cve.cpe,
  "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*",
);
assert.equal(djangoDetection.cve.version, null);
assert.equal(
  djangoDetection.cve.reason,
  "A confirmed technology version is required.",
);

console.log("PASS: Django cookie detection does not invent a version");

// 14.3. Generic session cookies must not identify Flask
const flaskDetection = detect({
  page: {
    cookies: ["session"],
  },
}).find((item) => item.name === "Flask");

assert.equal(
  flaskDetection,
  undefined,
  "Generic session cookie must not identify Flask",
);

console.log("PASS: Generic session cookie does not falsely identify Flask");

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

assert.ok(fathom, "Fathom Analytics should be detected");
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
// Simple Analytics detection and metadata
const simpleAnalyticsDetection = detect({
  page: {
    scripts: ["https://scripts.simpleanalyticscdn.com/latest.js"],
  },
}).find((item) => item.name === "Simple Analytics");

assert.ok(simpleAnalyticsDetection, "Simple Analytics should be detected");
assert.equal(simpleAnalyticsDetection.id, "simple-analytics");
assert.equal(simpleAnalyticsDetection.product.vendor, "Simple Analytics");
assert.equal(simpleAnalyticsDetection.product.name, "Simple Analytics");
assert.equal(simpleAnalyticsDetection.product.cpe, null);
assert.equal(simpleAnalyticsDetection.product.cpeStatus, "unmapped");
assert.equal(simpleAnalyticsDetection.product.purl, null);
assert.equal(simpleAnalyticsDetection.product.versionScope, "unknown");

console.log("PASS: Simple Analytics detection and metadata");

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
const migratedProducts = ["Fathom Analytics", "Umami", "Simple Analytics"];

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

// 35. WordPress verified CPE metadata
const wordpressRule = RULES.find((item) => item.name === "WordPress");

assert.ok(wordpressRule, "WordPress rule should exist");
assert.equal(wordpressRule.product.vendor, "wordpress");
assert.equal(wordpressRule.product.name, "wordpress");
assert.equal(
  wordpressRule.product.cpe,
  "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
);
assert.equal(wordpressRule.product.cpeStatus, "verified");
assert.equal(wordpressRule.product.versionScope, "server");

console.log("PASS: WordPress verified CPE metadata test");

// 36. WordPress confirmed version reaches CVE readiness
const wordpressDetection = detect({
  page: {
    meta: ["generator:wordpress"],
    versionHints: [
      {
        name: "WordPress",
        version: "6.7.1",
        source: "meta",
        confidence: 90,
      },
    ],
  },
}).find((item) => item.name === "WordPress");

assert.ok(wordpressDetection, "WordPress detection should exist");
assert.equal(wordpressDetection.id, "wordpress");
assert.equal(wordpressDetection.version, "6.7.1");
assert.equal(wordpressDetection.versionInfo.status, "confirmed");
assert.equal(wordpressDetection.cve.eligible, true);
assert.equal(
  wordpressDetection.cve.cpe,
  "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
);
assert.equal(wordpressDetection.cve.version, "6.7.1");

console.log("PASS: WordPress confirmed version reaches CVE readiness");

// 37. Nginx confirmed version reaches CVE readiness
const nginxDetection = detect({
  headers: [
    {
      name: "server",
      value: "nginx/1.24.0",
    },
  ],
}).find((item) => item.name === "Nginx");

assert.ok(nginxDetection, "Nginx detection should exist");
assert.equal(nginxDetection.id, "nginx");
assert.equal(nginxDetection.version, "1.24.0");
assert.equal(nginxDetection.versionInfo.status, "confirmed");
assert.equal(nginxDetection.cve.eligible, true);
assert.equal(nginxDetection.cve.cpe, "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*");
assert.equal(nginxDetection.cve.version, "1.24.0");

console.log("PASS: Nginx confirmed version reaches CVE readiness");

// 38. Apache HTTP Server confirmed version reaches CVE readiness
const apacheDetection = detect({
  headers: [
    {
      name: "server",
      value: "Apache/2.4.58",
    },
  ],
}).find((item) => item.name === "Apache HTTP Server");

assert.ok(apacheDetection, "Apache HTTP Server detection should exist");
assert.equal(apacheDetection.id, "apache-http-server");
assert.equal(apacheDetection.version, "2.4.58");
assert.equal(apacheDetection.versionInfo.status, "confirmed");
assert.equal(apacheDetection.cve.eligible, true);
assert.equal(
  apacheDetection.cve.cpe,
  "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
);
assert.equal(apacheDetection.cve.version, "2.4.58");

console.log("PASS: Apache HTTP Server confirmed version reaches CVE readiness");

// 39. PHP confirmed version reaches CVE readiness
const phpDetection = detect({
  headers: [
    {
      name: "x-powered-by",
      value: "PHP/8.2.12",
    },
  ],
}).find((item) => item.name === "PHP");

assert.ok(phpDetection, "PHP detection should exist");
assert.equal(phpDetection.id, "php");
assert.equal(phpDetection.version, "8.2.12");
assert.equal(phpDetection.versionInfo.status, "confirmed");
assert.equal(phpDetection.cve.eligible, true);
assert.equal(phpDetection.cve.cpe, "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*");
assert.equal(phpDetection.cve.version, "8.2.12");

console.log("PASS: PHP confirmed version reaches CVE readiness");

// 40. PHP session cookie does not invent a version
const phpCookieDetection = detect({
  headers: [],
  page: {
    cookies: ["PHPSESSID=abc123"],
  },
}).find((item) => item.name === "PHP");

assert.ok(phpCookieDetection, "PHP cookie detection should exist");
assert.equal(phpCookieDetection.version, null);
assert.equal(phpCookieDetection.cve.eligible, false);

console.log("PASS: PHP session cookie does not invent a version");

// 41. Drupal confirmed version reaches CVE readiness
const drupalDetection = detect({
  page: {
    meta: ["generator:drupal"],
    versionHints: [
      {
        name: "Drupal",
        version: "10.3.6",
        source: "meta",
        confidence: 90,
      },
    ],
  },
}).find((item) => item.name === "Drupal");

assert.ok(drupalDetection, "Drupal detection should exist");
assert.equal(drupalDetection.id, "drupal");
assert.equal(drupalDetection.version, "10.3.6");
assert.equal(drupalDetection.versionInfo.status, "confirmed");
assert.equal(drupalDetection.cve.eligible, true);
assert.equal(
  drupalDetection.cve.cpe,
  "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*",
);
assert.equal(drupalDetection.cve.version, "10.3.6");

console.log("PASS: Drupal confirmed version reaches CVE readiness");

// 42. Joomla confirmed version reaches CVE readiness
const joomlaDetection = detect({
  page: {
    meta: ["generator:joomla"],
    versionHints: [
      {
        name: "Joomla",
        version: "5.2.3",
        source: "meta",
        confidence: 90,
      },
    ],
  },
}).find((item) => item.name === "Joomla");

assert.ok(joomlaDetection, "Joomla detection should exist");
assert.equal(joomlaDetection.id, "joomla");
assert.equal(joomlaDetection.version, "5.2.3");
assert.equal(joomlaDetection.versionInfo.status, "confirmed");
assert.equal(joomlaDetection.cve.eligible, true);
assert.equal(
  joomlaDetection.cve.cpe,
  "cpe:2.3:a:joomla:joomla\\!:*:*:*:*:*:*:*:*",
);
assert.equal(joomlaDetection.cve.version, "5.2.3");

console.log("PASS: Joomla confirmed version reaches CVE readiness");

// 43. Magento confirmed version reaches CVE readiness
const magentoDetection = detect({
  page: {
    scripts: ["/static/frontend/"],
    globals: ["Magento"],
    versionHints: [
      {
        name: "Magento",
        version: "2.4.7",
        source: "meta",
        confidence: 90,
      },
    ],
  },
}).find((item) => item.name === "Magento");

assert.ok(magentoDetection, "Magento detection should exist");
assert.equal(magentoDetection.id, "magento");
assert.equal(magentoDetection.version, "2.4.7");
assert.equal(magentoDetection.versionInfo.status, "confirmed");
assert.equal(magentoDetection.cve.eligible, false);
assert.equal(magentoDetection.cve.cpe, null);
assert.equal(magentoDetection.cve.version, null);

console.log("PASS: Magento confirmed version reaches CVE readiness");

// 38. Apache Tomcat detection without misidentifying connector version
const tomcatDetection = detect({
  headers: [
    {
      name: "server",
      value: "Apache-Coyote/1.1",
    },
  ],
}).find((item) => item.name === "Apache Tomcat");

assert.ok(tomcatDetection, "Apache Tomcat detection should exist");
assert.equal(tomcatDetection.id, "apache-tomcat");
assert.equal(tomcatDetection.versionInfo.status, "unknown");
assert.equal(tomcatDetection.cve.eligible, false);
assert.equal(
  tomcatDetection.cve.cpe,
  "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
);
assert.equal(tomcatDetection.cve.version, null);
assert.equal(tomcatDetection.cve.eligible, false);
assert.equal(
  tomcatDetection.cve.reason,
  "A confirmed technology version is required.",
);

// Verify the CPE remains stored in the trusted detector catalogue.
const tomcatRule = RULES.find((item) => item.id === "apache-tomcat");

assert.ok(tomcatRule, "Apache Tomcat rule should exist");
assert.equal(tomcatRule.product.cpe, "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*");
assert.equal(tomcatRule.product.cpeStatus, "verified");

console.log(
  "PASS: Apache Tomcat detected without inventing a software version",
);

console.log(
  "PASS: Apache Tomcat detected without treating Coyote version as Tomcat version",
);

// Apache Traffic Server metadata validation
const trafficServerRule = RULES.find(
  (item) => item.name === "Apache Traffic Server",
);

assert.ok(trafficServerRule, "Apache Traffic Server rule should exist");
assert.equal(trafficServerRule.id, "apache-traffic-server");
assert.equal(trafficServerRule.product.vendor, "apache");
assert.equal(trafficServerRule.product.name, "traffic_server");
assert.equal(
  trafficServerRule.product.cpe,
  "cpe:2.3:a:apache:traffic_server:*:*:*:*:*:*:*:*",
);
assert.equal(trafficServerRule.product.cpeStatus, "verified");
assert.equal(trafficServerRule.product.purl, null);
assert.equal(trafficServerRule.product.versionScope, "server");

console.log("PASS: Apache Traffic Server metadata");

// Apache Traffic Server detection must not invent a version
const trafficServerDetection = detect({
  page: {},
  headers: [{ name: "Server", value: "ATS" }],
}).find((item) => item.name === "Apache Traffic Server");

assert.ok(
  trafficServerDetection,
  "Apache Traffic Server should be detected from Server header",
);
assert.equal(trafficServerDetection.id, "apache-traffic-server");
assert.equal(trafficServerDetection.version, null);
assert.equal(trafficServerDetection.versionInfo.status, "unknown");
assert.equal(trafficServerDetection.cve.eligible, false);
assert.equal(
  trafficServerDetection.cve.cpe,
  "cpe:2.3:a:apache:traffic_server:*:*:*:*:*:*:*:*",
);
assert.equal(trafficServerDetection.cve.version, null);

console.log(
  "PASS: Apache Traffic Server detection preserves unknown-version safety",
);

// Microsoft IIS metadata validation
const iisRule = RULES.find((item) => item.name === "Microsoft IIS");

assert.ok(iisRule, "Microsoft IIS rule should exist");
assert.equal(iisRule.id, "microsoft-iis");
assert.equal(iisRule.product.vendor, "microsoft");
assert.equal(iisRule.product.name, "internet_information_services");
assert.equal(
  iisRule.product.cpe,
  "cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*",
);
assert.equal(iisRule.product.cpeStatus, "verified");
assert.equal(iisRule.product.purl, null);
assert.deepEqual(iisRule.product.aliases, [
  "IIS",
  "Internet Information Services",
]);
assert.equal(iisRule.product.versionScope, "server");

console.log("PASS: Microsoft IIS metadata");

// Microsoft IIS detection must not invent a version
const iisDetection = detect({
  page: {},
  headers: [{ name: "Server", value: "Microsoft-IIS" }],
}).find((item) => item.name === "Microsoft IIS");

assert.ok(iisDetection, "Microsoft IIS should be detected from Server header");
assert.equal(iisDetection.id, "microsoft-iis");
assert.equal(iisDetection.version, null);
assert.equal(iisDetection.versionInfo.status, "unknown");
assert.equal(iisDetection.cve.eligible, false);
assert.equal(iisDetection.cve.version, null);

console.log("PASS: Microsoft IIS detection preserves unknown-version safety");

// Microsoft IIS version extraction
const iisVersionDetection = detect({
  page: {},
  headers: [{ name: "Server", value: "Microsoft-IIS/10.0" }],
}).find((item) => item.name === "Microsoft IIS");

assert.ok(iisVersionDetection, "Versioned IIS header should be detected");
assert.equal(iisVersionDetection.version, "10.0");

console.log("PASS: Microsoft IIS version extraction");

// Microsoft IIS false-positive protection
assert.ok(
  !names({
    headers: [{ name: "Server", value: "Example-Microsoft-IIS-Helper" }],
  }).includes("Microsoft IIS"),
  "Unrelated server header must not trigger IIS detection",
);

console.log("PASS: Microsoft IIS false-positive protection");

// OpenResty metadata validation
const openRestyRule = RULES.find((item) => item.name === "OpenResty");

assert.ok(openRestyRule, "OpenResty rule should exist");
assert.equal(openRestyRule.id, "openresty");
assert.equal(openRestyRule.product.vendor, "openresty");
assert.equal(openRestyRule.product.name, "openresty");
assert.equal(
  openRestyRule.product.cpe,
  "cpe:2.3:a:openresty:openresty:*:*:*:*:*:*:*:*",
);
assert.equal(openRestyRule.product.cpeStatus, "verified");
assert.equal(openRestyRule.product.purl, "pkg:generic/openresty");
assert.deepEqual(openRestyRule.product.aliases, []);
assert.equal(openRestyRule.product.versionScope, "server");

console.log("PASS: OpenResty metadata");

// OpenResty detection must not invent a version
const openRestyDetection = detect({
  page: {},
  headers: [{ name: "Server", value: "openresty" }],
}).find((item) => item.name === "OpenResty");

assert.ok(
  openRestyDetection,
  "OpenResty should be detected from Server header",
);
assert.equal(openRestyDetection.id, "openresty");
assert.equal(openRestyDetection.version, null);
assert.equal(openRestyDetection.versionInfo.status, "unknown");
assert.equal(openRestyDetection.cve.eligible, false);
assert.equal(openRestyDetection.cve.version, null);

console.log("PASS: OpenResty detection preserves unknown-version safety");

// OpenResty version extraction
const openRestyVersionDetection = detect({
  page: {},
  headers: [{ name: "Server", value: "openresty/1.25.3.1" }],
}).find((item) => item.name === "OpenResty");

assert.ok(
  openRestyVersionDetection,
  "Versioned OpenResty header should be detected",
);
assert.equal(openRestyVersionDetection.version, "1.25.3.1");

console.log("PASS: OpenResty version extraction");

// OpenResty false-positive protection
assert.ok(
  !names({
    headers: [{ name: "Server", value: "Example-OpenResty-Helper" }],
  }).includes("OpenResty"),
  "Unrelated server header must not trigger OpenResty detection",
);

console.log("PASS: OpenResty false-positive protection");

// Envoy metadata validation
const envoyRule = RULES.find((item) => item.name === "Envoy");

assert.ok(envoyRule, "Envoy rule should exist");
assert.equal(envoyRule.id, "envoy");
assert.equal(envoyRule.product.vendor, "envoyproxy");
assert.equal(envoyRule.product.name, "envoy");
assert.equal(
  envoyRule.product.cpe,
  "cpe:2.3:a:envoyproxy:envoy:*:*:*:*:*:*:*:*",
);
assert.equal(envoyRule.product.cpeStatus, "verified");
assert.equal(envoyRule.product.purl, "pkg:generic/envoy");
assert.deepEqual(envoyRule.product.aliases, []);
assert.equal(envoyRule.product.versionScope, "server");

console.log("PASS: Envoy metadata");

// Envoy detection must not invent a version
const envoyDetection = detect({
  page: {},
  headers: [{ name: "Server", value: "envoy" }],
}).find((item) => item.name === "Envoy");

assert.ok(envoyDetection, "Envoy should be detected from Server header");
assert.equal(envoyDetection.id, "envoy");
assert.equal(envoyDetection.version, null);
assert.equal(envoyDetection.versionInfo.status, "unknown");
assert.equal(envoyDetection.cve.eligible, false);
assert.equal(envoyDetection.cve.version, null);

console.log("PASS: Envoy detection preserves unknown-version safety");

// Envoy version extraction
const envoyVersionDetection = detect({
  page: {},
  headers: [{ name: "Server", value: "envoy/1.32.0" }],
}).find((item) => item.name === "Envoy");

assert.ok(envoyVersionDetection, "Versioned Envoy header should be detected");
assert.equal(envoyVersionDetection.version, "1.32.0");

console.log("PASS: Envoy version extraction");

// Envoy false-positive protection
assert.ok(
  !names({
    headers: [{ name: "Server", value: "Example-Envoy-Helper" }],
  }).includes("Envoy"),
  "Unrelated server header must not trigger Envoy detection",
);

console.log("PASS: Envoy false-positive protection");

// Gunicorn metadata validation
const gunicornRule = RULES.find((item) => item.name === "Gunicorn");

assert.ok(gunicornRule, "Gunicorn rule should exist");
assert.equal(gunicornRule.id, "gunicorn");
assert.equal(gunicornRule.product.vendor, "gunicorn");
assert.equal(gunicornRule.product.name, "gunicorn");
assert.equal(
  gunicornRule.product.cpe,
  "cpe:2.3:a:gunicorn:gunicorn:*:*:*:*:*:*:*:*",
);
assert.equal(gunicornRule.product.cpeStatus, "verified");
assert.equal(gunicornRule.product.purl, "pkg:pypi/gunicorn");
assert.deepEqual(gunicornRule.product.aliases, []);
assert.equal(gunicornRule.product.versionScope, "server");

console.log("PASS: Gunicorn metadata");

// Gunicorn detection must not invent a version
const gunicornDetection = detect({
  page: {},
  headers: [{ name: "Server", value: "gunicorn" }],
}).find((item) => item.name === "Gunicorn");

assert.ok(gunicornDetection, "Gunicorn should be detected from Server header");
assert.equal(gunicornDetection.id, "gunicorn");
assert.equal(gunicornDetection.version, null);
assert.equal(gunicornDetection.versionInfo.status, "unknown");
assert.equal(gunicornDetection.cve.eligible, false);
assert.equal(gunicornDetection.cve.version, null);

console.log("PASS: Gunicorn detection preserves unknown-version safety");

// Gunicorn version extraction
const gunicornVersionDetection = detect({
  page: {},
  headers: [{ name: "Server", value: "gunicorn/23.0.0" }],
}).find((item) => item.name === "Gunicorn");

assert.ok(
  gunicornVersionDetection,
  "Versioned Gunicorn header should be detected",
);
assert.equal(gunicornVersionDetection.version, "23.0.0");

console.log("PASS: Gunicorn version extraction");

// Gunicorn false-positive protection
assert.ok(
  !names({
    headers: [{ name: "Server", value: "Example-Gunicorn-Helper" }],
  }).includes("Gunicorn"),
  "Unrelated server header must not trigger Gunicorn detection",
);

console.log("PASS: Gunicorn false-positive protection");

// Uvicorn metadata validation
const uvicornRule = RULES.find((item) => item.name === "Uvicorn");

assert.ok(uvicornRule, "Uvicorn rule should exist");
assert.equal(uvicornRule.id, "uvicorn");
assert.equal(uvicornRule.product.vendor, "encode");
assert.equal(uvicornRule.product.name, "uvicorn");
assert.equal(
  uvicornRule.product.cpe,
  "cpe:2.3:a:encode:uvicorn:*:*:*:*:*:*:*:*",
);
assert.equal(uvicornRule.product.cpeStatus, "unmapped");
assert.equal(uvicornRule.product.purl, "pkg:pypi/uvicorn");
assert.equal(uvicornRule.product.versionScope, "server");

console.log("PASS: Uvicorn metadata");

// Uvicorn detection must not invent a version
const uvicornDetection = detect({
  page: {},
  headers: [{ name: "Server", value: "uvicorn" }],
}).find((item) => item.name === "Uvicorn");

assert.ok(uvicornDetection, "Uvicorn should be detected");
assert.equal(uvicornDetection.id, "uvicorn");
assert.equal(uvicornDetection.version, null);
assert.equal(uvicornDetection.versionInfo.status, "unknown");
assert.equal(uvicornDetection.cve.eligible, false);
assert.equal(uvicornDetection.cve.version, null);

console.log("PASS: Uvicorn detection preserves unknown-version safety");

// Kestrel metadata validation
const kestrelRule = RULES.find((item) => item.name === "Kestrel");

assert.ok(kestrelRule, "Kestrel rule should exist");
assert.equal(kestrelRule.id, "kestrel");
assert.equal(kestrelRule.product.vendor, "microsoft");
assert.equal(kestrelRule.product.name, "kestrel");
assert.equal(kestrelRule.product.cpe, null);
assert.equal(kestrelRule.product.cpeStatus, "unmapped");
assert.equal(
  kestrelRule.product.purl,
  "pkg:nuget/microsoft.aspnetcore.server.kestrel",
);
assert.equal(kestrelRule.product.versionScope, "server");

console.log("PASS: Kestrel metadata");

// Kestrel detection must not invent a version
const kestrelDetection = detect({
  page: {},
  headers: [{ name: "Server", value: "kestrel" }],
}).find((item) => item.name === "Kestrel");

assert.ok(kestrelDetection, "Kestrel should be detected");
assert.equal(kestrelDetection.id, "kestrel");
assert.equal(kestrelDetection.version, null);
assert.equal(kestrelDetection.versionInfo.status, "unknown");
assert.equal(kestrelDetection.cve.eligible, false);
assert.equal(kestrelDetection.cve.version, null);

console.log("PASS: Kestrel detection preserves unknown-version safety");

// LiteSpeed Cache metadata validation
const litespeedRule = RULES.find((item) => item.name === "LiteSpeed Cache");

assert.ok(litespeedRule, "LiteSpeed Cache rule should exist");
assert.equal(litespeedRule.id, "litespeed-cache");
assert.equal(litespeedRule.product.vendor, "litespeed");
assert.equal(litespeedRule.product.name, "litespeed_cache");
assert.equal(litespeedRule.product.cpe, null);
assert.equal(litespeedRule.product.cpeStatus, "unmapped");
assert.equal(litespeedRule.product.purl, "pkg:wordpress/litespeed-cache");
assert.equal(litespeedRule.product.versionScope, "unknown");

console.log("PASS: LiteSpeed Cache metadata");

// LiteSpeed Cache detection must not invent a version
const litespeedDetection = detect({
  page: {},
  headers: [{ name: "x-litespeed-cache", value: "hit" }],
}).find((item) => item.name === "LiteSpeed Cache");

assert.ok(litespeedDetection, "LiteSpeed Cache should be detected");
assert.equal(litespeedDetection.id, "litespeed-cache");
assert.equal(litespeedDetection.version, null);
assert.equal(litespeedDetection.versionInfo.status, "unknown");
assert.equal(litespeedDetection.cve.eligible, false);
assert.equal(litespeedDetection.cve.version, null);

console.log("PASS: LiteSpeed Cache detection preserves unknown-version safety");

// LiteSpeed web server metadata validation
const liteSpeedServerRule = RULES.find((item) => item.name === "LiteSpeed");

assert.ok(liteSpeedServerRule, "LiteSpeed rule should exist");
assert.equal(liteSpeedServerRule.id, "litespeed");
assert.equal(liteSpeedServerRule.product.vendor, "litespeedtech");
assert.equal(liteSpeedServerRule.product.name, "litespeed");
assert.equal(liteSpeedServerRule.product.cpe, null);
assert.equal(liteSpeedServerRule.product.cpeStatus, "unmapped");
assert.equal(liteSpeedServerRule.product.purl, null);
assert.deepEqual(liteSpeedServerRule.product.aliases, [
  "OpenLiteSpeed",
  "LiteSpeed Web Server",
]);
assert.equal(liteSpeedServerRule.product.versionScope, "server");

console.log("PASS: LiteSpeed web server metadata");

// Varnish metadata validation
const varnishRule = RULES.find((item) => item.name === "Varnish");

assert.ok(varnishRule, "Varnish rule should exist");
assert.equal(varnishRule.id, "varnish");
assert.equal(varnishRule.product.vendor, "varnishcache");
assert.equal(varnishRule.product.name, "varnish");
assert.equal(varnishRule.product.cpe, null);
assert.equal(varnishRule.product.cpeStatus, "unmapped");
assert.equal(varnishRule.product.purl, "pkg:generic/varnish-cache");
assert.equal(varnishRule.product.versionScope, "server");

console.log("PASS: Varnish metadata");

// Varnish detection must not invent a version
const varnishDetection = detect({
  page: {},
  headers: [{ name: "via", value: "varnish" }],
}).find((item) => item.name === "Varnish");

assert.ok(varnishDetection, "Varnish should be detected");
assert.equal(varnishDetection.id, "varnish");
assert.equal(varnishDetection.version, null);
assert.equal(varnishDetection.versionInfo.status, "unknown");
assert.equal(varnishDetection.cve.eligible, false);
assert.equal(varnishDetection.cve.version, null);

console.log("PASS: Varnish detection preserves unknown-version safety");

// Express.js metadata validation
const expressRule = RULES.find((item) => item.name === "Express.js");

assert.ok(expressRule, "Express.js rule should exist");
assert.equal(expressRule.id, "express");
assert.equal(expressRule.product.name, "express");
assert.equal(expressRule.product.vendor, "openjsf");
assert.equal(
  expressRule.product.cpe,
  "cpe:2.3:a:openjsf:express:*:*:*:*:*:node.js:*:*",
);
assert.equal(expressRule.product.cpeStatus, "verified");
assert.equal(expressRule.product.purl, "pkg:npm/express");
assert.equal(expressRule.product.versionScope, "server");

console.log("PASS: Express.js metadata");

// Express.js X-Powered-By detection must not invent a version
const expressDetection = detect({
  page: {},
  headers: [{ name: "X-Powered-By", value: "Express" }],
}).find((item) => item.name === "Express.js");

assert.ok(expressDetection, "Express.js should be detected from X-Powered-By");
assert.equal(expressDetection.id, "express");
assert.equal(expressDetection.version, null);
assert.equal(expressDetection.versionInfo.status, "unknown");
assert.equal(expressDetection.cve.eligible, false);
assert.equal(
  expressDetection.cve.cpe,
  "cpe:2.3:a:openjsf:express:*:*:*:*:*:node.js:*:*",
);
assert.equal(expressDetection.cve.version, null);

console.log(
  "PASS: Express.js X-Powered-By detection does not invent a version",
);

// Next.js detection tests
assert.ok(
  names({
    page: {
      domHints: ["#__next"],
    },
  }).includes("Next.js"),
);

assert.ok(
  names({
    page: {
      scripts: ["/_next/static/chunks/main.js"],
    },
  }).includes("Next.js"),
);

assert.ok(
  names({
    page: {
      globals: ["__NEXT_DATA__"],
    },
  }).includes("Next.js"),
);

console.log("PASS: Next.js detection tests");

// Nuxt tests
assert.ok(
  names({
    page: {
      domHints: ["#__nuxt"],
    },
  }).includes("Nuxt"),
);

assert.ok(
  names({
    page: {
      scripts: ["/_nuxt/static/app.js"],
    },
  }).includes("Nuxt"),
);

assert.ok(
  names({
    page: {
      globals: ["__NUXT__"],
    },
  }).includes("Nuxt"),
);

console.log("PASS: Nuxt detection tests");

// NestJS tests
assert.ok(
  names({
    page: {
      resources: ["https://example.com/@nestjs/core"],
    },
  }).includes("NestJS"),
);

console.log("PASS: NestJS detection tests");

// Node.js explicit server-header detection
const nodeDetection = detect({
  page: {},
  headers: [{ name: "X-Powered-By", value: "Node.js" }],
}).find((item) => item.name === "Node.js");

assert.ok(nodeDetection, "Node.js should be detected from an explicit header");
assert.equal(nodeDetection.version, null);
assert.equal(nodeDetection.versionInfo.status, "unknown");

assert.equal(nodeDetection.id, "nodejs");
assert.equal(nodeDetection.cve.eligible, false);
assert.equal(nodeDetection.cve.cpe, "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*");
assert.equal(nodeDetection.cve.version, null);
assert.equal(
  nodeDetection.cve.reason,
  "A confirmed technology version is required.",
);

// Express must not automatically imply Node.js
const expressOnlyNodeCheck = detect({
  page: {},
  headers: [{ name: "X-Powered-By", value: "Express" }],
}).find((item) => item.name === "Node.js");

assert.equal(expressOnlyNodeCheck, undefined);

console.log("PASS: Node.js explicit header detection and Express separation");

// Grafana verified CPE metadata
const grafanaRule = RULES.find((item) => item.name === "Grafana");

assert.ok(grafanaRule, "Grafana rule should exist");
assert.equal(grafanaRule.id, "grafana");
assert.equal(grafanaRule.product.vendor, "grafana");
assert.equal(grafanaRule.product.name, "grafana");
assert.equal(
  grafanaRule.product.cpe,
  "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*",
);
assert.equal(grafanaRule.product.cpeStatus, "verified");
assert.equal(grafanaRule.product.purl, null);
assert.equal(grafanaRule.product.versionScope, "server");

console.log("PASS: Grafana verified CPE metadata");

// Grafana detection must not invent a version or enable CVE lookup
const grafanaDetection = detect({
  page: {
    globals: ["grafanaBootData"],
  },
}).find((item) => item.name === "Grafana");

assert.ok(grafanaDetection, "Grafana should be detected");
assert.equal(grafanaDetection.id, "grafana");
assert.equal(grafanaDetection.version, null);
assert.equal(grafanaDetection.versionInfo.status, "unknown");
assert.equal(grafanaDetection.cve.eligible, false);
assert.equal(
  grafanaDetection.cve.cpe,
  "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*",
);
assert.equal(grafanaDetection.cve.version, null);
assert.equal(
  grafanaDetection.cve.reason,
  "A confirmed technology version is required.",
);

console.log(
  "PASS: Grafana detection does not invent a version or enable CVE lookup",
);

// Redis metadata validation (metadata-only; no browser fingerprint)
const redisRule = RULES.find((item) => item.name === "Redis");

assert.ok(redisRule, "Redis rule should exist");
assert.equal(redisRule.id, "redis");
assert.equal(redisRule.product.vendor, "redis");
assert.equal(redisRule.product.name, "redis");
assert.equal(redisRule.product.cpe, "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*");
assert.equal(redisRule.product.cpeStatus, "verified");
assert.equal(redisRule.product.purl, "pkg:docker/redis");
assert.equal(redisRule.product.versionScope, "server");
assert.deepEqual(redisRule.tests, []);

console.log(
  "PASS: Redis metadata is valid and has no weak detection fingerprints",
);

// Memcached metadata validation (metadata-only; no browser fingerprint)
const memcachedRule = RULES.find((item) => item.name === "Memcached");

assert.ok(memcachedRule, "Memcached rule should exist");
assert.equal(memcachedRule.id, "memcached");
assert.equal(memcachedRule.product.vendor, "memcached");
assert.equal(memcachedRule.product.name, "memcached");
assert.equal(
  memcachedRule.product.cpe,
  "cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*",
);
assert.equal(memcachedRule.product.cpeStatus, "verified");
assert.equal(memcachedRule.product.purl, "pkg:docker/memcached");
assert.equal(memcachedRule.product.versionScope, "server");
assert.deepEqual(memcachedRule.tests, []);

console.log(
  "PASS: Memcached metadata is valid and has no weak detection fingerprints",
);

// Caddy metadata validation
const caddyRule = RULES.find((item) => item.name === "Caddy");

assert.ok(caddyRule, "Caddy rule should exist");
assert.equal(caddyRule.id, "caddy");
assert.equal(caddyRule.product.vendor, "caddyserver");
assert.equal(caddyRule.product.name, "caddy");
assert.equal(
  caddyRule.product.cpe,
  "cpe:2.3:a:caddyserver:caddy:*:*:*:*:*:*:*:*",
);
assert.equal(caddyRule.product.cpeStatus, "verified");
assert.equal(
  caddyRule.product.purl,
  "pkg:golang/github.com/caddyserver/caddy/v2",
);
assert.equal(caddyRule.product.versionScope, "server");
assert.deepEqual(caddyRule.tests, [["header", "server:caddy"]]);

console.log("PASS: Caddy CVE metadata and detection signature are valid");

// React metadata validation
const reactRule = RULES.find((item) => item.name === "React");

assert.ok(reactRule, "React rule should exist");
assert.equal(reactRule.id, "react");
assert.equal(reactRule.product.vendor, "facebook");
assert.equal(reactRule.product.name, "react");
assert.equal(reactRule.product.cpe, "cpe:2.3:a:facebook:react:*:*:*:*:*:*:*:*");
assert.equal(reactRule.product.cpeStatus, "verified");
assert.equal(reactRule.product.purl, "pkg:npm/react");
assert.equal(reactRule.product.versionScope, "client");

console.log("PASS: React CVE metadata is valid");

// Next.js metadata validation
const nextjsRule = RULES.find((item) => item.name === "Next.js");

assert.ok(nextjsRule, "Next.js rule should exist");
assert.equal(nextjsRule.id, "nextjs");
assert.equal(nextjsRule.product.vendor, "vercel");
assert.equal(nextjsRule.product.name, "next.js");
assert.equal(
  nextjsRule.product.cpe,
  "cpe:2.3:a:vercel:next.js:*:*:*:*:*:node.js:*:*",
);
assert.equal(nextjsRule.product.cpeStatus, "verified");
assert.equal(nextjsRule.product.purl, "pkg:npm/next");
assert.equal(nextjsRule.product.versionScope, "server");

console.log("PASS: Next.js CVE metadata is valid");

// Bootstrap metadata validation
const bootstrapRule = RULES.find((item) => item.name === "Bootstrap");

assert.ok(bootstrapRule, "Bootstrap rule should exist");
assert.equal(bootstrapRule.id, "bootstrap");
assert.equal(bootstrapRule.product.vendor, "getbootstrap");
assert.equal(bootstrapRule.product.name, "bootstrap");
assert.equal(
  bootstrapRule.product.cpe,
  "cpe:2.3:a:getbootstrap:bootstrap:*:*:*:*:*:*:*:*",
);
assert.equal(bootstrapRule.product.cpeStatus, "verified");
assert.equal(bootstrapRule.product.purl, "pkg:npm/bootstrap");
assert.equal(bootstrapRule.product.versionScope, "client");

console.log("PASS: Bootstrap CVE metadata is valid");

// Nuxt metadata validation
const nuxtRule = RULES.find((item) => item.name === "Nuxt");

assert.ok(nuxtRule, "Nuxt rule should exist");
assert.equal(nuxtRule.id, "nuxt");
assert.equal(nuxtRule.product.vendor, "nuxt");
assert.equal(nuxtRule.product.name, "nuxt");
assert.equal(nuxtRule.product.cpe, "cpe:2.3:a:nuxt:nuxt:*:*:*:*:*:*:*:*");
assert.equal(nuxtRule.product.cpeStatus, "verified");
assert.equal(nuxtRule.product.purl, "pkg:npm/nuxt");
assert.equal(nuxtRule.product.versionScope, "unknown");

console.log("PASS: Nuxt CVE metadata is valid");

// NestJS metadata validation
const nestjsRule = RULES.find((item) => item.name === "NestJS");

assert.ok(nestjsRule, "NestJS rule should exist");
assert.equal(nestjsRule.id, "nestjs");
assert.equal(nestjsRule.product.vendor, "nestjs");
assert.equal(nestjsRule.product.name, "nestjs");
assert.equal(
  nestjsRule.product.cpe,
  "cpe:2.3:a:nestjs:nest:*:*:*:*:*:node.js:*:*",
);
assert.equal(nestjsRule.product.cpeStatus, "verified");
assert.equal(nestjsRule.product.purl, "pkg:npm/%40nestjs/core");
assert.equal(nestjsRule.product.versionScope, "server");

console.log("PASS: NestJS CVE metadata is valid");

// Vue.js metadata validation
const vueRule = RULES.find((item) => item.name === "Vue.js");

assert.ok(vueRule, "Vue.js rule should exist");
assert.equal(vueRule.id, "vue");
assert.equal(vueRule.product.vendor, "vuejs");
assert.equal(vueRule.product.name, "vue");
assert.equal(vueRule.product.cpe, "cpe:2.3:a:vuejs:vue:*:*:*:*:*:*:*:*");
assert.equal(vueRule.product.cpeStatus, "verified");
assert.equal(vueRule.product.purl, "pkg:npm/vue");
assert.equal(vueRule.product.versionScope, "client");

console.log("PASS: Vue.js CVE metadata is valid");

// Flask metadata validation
const flaskRule = RULES.find((item) => item.name === "Flask");

assert.ok(flaskRule, "Flask rule should exist");
assert.equal(flaskRule.id, "flask");
assert.equal(flaskRule.product.vendor, "palletsprojects");
assert.equal(flaskRule.product.name, "flask");
assert.equal(
  flaskRule.product.cpe,
  "cpe:2.3:a:palletsprojects:flask:*:*:*:*:*:*:*:*",
);
assert.equal(flaskRule.product.cpeStatus, "verified");
assert.equal(flaskRule.product.purl, "pkg:pypi/flask");
assert.equal(flaskRule.product.versionScope, "server");

console.log("PASS: Flask CVE metadata is valid");

// Node.js metadata validation
const nodejsRule = RULES.find((item) => item.name === "Node.js");

assert.ok(nodejsRule, "Node.js rule should exist");
assert.equal(nodejsRule.id, "nodejs");
assert.equal(nodejsRule.product.vendor, "nodejs");
assert.equal(nodejsRule.product.name, "node.js");
assert.equal(
  nodejsRule.product.cpe,
  "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*",
);
assert.equal(nodejsRule.product.cpeStatus, "verified");
assert.equal(nodejsRule.product.purl, null);
assert.equal(nodejsRule.product.versionScope, "server");

console.log("PASS: Node.js CVE metadata is valid");

// PHP metadata validation
const phpRule = RULES.find((item) => item.name === "PHP");

assert.ok(phpRule, "PHP rule should exist");
assert.equal(phpRule.id, "php");
assert.equal(phpRule.product.vendor, "php");
assert.equal(phpRule.product.name, "php");
assert.equal(phpRule.product.cpe, "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*");
assert.equal(phpRule.product.cpeStatus, "verified");
assert.equal(phpRule.product.purl, null);
assert.equal(phpRule.product.versionScope, "server");

console.log("PASS: PHP metadata is valid");

// CakePHP metadata validation
const cakephpRule = RULES.find((item) => item.name === "CakePHP");

assert.ok(cakephpRule, "CakePHP rule should exist");
assert.equal(cakephpRule.id, "cakephp");
assert.equal(cakephpRule.product.vendor, "cakephp");
assert.equal(cakephpRule.product.name, "cakephp");
assert.equal(
  cakephpRule.product.cpe,
  "cpe:2.3:a:cakephp:cakephp:*:*:*:*:*:*:*:*",
);
assert.equal(cakephpRule.product.cpeStatus, "verified");
assert.equal(cakephpRule.product.purl, "pkg:composer/cakephp/cakephp");
assert.equal(cakephpRule.product.versionScope, "server");

console.log("PASS: CakePHP metadata is valid");

// Joomla metadata validation
const joomlaRule = RULES.find((item) => item.name === "Joomla");

assert.ok(joomlaRule, "Joomla rule should exist");
assert.equal(joomlaRule.id, "joomla");
assert.equal(joomlaRule.product.vendor, "joomla");
assert.equal(joomlaRule.product.name, "joomla!");
assert.equal(
  joomlaRule.product.cpe,
  "cpe:2.3:a:joomla:joomla\\!:*:*:*:*:*:*:*:*",
);
assert.equal(joomlaRule.product.cpeStatus, "verified");
assert.equal(joomlaRule.product.purl, null);
assert.equal(joomlaRule.product.versionScope, "server");

console.log("PASS: Joomla metadata is valid");

// Drupal metadata validation
const drupalRule = RULES.find((item) => item.name === "Drupal");

assert.ok(drupalRule, "Drupal rule should exist");
assert.equal(drupalRule.id, "drupal");
assert.equal(drupalRule.product.vendor, "drupal");
assert.equal(drupalRule.product.name, "drupal");
assert.equal(drupalRule.product.cpe, "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*");
assert.equal(drupalRule.product.cpeStatus, "verified");
assert.equal(drupalRule.product.purl, null);
assert.equal(drupalRule.product.versionScope, "server");

console.log("PASS: Drupal metadata is valid");

// Magento metadata validation
const magentoRule = RULES.find((item) => item.name === "Magento");

assert.ok(magentoRule, "Magento rule should exist");
assert.equal(magentoRule.id, "magento");
assert.equal(magentoRule.product.vendor, "adobe");
assert.equal(magentoRule.product.name, "magento");
assert.equal(magentoRule.product.cpe, null);
assert.equal(magentoRule.product.cpeStatus, "unmapped");
assert.equal(magentoRule.product.purl, null);
assert.equal(magentoRule.product.versionScope, "server");

console.log("PASS: Magento metadata is valid");

// Cloudflare metadata validation
const cloudflareRule = RULES.find((item) => item.name === "Cloudflare");

assert.ok(cloudflareRule, "Cloudflare rule should exist");
assert.equal(cloudflareRule.id, "cloudflare");
assert.equal(cloudflareRule.product.vendor, "cloudflare");
assert.equal(cloudflareRule.product.name, "cloudflare");
assert.equal(cloudflareRule.product.cpe, null);
assert.equal(cloudflareRule.product.cpeStatus, "unmapped");
assert.equal(cloudflareRule.product.purl, null);
assert.deepEqual(cloudflareRule.product.aliases, []);
assert.equal(cloudflareRule.product.versionScope, "unknown");

console.log("PASS: Cloudflare metadata is valid");

// Cloudflare detection must not invent a version
const cloudflareDetection = detect({
  page: {
    cookies: ["__cf_bm"],
  },
  headers: [
    { name: "server", value: "cloudflare" },
    { name: "cf-ray", value: "example-ray-id" },
  ],
}).find((item) => item.name === "Cloudflare");

assert.ok(cloudflareDetection, "Cloudflare should be detected");
assert.equal(cloudflareDetection.id, "cloudflare");
assert.equal(cloudflareDetection.version, null);
assert.equal(cloudflareDetection.versionInfo.status, "unknown");
assert.equal(cloudflareDetection.cve.eligible, false);

console.log("PASS: Cloudflare detection preserves unknown-version safety");

// Apache ECharts metadata validation
const echartsRule = RULES.find((item) => item.name === "Apache ECharts");

assert.ok(echartsRule, "Apache ECharts rule should exist");
assert.equal(echartsRule.id, "apache-echarts");
assert.equal(echartsRule.product.vendor, "apache");
assert.equal(echartsRule.product.name, "echarts");
assert.equal(echartsRule.product.cpe, null);
assert.equal(echartsRule.product.cpeStatus, "unmapped");
assert.equal(echartsRule.product.purl, "pkg:npm/echarts");
assert.deepEqual(echartsRule.product.aliases, []);
assert.equal(echartsRule.product.versionScope, "client");

console.log("PASS: Apache ECharts metadata");

// Tailwind CSS metadata validation
const tailwindRule = RULES.find((item) => item.name === "Tailwind CSS");

assert.ok(tailwindRule, "Tailwind CSS rule should exist");
assert.equal(tailwindRule.id, "tailwindcss");
assert.equal(tailwindRule.product.vendor, "tailwindlabs");
assert.equal(tailwindRule.product.name, "tailwindcss");
assert.equal(tailwindRule.product.cpe, null);
assert.equal(tailwindRule.product.cpeStatus, "unmapped");
assert.equal(tailwindRule.product.purl, "pkg:npm/tailwindcss");
assert.equal(tailwindRule.product.versionScope, "unknown");

console.log("PASS: Tailwind CSS metadata is valid");

// Umami Analytics detection and metadata
const umamiDetection = detect({
  page: {
    scripts: ["https://cloud.umami.is/script.js"],
  },
}).find((item) => item.name === "Umami");

assert.ok(umamiDetection, "Umami should be detected");
assert.equal(umamiDetection.id, "umami");
assert.equal(umamiDetection.product.vendor, "Umami");
assert.equal(umamiDetection.product.name, "Umami");
assert.equal(umamiDetection.product.cpe, null);
assert.equal(umamiDetection.product.cpeStatus, "unmapped");
assert.equal(umamiDetection.product.purl, null);
assert.equal(umamiDetection.product.versionScope, "unknown");

console.log("PASS: Umami Analytics detection and metadata");

// Pirsch Analytics detection and metadata
const pirschDetection = detect({
  page: {
    scripts: ["https://api.pirsch.io/pa.js"],
  },
}).find((item) => item.name === "Pirsch Analytics");

assert.ok(pirschDetection, "Pirsch Analytics should be detected");
assert.equal(pirschDetection.id, "pirsch-analytics");
assert.equal(pirschDetection.product.vendor, "Pirsch");
assert.equal(pirschDetection.product.name, "Pirsch Analytics");
assert.equal(pirschDetection.product.cpe, null);
assert.equal(pirschDetection.product.cpeStatus, "unmapped");
assert.equal(pirschDetection.product.purl, null);
assert.equal(pirschDetection.product.versionScope, "unknown");
assert.equal(pirschDetection.version, null);
assert.equal(pirschDetection.versionInfo.status, "unknown");
assert.equal(pirschDetection.cve.eligible, false);

console.log("PASS: Pirsch Analytics detection and metadata");

// Yandex Metrica detection and metadata
const yandexMetricaDetection = detect({
  page: {
    scripts: ["https://mc.yandex.ru/metrika/tag.js"],
  },
}).find((item) => item.name === "Yandex Metrica");

assert.ok(yandexMetricaDetection, "Yandex Metrica should be detected");
assert.equal(yandexMetricaDetection.id, "yandex-metrica");
assert.equal(yandexMetricaDetection.product.vendor, "Yandex");
assert.equal(yandexMetricaDetection.product.cpe, null);
assert.equal(yandexMetricaDetection.product.cpeStatus, "unmapped");
assert.equal(yandexMetricaDetection.product.purl, null);
assert.equal(yandexMetricaDetection.product.versionScope, "unknown");
assert.equal(yandexMetricaDetection.version, null);
assert.equal(yandexMetricaDetection.versionInfo.status, "unknown");
assert.equal(yandexMetricaDetection.cve.eligible, false);

// The watch endpoint is not the JavaScript library
assert.ok(
  !names({
    page: {
      scripts: ["https://mc.yandex.ru/watch/123456"],
    },
  }).includes("Yandex Metrica"),
  "Yandex Metrica should not be detected from the watch image endpoint alone",
);

console.log("PASS: Yandex Metrica detection and metadata");

// Adobe Analytics detection and metadata
const adobeAnalyticsDetection = detect({
  page: {
    scripts: ["https://example.com/scripts/AppMeasurement.js"],
  },
}).find((item) => item.name === "Adobe Analytics");

assert.ok(adobeAnalyticsDetection, "Adobe Analytics should be detected");
assert.equal(adobeAnalyticsDetection.id, "adobe-analytics");
assert.equal(adobeAnalyticsDetection.product.vendor, "Adobe");
assert.equal(adobeAnalyticsDetection.product.name, "Adobe Analytics");
assert.equal(adobeAnalyticsDetection.product.cpe, null);
assert.equal(adobeAnalyticsDetection.product.cpeStatus, "unmapped");
assert.equal(adobeAnalyticsDetection.product.purl, null);
assert.equal(adobeAnalyticsDetection.product.versionScope, "unknown");
assert.equal(adobeAnalyticsDetection.version, null);
assert.equal(adobeAnalyticsDetection.versionInfo.status, "unknown");
assert.equal(adobeAnalyticsDetection.cve.eligible, false);

// Adobe tag manager alone should not identify Adobe Analytics
assert.ok(
  !names({
    page: {
      scripts: ["https://assets.adobedtm.com/launch-EN123.min.js"],
    },
  }).includes("Adobe Analytics"),
  "Adobe tag manager alone should not trigger Adobe Analytics detection",
);

// Alloy Web SDK alone should not identify Adobe Analytics
assert.ok(
  !names({
    page: {
      scripts: ["https://cdn1.adoberesources.net/alloy/2.19.1/alloy.js"],
    },
  }).includes("Adobe Analytics"),
  "Alloy alone should not trigger Adobe Analytics detection",
);

console.log("PASS: Adobe Analytics detection and metadata");

// Amplitude detection and metadata
const amplitudeLegacyDetection = detect({
  page: {
    scripts: ["https://cdn.amplitude.com/libs/amplitude-8.21.4-min.gz.js"],
  },
}).find((item) => item.name === "Amplitude");

const amplitudeUnifiedDetection = detect({
  page: {
    scripts: ["https://cdn.amplitude.com/script/EXAMPLE_API_KEY.js"],
  },
}).find((item) => item.name === "Amplitude");

assert.ok(amplitudeLegacyDetection, "Amplitude legacy SDK should be detected");
assert.ok(
  amplitudeUnifiedDetection,
  "Amplitude Unified Script should be detected",
);

for (const amplitudeDetection of [
  amplitudeLegacyDetection,
  amplitudeUnifiedDetection,
]) {
  assert.equal(amplitudeDetection.id, "amplitude");
  assert.equal(amplitudeDetection.product.vendor, "Amplitude");
  assert.equal(amplitudeDetection.product.name, "Amplitude Analytics");
  assert.equal(amplitudeDetection.product.cpe, null);
  assert.equal(amplitudeDetection.product.cpeStatus, "unmapped");
  assert.equal(amplitudeDetection.product.purl, null);
  assert.equal(amplitudeDetection.product.versionScope, "unknown");
  assert.equal(amplitudeDetection.version, null);
  assert.equal(amplitudeDetection.versionInfo.status, "unknown");
  assert.equal(amplitudeDetection.cve.eligible, false);
}

// A generic Amplitude domain reference should not trigger detection
assert.ok(
  !names({
    page: {
      scripts: ["https://example.com/amplitude.com/libs/other.js"],
    },
  }).includes("Amplitude"),
  "Generic Amplitude text should not trigger detection",
);

console.log("PASS: Amplitude detection and metadata");

// Google Analytics detection and metadata
const googleAnalyticsUrls = [
  "https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX",
  "https://www.google-analytics.com/analytics.js",
  "https://www.google-analytics.com/ga.js",
];

for (const url of googleAnalyticsUrls) {
  const googleAnalyticsDetection = detect({
    page: {
      scripts: [url],
    },
  }).find((item) => item.name === "Google Analytics");

  assert.ok(
    googleAnalyticsDetection,
    `Google Analytics should be detected from ${url}`,
  );

  assert.equal(googleAnalyticsDetection.id, "google-analytics");
  assert.equal(googleAnalyticsDetection.product.vendor, "Google");
  assert.equal(googleAnalyticsDetection.product.name, "Google Analytics");
  assert.equal(googleAnalyticsDetection.product.cpe, null);
  assert.equal(googleAnalyticsDetection.product.cpeStatus, "unmapped");
  assert.equal(googleAnalyticsDetection.product.purl, null);
  assert.equal(googleAnalyticsDetection.product.versionScope, "unknown");
  assert.equal(googleAnalyticsDetection.version, null);
  assert.equal(googleAnalyticsDetection.versionInfo.status, "unknown");
  assert.equal(googleAnalyticsDetection.cve.eligible, false);
}

// gtag global alone must not trigger Google Analytics
assert.ok(
  !names({
    page: {
      globals: ["gtag"],
    },
  }).includes("Google Analytics"),
  "gtag alone should not trigger Google Analytics detection",
);

console.log("PASS: Google Analytics detection and metadata");

// PostHog detection and metadata
const posthogCases = [
  {
    page: {
      globals: ["posthog"],
    },
  },
  {
    page: {
      scripts: ["https://us-assets.i.posthog.com/static/array.js"],
    },
  },
  {
    page: {
      resources: ["https://us.i.posthog.com/e/"],
    },
  },
  {
    page: {
      resources: ["https://eu.i.posthog.com/e/"],
    },
  },
];

for (const input of posthogCases) {
  const posthogDetection = detect(input).find(
    (item) => item.name === "PostHog",
  );

  assert.ok(posthogDetection, "PostHog should be detected");

  assert.equal(posthogDetection.id, "posthog");
  assert.equal(posthogDetection.product.vendor, "PostHog");
  assert.equal(posthogDetection.product.name, "PostHog");
  assert.equal(posthogDetection.product.cpe, null);
  assert.equal(posthogDetection.product.cpeStatus, "unmapped");
  assert.equal(posthogDetection.product.purl, "pkg:npm/posthog-js");
  assert.equal(posthogDetection.product.versionScope, "client");
  assert.equal(posthogDetection.version, null);
  assert.equal(posthogDetection.versionInfo.status, "unknown");
  assert.equal(posthogDetection.cve.eligible, false);
}

// Generic script text should not trigger PostHog
assert.ok(
  !names({
    page: {
      scripts: ["https://example.com/scripts/posthog-helper.js"],
    },
  }).includes("PostHog"),
  "Generic PostHog script text should not trigger detection",
);

console.log("PASS: PostHog detection and metadata");

// Google Tag Manager detection and metadata
const gtmDetection = detect({
  page: {
    scripts: ["https://www.googletagmanager.com/gtm.js?id=GTM-ABC123"],
  },
}).find((item) => item.name === "Google Tag Manager");

assert.ok(gtmDetection, "Google Tag Manager should be detected");
assert.equal(gtmDetection.id, "google-tag-manager");
assert.equal(gtmDetection.product.vendor, "Google");
assert.equal(gtmDetection.product.name, "Google Tag Manager");
assert.equal(gtmDetection.product.cpe, null);
assert.equal(gtmDetection.product.cpeStatus, "unmapped");
assert.equal(gtmDetection.product.purl, null);
assert.equal(gtmDetection.product.versionScope, "unknown");
assert.equal(gtmDetection.version, null);
assert.equal(gtmDetection.versionInfo.status, "unknown");
assert.equal(gtmDetection.cve.eligible, false);

// The Google tag gtag.js alone must not trigger GTM
assert.ok(
  !names({
    page: {
      scripts: ["https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX"],
    },
  }).includes("Google Tag Manager"),
  "gtag.js alone should not trigger Google Tag Manager detection",
);

console.log("PASS: Google Tag Manager detection and metadata");

// Netlify detection and metadata
const netlifyDetection = detect({
  page: {},
  headers: [{ name: "x-nf-request-id", value: "example-request-id" }],
}).find((item) => item.name === "Netlify");

assert.ok(netlifyDetection, "Netlify should be detected");
assert.equal(netlifyDetection.id, "netlify");
assert.equal(netlifyDetection.product.vendor, "Netlify");
assert.equal(netlifyDetection.product.name, "Netlify");
assert.equal(netlifyDetection.product.cpe, null);
assert.equal(netlifyDetection.product.cpeStatus, "unmapped");
assert.equal(netlifyDetection.product.purl, null);
assert.equal(netlifyDetection.version, null);
assert.equal(netlifyDetection.versionInfo.status, "unknown");
assert.equal(netlifyDetection.cve.eligible, false);

assert.ok(
  !names({
    page: {},
    headers: [{ name: "x-request-id", value: "12345" }],
  }).includes("Netlify"),
  "Generic request ID must not identify Netlify",
);

console.log("PASS: Netlify detection and metadata");

// Render detection and metadata
const renderDetection = detect({
  page: {},
  headers: [{ name: "x-render-origin-server", value: "Render" }],
}).find((item) => item.name === "Render");

assert.ok(renderDetection, "Render should be detected");
assert.equal(renderDetection.id, "render");
assert.equal(renderDetection.product.vendor, "Render");
assert.equal(renderDetection.product.name, "Render");
assert.equal(renderDetection.product.cpe, null);
assert.equal(renderDetection.product.cpeStatus, "unmapped");
assert.equal(renderDetection.product.purl, null);
assert.equal(renderDetection.version, null);
assert.equal(renderDetection.versionInfo.status, "unknown");
assert.equal(renderDetection.cve.eligible, false);

assert.ok(
  !names({
    page: {},
    headers: [{ name: "server", value: "Render" }],
  }).includes("Render"),
  "Server header alone must not identify Render",
);

console.log("PASS: Render detection and metadata");

// Vercel detection and metadata
const vercelDetection = detect({
  page: {},
  headers: [{ name: "x-vercel-id", value: "iad1::example-id" }],
}).find((item) => item.name === "Vercel");

assert.ok(vercelDetection, "Vercel should be detected");
assert.equal(vercelDetection.id, "vercel");
assert.equal(vercelDetection.product.vendor, "Vercel");
assert.equal(vercelDetection.product.name, "Vercel");
assert.equal(vercelDetection.product.cpe, null);
assert.equal(vercelDetection.product.cpeStatus, "unmapped");
assert.equal(vercelDetection.product.purl, null);
assert.equal(vercelDetection.version, null);
assert.equal(vercelDetection.versionInfo.status, "unknown");
assert.equal(vercelDetection.cve.eligible, false);

assert.ok(
  !names({
    page: {},
    headers: [{ name: "x-request-id", value: "12345" }],
  }).includes("Vercel"),
  "Generic request ID must not identify Vercel",
);

console.log("PASS: Vercel detection and metadata");

// Alpine.js detection and metadata
const alpineScriptDetection = detect({
  page: {
    scripts: ["https://cdn.jsdelivr.net/npm/alpinejs@3.14.1/dist/cdn.min.js"],
  },
}).find((item) => item.name === "Alpine.js");

const alpineGlobalDetection = detect({
  page: {
    globals: ["Alpine"],
  },
}).find((item) => item.name === "Alpine.js");

assert.ok(alpineScriptDetection, "Alpine.js CDN script should be detected");
assert.ok(alpineGlobalDetection, "Alpine.js global should be detected");

for (const alpineDetection of [alpineScriptDetection, alpineGlobalDetection]) {
  assert.equal(alpineDetection.id, "alpine-js");
  assert.equal(alpineDetection.product.vendor, "Alpine.js");
  assert.equal(alpineDetection.product.name, "Alpine.js");
  assert.equal(alpineDetection.product.cpe, null);
  assert.equal(alpineDetection.product.cpeStatus, "unmapped");
  assert.equal(alpineDetection.product.purl, "pkg:npm/alpinejs");
  assert.equal(alpineDetection.product.versionScope, "client");
  assert.equal(alpineDetection.version, null);
  assert.equal(alpineDetection.versionInfo.status, "unknown");
  assert.equal(alpineDetection.cve.eligible, false);
}

assert.ok(
  !names({
    page: {
      scripts: ["https://example.com/alpine-helper.js"],
    },
  }).includes("Alpine.js"),
  "Unrelated Alpine helper script must not trigger detection",
);

console.log("PASS: Alpine.js detection and metadata");

// Axios detection and metadata
const axiosMinDetection = detect({
  page: {
    scripts: ["https://unpkg.com/axios/dist/axios.min.js"],
  },
}).find((item) => item.name === "Axios");

const axiosDetection = detect({
  page: {
    scripts: ["https://unpkg.com/axios/dist/axios.js"],
  },
}).find((item) => item.name === "Axios");

assert.ok(axiosMinDetection, "Axios minified script should be detected");
assert.ok(axiosDetection, "Axios script should be detected");

for (const axiosResult of [axiosMinDetection, axiosDetection]) {
  assert.equal(axiosResult.id, "axios");
  assert.equal(axiosResult.product.vendor, "Axios");
  assert.equal(axiosResult.product.name, "Axios");
  assert.equal(axiosResult.product.cpe, null);
  assert.equal(axiosResult.product.cpeStatus, "unmapped");
  assert.equal(axiosResult.product.purl, "pkg:npm/axios");
  assert.equal(axiosResult.product.versionScope, "client");
  assert.equal(axiosResult.version, null);
  assert.equal(axiosResult.versionInfo.status, "unknown");
  assert.equal(axiosResult.cve.eligible, false);
}

assert.ok(
  !names({
    page: {
      scripts: ["https://example.com/axios-helper.js"],
    },
  }).includes("Axios"),
  "Unrelated Axios helper script must not trigger detection",
);

console.log("PASS: Axios detection and metadata");

// D3.js detection and metadata
const d3MinDetection = detect({
  page: {
    scripts: ["https://example.com/d3.min.js"],
  },
}).find((item) => item.name === "D3.js");

const d3VersionedDetection = detect({
  page: {
    scripts: ["https://d3js.org/d3.v7.min.js"],
  },
}).find((item) => item.name === "D3.js");

assert.ok(d3MinDetection, "D3.js minified script should be detected");
assert.ok(d3VersionedDetection, "D3.js versioned script should be detected");

for (const d3Detection of [d3MinDetection, d3VersionedDetection]) {
  assert.equal(d3Detection.id, "d3");
  assert.equal(d3Detection.product.vendor, "D3");
  assert.equal(d3Detection.product.name, "D3");
  assert.equal(d3Detection.product.cpe, null);
  assert.equal(d3Detection.product.cpeStatus, "unmapped");
  assert.equal(d3Detection.product.purl, "pkg:npm/d3");
  assert.equal(d3Detection.product.versionScope, "client");
  assert.equal(d3Detection.version, null);
  assert.equal(d3Detection.versionInfo.status, "unknown");
  assert.equal(d3Detection.cve.eligible, false);
}

assert.ok(
  !names({
    page: {
      scripts: ["https://example.com/d3-helper.js"],
    },
  }).includes("D3.js"),
  "Unrelated D3 helper script must not trigger detection",
);

console.log("PASS: D3.js detection and metadata");

// GSAP detection and metadata
const gsapScriptDetection = detect({
  page: {
    scripts: ["https://cdn.jsdelivr.net/npm/gsap@3.15/dist/gsap.min.js"],
  },
}).find((item) => item.name === "GSAP");

const gsapGlobalDetection = detect({
  page: {
    globals: ["gsap"],
  },
}).find((item) => item.name === "GSAP");

assert.ok(gsapScriptDetection, "GSAP script should be detected");
assert.ok(gsapGlobalDetection, "GSAP global should be detected");

for (const gsapDetection of [gsapScriptDetection, gsapGlobalDetection]) {
  assert.equal(gsapDetection.id, "gsap");
  assert.equal(gsapDetection.product.vendor, "GreenSock");
  assert.equal(gsapDetection.product.name, "GSAP");
  assert.equal(gsapDetection.product.cpe, null);
  assert.equal(gsapDetection.product.cpeStatus, "unmapped");
  assert.equal(gsapDetection.product.purl, "pkg:npm/gsap");
  assert.equal(gsapDetection.product.versionScope, "client");
  assert.equal(gsapDetection.version, null);
  assert.equal(gsapDetection.versionInfo.status, "unknown");
  assert.equal(gsapDetection.cve.eligible, false);
}

assert.ok(
  !names({
    page: {
      scripts: ["https://example.com/greensock-helper.js"],
    },
  }).includes("GSAP"),
  "Unrelated GreenSock helper must not trigger detection",
);

console.log("PASS: GSAP detection and metadata");

// HTMX detection and metadata
const htmxMinDetection = detect({
  page: {
    scripts: ["https://cdn.jsdelivr.net/npm/htmx.org@2.0.11/dist/htmx.min.js"],
  },
}).find((item) => item.name === "HTMX");

const htmxScriptDetection = detect({
  page: {
    scripts: ["https://cdn.jsdelivr.net/npm/htmx.org@2.0.11/dist/htmx.js"],
  },
}).find((item) => item.name === "HTMX");

const htmxGlobalDetection = detect({
  page: {
    globals: ["htmx"],
  },
}).find((item) => item.name === "HTMX");

assert.ok(htmxMinDetection, "HTMX minified script should be detected");
assert.ok(htmxScriptDetection, "HTMX unminified script should be detected");
assert.ok(htmxGlobalDetection, "HTMX global should be detected");

for (const htmxDetection of [
  htmxMinDetection,
  htmxScriptDetection,
  htmxGlobalDetection,
]) {
  assert.equal(htmxDetection.id, "htmx");
  assert.equal(htmxDetection.product.vendor, "Big Sky Software");
  assert.equal(htmxDetection.product.name, "htmx");
  assert.equal(htmxDetection.product.cpe, null);
  assert.equal(htmxDetection.product.cpeStatus, "unmapped");
  assert.equal(htmxDetection.product.purl, "pkg:npm/htmx.org");
  assert.equal(htmxDetection.product.versionScope, "client");
  assert.equal(htmxDetection.version, null);
  assert.equal(htmxDetection.versionInfo.status, "unknown");
  assert.equal(htmxDetection.cve.eligible, false);
}

assert.ok(
  !names({
    page: {
      scripts: ["https://example.com/htmx-helper.js"],
    },
  }).includes("HTMX"),
  "Unrelated HTMX helper script must not trigger detection",
);

console.log("PASS: HTMX detection and metadata");

// jQuery detection and metadata
const jqueryGlobalDetection = detect({
  page: {
    globals: ["jQuery"],
  },
}).find((item) => item.name === "jQuery");

const jqueryResourceDetection = detect({
  page: {
    resources: ["https://code.jquery.com/jquery-4.0.0.min.js"],
  },
}).find((item) => item.name === "jQuery");

assert.ok(jqueryGlobalDetection, "jQuery global should be detected");
assert.ok(jqueryResourceDetection, "jQuery resource should be detected");

for (const jqueryDetection of [
  jqueryGlobalDetection,
  jqueryResourceDetection,
]) {
  assert.equal(jqueryDetection.id, "jquery");
  assert.equal(jqueryDetection.product.vendor, "OpenJS Foundation");
  assert.equal(jqueryDetection.product.name, "jQuery");
  assert.equal(
    jqueryDetection.product.cpe,
    "cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*",
  );
  assert.equal(jqueryDetection.product.cpeStatus, "verified");
  assert.equal(jqueryDetection.product.purl, "pkg:npm/jquery");
  assert.equal(jqueryDetection.product.versionScope, "client");
}

assert.ok(
  !names({
    page: {
      resources: ["https://example.com/jquery-helper.js"],
    },
  }).includes("jQuery"),
  "Unrelated jQuery helper resource must not trigger detection",
);

console.log("PASS: jQuery detection and metadata");

// Lodash detection and metadata
const lodashMinDetection = detect({
  page: {
    scripts: ["https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"],
  },
}).find((item) => item.name === "Lodash");

const lodashScriptDetection = detect({
  page: {
    scripts: ["https://example.com/vendor/lodash.js"],
  },
}).find((item) => item.name === "Lodash");

assert.ok(lodashMinDetection, "Lodash minified script should be detected");
assert.ok(lodashScriptDetection, "Lodash script should be detected");

for (const lodashDetection of [lodashMinDetection, lodashScriptDetection]) {
  assert.equal(lodashDetection.id, "lodash");
  assert.equal(lodashDetection.product.vendor, "OpenJS Foundation");
  assert.equal(lodashDetection.product.name, "Lodash");
  assert.equal(
    lodashDetection.product.cpe,
    "cpe:2.3:a:lodash:lodash:*:*:*:*:*:*:*:*",
  );
  assert.equal(lodashDetection.product.cpeStatus, "verified");
  assert.equal(lodashDetection.product.purl, "pkg:npm/lodash");
  assert.equal(lodashDetection.product.versionScope, "client");
}

assert.ok(
  !names({
    page: {
      scripts: ["https://example.com/lodash-helper.js"],
    },
  }).includes("Lodash"),
  "Unrelated Lodash helper script must not trigger detection",
);

console.log("PASS: Lodash detection and metadata");

// Three.js detection and metadata
const threeModuleDetection = detect({
  page: {
    scripts: [
      "https://cdn.jsdelivr.net/npm/three@0.187.0/build/three.module.js",
    ],
  },
}).find((item) => item.name === "Three.js");

const threeMinDetection = detect({
  page: {
    scripts: ["https://example.com/build/three.min.js"],
  },
}).find((item) => item.name === "Three.js");

assert.ok(threeModuleDetection, "Three.js module should be detected");
assert.ok(threeMinDetection, "Three.js minified script should be detected");

for (const threeDetection of [threeModuleDetection, threeMinDetection]) {
  assert.equal(threeDetection.id, "three-js");
  assert.equal(threeDetection.product.vendor, "Three.js");
  assert.equal(threeDetection.product.name, "Three.js");
  assert.equal(threeDetection.product.cpe, null);
  assert.equal(threeDetection.product.cpeStatus, "unmapped");
  assert.equal(threeDetection.product.purl, "pkg:npm/three");
  assert.equal(threeDetection.product.versionScope, "client");
}

assert.ok(
  !names({
    page: {
      scripts: ["https://example.com/three-helper.js"],
    },
  }).includes("Three.js"),
  "Unrelated Three.js helper script must not trigger detection",
);

console.log("PASS: Three.js detection and metadata");

// Sentry detection and metadata
const sentryCdnDetection = detect({
  page: {
    scripts: ["https://browser.sentry-cdn.com/11.0.0/bundle.min.js"],
  },
}).find((item) => item.name === "Sentry");

const sentryGlobalDetection = detect({
  page: {
    globals: ["Sentry"],
  },
}).find((item) => item.name === "Sentry");

const sentryInternalDetection = detect({
  page: {
    globals: ["__SENTRY__"],
  },
}).find((item) => item.name === "Sentry");

assert.ok(sentryCdnDetection, "Sentry CDN script should be detected");
assert.ok(sentryGlobalDetection, "Sentry global should be detected");
assert.ok(sentryInternalDetection, "Sentry internal global should be detected");

for (const sentryDetection of [
  sentryCdnDetection,
  sentryGlobalDetection,
  sentryInternalDetection,
]) {
  assert.equal(sentryDetection.id, "sentry");
  assert.equal(sentryDetection.product.vendor, "Sentry");
  assert.equal(sentryDetection.product.name, "Sentry JavaScript SDK");
  assert.equal(sentryDetection.product.cpe, null);
  assert.equal(sentryDetection.product.cpeStatus, "unmapped");
  assert.equal(sentryDetection.product.purl, "pkg:npm/%40sentry/browser");
  assert.equal(sentryDetection.product.versionScope, "client");
}

assert.ok(
  !names({
    page: {
      scripts: ["https://example.com/sentry-helper.js"],
    },
  }).includes("Sentry"),
  "Unrelated Sentry helper script must not trigger detection",
);

console.log("PASS: Sentry detection and metadata");

console.log("PASS: All detector baseline and false-positive tests passed");
