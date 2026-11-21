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
assert.equal(symfonyRule.product.vendor, "symfony");
assert.equal(symfonyRule.product.name, "symfony");
assert.equal(symfonyRule.product.cpe, null);
assert.equal(symfonyRule.product.cpeStatus, "unmapped");
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
assert.equal(symfonyTokenDetection.cve.cpe, null);
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
assert.equal(symfonyLinkDetection.cve.cpe, null);
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
assert.equal(magentoDetection.cve.eligible, true);
assert.equal(
  magentoDetection.cve.cpe,
  "cpe:2.3:a:adobe:magento:*:*:*:*:open_source:*:*:*",
);
assert.equal(magentoDetection.cve.version, "2.4.7");

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

// Express.js metadata validation
const expressRule = RULES.find((item) => item.name === "Express.js");

assert.ok(expressRule, "Express.js rule should exist");
assert.equal(expressRule.id, "express");
assert.equal(expressRule.product.vendor, "expressjs");
assert.equal(expressRule.product.name, "express");
assert.equal(expressRule.product.cpe, null);
assert.equal(expressRule.product.cpeStatus, "unmapped");
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
assert.equal(expressDetection.cve.cpe, null);
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
assert.equal(grafanaRule.product.purl, "pkg:docker/grafana/grafana");
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
  "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*",
);
assert.equal(nextjsRule.product.cpeStatus, "verified");
assert.equal(nextjsRule.product.purl, "pkg:npm/next");
assert.equal(nextjsRule.product.versionScope, "server");

console.log("PASS: Next.js CVE metadata is valid");

// Bootstrap metadata validation
const bootstrapRule = RULES.find((item) => item.name === "Bootstrap");

assert.ok(bootstrapRule, "Bootstrap rule should exist");
assert.equal(bootstrapRule.id, "bootstrap");
assert.equal(bootstrapRule.product.vendor, "twbs");
assert.equal(bootstrapRule.product.name, "bootstrap");
assert.equal(
  bootstrapRule.product.cpe,
  "cpe:2.3:a:twbs:bootstrap:*:*:*:*:*:*:*:*",
);
assert.equal(bootstrapRule.product.cpeStatus, "verified");
assert.equal(bootstrapRule.product.purl, "pkg:npm/bootstrap");
assert.equal(bootstrapRule.product.versionScope, "client");

console.log("PASS: Bootstrap CVE metadata is valid");

console.log("PASS: All detector baseline and false-positive tests passed");
