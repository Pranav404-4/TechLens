"use strict";

const fs = require("fs");
const vm = require("vm");
const assert = require("assert");

// Load the existing analyzer without modifying it.
const source = fs.readFileSync("./riskAnalyzer.js", "utf8");
const context = vm.createContext({
  URL: URL,
});

vm.runInContext(source, context);

const analyze = vm.runInContext("TechLensRiskAnalyzer.analyze", context);

function runTest(name, headers, captured, url, expectedTitle) {
  const findings = analyze(headers, captured, url);
  const passed = expectedTitle
    ? findings.some((f) => f.title === expectedTitle)
    : findings.length === 0;

  console.log(`${passed ? "PASS" : "FAIL"}: ${name}`);

  if (!passed) {
    console.log(
      "  Findings:",
      findings.map((f) => f.title),
    );
    console.log("  Expected:", expectedTitle || "no findings");
  }

  assert.ok(passed, `Test failed: ${name}`);
}

const cspMissing = "Content Security Policy not observed";
const hstsMissing = "HSTS header not observed";

// HSTS validation tests

// A valid positive max-age should not be reported as missing.
const validHstsFindings = analyze(
  [
    {
      name: "strict-transport-security",
      value: "max-age=31536000; includeSubDomains",
    },
  ],
  true,
  "https://example.com",
);

assert.ok(
  !validHstsFindings.some((f) => f.title === "HSTS header not observed"),
  "A present HSTS header should not be reported as missing",
);

console.log("PASS: HSTS header presence");

// A malformed max-age should be detected.
const malformedHstsFindings = analyze(
  [
    {
      name: "strict-transport-security",
      value: "max-age=abc",
    },
  ],
  true,
  "https://example.com",
);

assert.ok(
  malformedHstsFindings.some((f) => f.title === "Invalid HSTS header"),
  "A non-numeric max-age should be reported as invalid",
);

console.log("PASS: Invalid HSTS max-age");

// max-age=0 disables HSTS rather than enabling persistence.
const zeroHstsFindings = analyze(
  [
    {
      name: "strict-transport-security",
      value: "max-age=0",
    },
  ],
  true,
  "https://example.com",
);

assert.ok(
  zeroHstsFindings.some((f) => f.title === "HSTS protection disabled"),
  "max-age=0 should be reported as disabling HSTS",
);

console.log("PASS: HSTS max-age zero");

// HSTS edge-case tests

// A positive max-age should not trigger an HSTS warning.
const positiveHstsFindings = analyze(
  [{ name: "strict-transport-security", value: "max-age=31536000" }],
  true,
  "https://example.com",
);

assert.ok(
  !positiveHstsFindings.some(
    (f) =>
      f.title === "Invalid HSTS header" ||
      f.title === "HSTS protection disabled",
  ),
  "A positive max-age should be accepted",
);

console.log("PASS: Positive HSTS max-age");

// HSTS should not be evaluated for HTTP pages.
const httpHstsFindings = analyze([], true, "http://example.com");

assert.ok(
  !httpHstsFindings.some(
    (f) =>
      f.title === "HSTS header not observed" ||
      f.title === "Invalid HSTS header" ||
      f.title === "HSTS protection disabled",
  ),
  "HSTS should not be evaluated for HTTP pages",
);

console.log("PASS: HSTS ignored on HTTP");

// X-Content-Type-Options edge-case tests

// Header values are case-insensitive.
const caseInsensitiveNosniffFindings = analyze(
  [{ name: "X-Content-Type-Options", value: "NoSnIfF" }],
  true,
  "https://example.com",
);

assert.ok(
  !caseInsensitiveNosniffFindings.some(
    (f) => f.title === "MIME-sniffing protection not observed",
  ),
  "nosniff should be accepted regardless of letter case",
);

console.log("PASS: Case-insensitive nosniff");

// An invalid value should not count as protection.
const invalidNosniffFindings = analyze(
  [{ name: "X-Content-Type-Options", value: "invalid" }],
  true,
  "https://example.com",
);

assert.ok(
  invalidNosniffFindings.some(
    (f) => f.title === "MIME-sniffing protection not observed",
  ),
  "An invalid X-Content-Type-Options value should be flagged",
);

console.log("PASS: Invalid nosniff value");

// A comma-separated value should not be accepted as a valid header.
const commaNosniffFindings = analyze(
  [{ name: "X-Content-Type-Options", value: "nosniff, invalid" }],
  true,
  "https://example.com",
);

assert.ok(
  commaNosniffFindings.some(
    (f) => f.title === "MIME-sniffing protection not observed",
  ),
  "A comma-separated invalid value should be flagged",
);

console.log("PASS: Malformed nosniff value");

// Duplicate X-Content-Type-Options tests

const duplicateNosniffFindings = analyze(
  [
    { name: "x-content-type-options", value: "nosniff" },
    { name: "x-content-type-options", value: "invalid" },
  ],
  true,
  "https://example.com",
);

assert.ok(
  duplicateNosniffFindings.some(
    (f) => f.title === "MIME-sniffing protection not observed",
  ),
  "A duplicate invalid header should not be hidden by a valid header",
);

console.log("PASS: Duplicate X-Content-Type-Options validation");

// X-Frame-Options validation tests

// A valid DENY value should provide framing protection.
const denyXfoFindings = analyze(
  [{ name: "x-frame-options", value: "DENY" }],
  true,
  "https://example.com",
);

assert.ok(
  !denyXfoFindings.some(
    (f) =>
      f.title === "Framing protection not observed" ||
      f.title === "Ambiguous X-Frame-Options header",
  ),
  "X-Frame-Options DENY should be accepted",
);

console.log("PASS: X-Frame-Options DENY");

// A valid SAMEORIGIN value should provide framing protection.
const sameOriginXfoFindings = analyze(
  [{ name: "x-frame-options", value: "SAMEORIGIN" }],
  true,
  "https://example.com",
);

assert.ok(
  !sameOriginXfoFindings.some(
    (f) =>
      f.title === "Framing protection not observed" ||
      f.title === "Ambiguous X-Frame-Options header",
  ),
  "X-Frame-Options SAMEORIGIN should be accepted",
);

console.log("PASS: X-Frame-Options SAMEORIGIN");

// An invalid value should not count as framing protection.
const invalidXfoFindings = analyze(
  [{ name: "x-frame-options", value: "ALLOWALL" }],
  true,
  "https://example.com",
);

assert.ok(
  invalidXfoFindings.some(
    (f) =>
      f.title === "Framing protection not observed" ||
      f.title === "Ambiguous X-Frame-Options header",
  ),
  "An invalid X-Frame-Options value should not count as protection",
);

console.log("PASS: Invalid X-Frame-Options");

// Conflicting duplicate X-Frame-Options headers

const conflictingXfoFindings = analyze(
  [
    { name: "x-frame-options", value: "DENY" },
    { name: "x-frame-options", value: "ALLOWALL" },
  ],
  true,
  "https://example.com",
);

assert.ok(
  conflictingXfoFindings.some(
    (f) => f.title === "Ambiguous X-Frame-Options header",
  ),
  "Conflicting X-Frame-Options values should be reported as ambiguous",
);

console.log("PASS: Conflicting X-Frame-Options headers");

// Referrer-Policy validation tests

// A valid policy should not trigger an invalid-policy finding.
const validReferrerFindings = analyze(
  [{ name: "referrer-policy", value: "strict-origin-when-cross-origin" }],
  true,
  "https://example.com",
);

assert.ok(
  !validReferrerFindings.some(
    (f) => f.title === "Invalid Referrer-Policy header",
  ),
  "A valid Referrer-Policy value should be accepted",
);

console.log("PASS: Valid Referrer-Policy");

// An unrecognized policy should be reported as invalid.
const invalidReferrerFindings = analyze(
  [{ name: "referrer-policy", value: "invalid-policy" }],
  true,
  "https://example.com",
);

assert.ok(
  invalidReferrerFindings.some(
    (f) => f.title === "Invalid Referrer-Policy header",
  ),
  "An invalid Referrer-Policy value should be flagged",
);

console.log("PASS: Invalid Referrer-Policy");

// Policy values are case-insensitive.
const caseInsensitiveReferrerFindings = analyze(
  [{ name: "referrer-policy", value: "NO-REFERRER" }],
  true,
  "https://example.com",
);

assert.ok(
  !caseInsensitiveReferrerFindings.some(
    (f) => f.title === "Invalid Referrer-Policy header",
  ),
  "Referrer-Policy should be matched case-insensitively",
);

console.log("PASS: Case-insensitive Referrer-Policy");

// 1. Headers weren't captured: don't report missing security headers.
runTest(
  "Unavailable header collection",
  [],
  false,
  "https://example.com",
  null,
);

// 2. Collection succeeded, but CSP is missing.
runTest("Missing CSP is reported", [], true, "https://example.com", cspMissing);

// 3. Multiple CSP header values: a policy with frame-ancestors exists.
const multiplePolicies = analyze(
  [
    {
      name: "content-security-policy",
      value: "default-src 'self'",
    },
    {
      name: "content-security-policy",
      value: "frame-ancestors 'none'; object-src 'none'",
    },
  ],
  true,
  "https://example.com",
);

assert.ok(
  !multiplePolicies.some((f) => f.title === "Framing protection not observed"),
  "Expected frame-ancestors protection to be recognized",
);
console.log("PASS: Multiple CSP policies with framing protection");

// 4. HSTS should be checked for HTTPS.
runTest(
  "Missing HSTS on HTTPS is reported",
  [],
  true,
  "https://example.com",
  hstsMissing,
);

// 5. HSTS should not be reported as missing for HTTP.
const httpFindings = analyze([], true, "http://example.com");

assert.ok(
  !httpFindings.some((f) => f.title === hstsMissing),
  "HSTS missing finding should not be generated for HTTP",
);
console.log("PASS: HSTS missing check is skipped for HTTP");

function getFindings(headers) {
  return analyze(headers, true, "https://example.com");
}

// 6. CSP containing unsafe-eval should be flagged.
const unsafeEvalFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'; script-src 'self' 'unsafe-eval'",
  },
]);

assert.ok(
  unsafeEvalFindings.some(
    (f) =>
      f.title === "CSP allows unsafe JavaScript evaluation" ||
      f.evidence.includes("'unsafe-eval'"),
  ),
  "Expected unsafe-eval to be flagged",
);
console.log("PASS: CSP unsafe-eval detection");

// 7. CSP with unsafe-inline should be flagged.
const unsafeInlineFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'; script-src 'self' 'unsafe-inline'",
  },
]);
assert.ok(
  unsafeInlineFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" ||
      f.evidence.includes("'unsafe-inline'"),
  ),
  "Expected unsafe-inline to be flagged",
);
console.log("PASS: CSP unsafe-inline detection");

// 8. script-src-elem takes precedence over script-src for script elements.
const scriptElemFindings = getFindings([
  {
    name: "content-security-policy",
    value:
      "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline'; " +
      "script-src-elem 'self'",
  },
]);

assert.ok(
  !scriptElemFindings.some((f) => f.title === "CSP allows inline scripts"),
  "script-src-elem should take precedence for script elements",
);
console.log("PASS: script-src-elem precedence");

// 9. A secure framing policy should not trigger a framing warning.
const framingFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'; frame-ancestors 'none'",
  },
]);

assert.ok(
  !framingFindings.some((f) => f.title === "Framing protection not observed"),
  "A frame-ancestors 'none' directive should count as framing protection",
);
console.log("PASS: CSP framing protection detection");

//10.
const nonceFindings = getFindings([
  {
    name: "content-security-policy",
    value:
      "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline' 'nonce-abc123'",
  },
]);

assert.ok(
  !nonceFindings.some((f) => f.title === "CSP allows inline scripts"),
  "A nonce source should suppress the unsafe-inline warning",
);
console.log("PASS: CSP nonce handling");

const hashFindings = getFindings([
  {
    name: "content-security-policy",
    value:
      "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline' " +
      "'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='",
  },
]);

assert.ok(
  !hashFindings.some((f) => f.title === "CSP allows inline scripts"),
  "A hash source should suppress the unsafe-inline warning",
);
console.log("PASS: CSP hash handling");

//11.
const scriptAttrFindings = getFindings([
  {
    name: "content-security-policy",
    value:
      "default-src 'self'; " +
      "script-src 'self'; " +
      "script-src-attr 'unsafe-inline'",
  },
]);

assert.ok(
  scriptAttrFindings.some((f) => f.title === "CSP allows inline scripts"),
  "An unsafe-inline script-src-attr directive should be detected",
);
console.log("PASS: script-src-attr unsafe-inline detection");

// 12. script-src-elem without script-src should not trigger
// the existing missing-script-source finding.
const elemOnlyFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'; script-src-elem 'self'",
  },
]);

assert.ok(
  !elemOnlyFindings.some(
    (f) =>
      f.title ===
      "CSP does not restrict scripts through script-src or default-src",
  ),
  "default-src should prevent the missing-script-source finding",
);
console.log("PASS: script-src-elem with default-src fallback");

// 13. A restrictive script-src does not cancel unsafe-inline
// explicitly allowed by script-src-attr.
const attrOverrideFindings = getFindings([
  {
    name: "content-security-policy",
    value:
      "default-src 'self'; " +
      "script-src 'self'; " +
      "script-src-attr 'unsafe-inline'",
  },
]);

assert.ok(
  attrOverrideFindings.some(
    (f) => f.evidence && f.evidence.includes("script-src-attr"),
  ),
  "script-src-attr unsafe-inline should be detected independently",
);
console.log("PASS: script-src-attr checked independently");

// 14. Multiple enforced CSP policies must each be inspected.
const multipleScriptPolicies = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'; script-src 'self'",
  },
  {
    name: "content-security-policy",
    value: "script-src 'unsafe-eval'",
  },
]);

assert.ok(
  multipleScriptPolicies.some(
    (f) => f.title === "CSP allows unsafe JavaScript evaluation",
  ),
  "unsafe-eval in a separate enforced policy should be detected",
);
console.log("PASS: Multiple CSP script policies");

// 15. A wildcard script source should be detected.
const wildcardFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'; script-src *",
  },
]);

assert.ok(
  wildcardFindings.some(
    (f) => f.title === "CSP allows scripts from any host source",
  ),
  "A wildcard script source should be flagged",
);
console.log("PASS: CSP wildcard script source detection");

// 16. CSP directive names are case-insensitive.
const uppercaseFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'; SCRIPT-SRC 'self' 'unsafe-eval'",
  },
]);

assert.ok(
  uppercaseFindings.some(
    (f) => f.title === "CSP allows unsafe JavaScript evaluation",
  ),
  "Uppercase CSP directive names should be recognized",
);
console.log("PASS: Case-insensitive CSP directive names");

// 17. The first duplicate directive takes precedence.
const duplicateFindings = getFindings([
  {
    name: "content-security-policy",
    value:
      "default-src 'self'; " +
      "script-src 'self'; " +
      "script-src 'unsafe-eval'",
  },
]);

assert.ok(
  !duplicateFindings.some(
    (f) => f.title === "CSP allows unsafe JavaScript evaluation",
  ),
  "The second duplicate script-src should be ignored",
);
console.log("PASS: Duplicate CSP directive handling");

// 18. A scheme source is not the literal wildcard source.
const schemeFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'; script-src https:",
  },
]);

assert.ok(
  !schemeFindings.some(
    (f) => f.title === "CSP allows scripts from any host source",
  ),
  "https: should not be mistaken for the literal wildcard *",
);
console.log("PASS: CSP scheme source handling");

// 19. default-src 'none' should also restrict objects
// when object-src is not explicitly present.
const objectFallbackFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'none'",
  },
]);

assert.ok(
  !objectFallbackFindings.some(
    (f) => f.title === "CSP does not explicitly block plugin objects",
  ),
  "default-src 'none' should count as an object-src fallback restriction",
);
console.log("PASS: CSP object-src fallback");

// 20. An explicit base-uri 'none' should be accepted.
const baseUriFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'; base-uri 'none'; object-src 'none'",
  },
]);

assert.ok(
  !baseUriFindings.some(
    (f) => f.title === "CSP base-uri directive not observed",
  ),
  "An explicit base-uri directive should prevent the missing finding",
);
console.log("PASS: CSP base-uri detection");

// 20b. A base-uri restriction in one enforced policy
// should count even if another policy omits the directive.
const multiPolicyBaseUriFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'; base-uri 'none'; object-src 'none'",
  },
  {
    name: "content-security-policy",
    value: "default-src https:",
  },
]);

assert.ok(
  !multiPolicyBaseUriFindings.some(
    (f) => f.title === "CSP base-uri directive not observed",
  ),
  "A base-uri directive in one enforced policy should prevent the missing finding",
);
console.log("PASS: CSP base-uri across multiple policies");

// 21. frame-ancestors 'self' should count as framing protection.
const frameSelfFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'; frame-ancestors 'self'",
  },
]);

assert.ok(
  !frameSelfFindings.some((f) => f.title === "Framing protection not observed"),
  "frame-ancestors 'self' should count as framing protection",
);
console.log("PASS: CSP frame-ancestors self");

// 22. An empty frame-ancestors directive should not count as protection.
const emptyFrameFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'; frame-ancestors",
  },
]);

assert.ok(
  emptyFrameFindings.some((f) => f.title === "Framing protection not observed"),
  "An empty frame-ancestors directive should not count as protection",
);
console.log("PASS: Empty frame-ancestors handling");

// 23. X-Frame-Options DENY should count as framing protection.
const xfoFindings = analyze(
  [
    {
      name: "x-frame-options",
      value: "DENY",
    },
  ],
  true,
  "https://example.com",
);

assert.ok(
  !xfoFindings.some((f) => f.title === "Framing protection not observed"),
  "X-Frame-Options DENY should count as framing protection",
);
console.log("PASS: X-Frame-Options DENY");

// 23b. X-Frame-Options SAMEORIGIN should count as framing protection.
const xfoSameOriginFindings = getFindings([
  {
    name: "x-frame-options",
    value: "SAMEORIGIN",
  },
]);

assert.ok(
  !xfoSameOriginFindings.some(
    (f) => f.title === "Framing protection not observed",
  ),
  "X-Frame-Options SAMEORIGIN should count as framing protection",
);
console.log("PASS: X-Frame-Options SAMEORIGIN");

// 23c. An invalid X-Frame-Options value must not count as protection.
const xfoInvalidFindings = getFindings([
  {
    name: "x-frame-options",
    value: "INVALID",
  },
]);

assert.ok(
  xfoInvalidFindings.some(
    (f) => f.title === "Ambiguous X-Frame-Options header",
  ),
  "An invalid X-Frame-Options value must be reported as ambiguous",
);
console.log("PASS: Invalid X-Frame-Options reported as ambiguous");

// 23d. Conflicting X-Frame-Options values should not be trusted.
const xfoConflictingFindings = getFindings([
  {
    name: "x-frame-options",
    value: "DENY, INVALID",
  },
]);

assert.ok(
  xfoConflictingFindings.some(
    (f) => f.title === "Ambiguous X-Frame-Options header",
  ),
  "Conflicting X-Frame-Options values should not count as reliable protection",
);
console.log("PASS: Conflicting X-Frame-Options");

// 23e. Separate duplicate X-Frame-Options headers are ambiguous.
const xfoDuplicateFindings = getFindings([
  {
    name: "x-frame-options",
    value: "DENY",
  },
  {
    name: "x-frame-options",
    value: "SAMEORIGIN",
  },
]);

assert.ok(
  xfoDuplicateFindings.some(
    (f) => f.title === "Ambiguous X-Frame-Options header",
  ),
  "Separate conflicting X-Frame-Options headers must not count as reliable protection",
);
console.log("PASS: Duplicate X-Frame-Options headers");

// 24. frame-ancestors 'none' is valid protection.
const frameNoneFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'; frame-ancestors 'none'",
  },
]);

assert.ok(
  !frameNoneFindings.some((f) => f.title === "Framing protection not observed"),
  "frame-ancestors 'none' should count as protection",
);
console.log("PASS: frame-ancestors none");

// 25. Multiple allowed ancestor sources should be recognized.
const frameMultipleFindings = getFindings([
  {
    name: "content-security-policy",
    value:
      "default-src 'self'; " + "frame-ancestors 'self' https://example.com",
  },
]);

assert.ok(
  !frameMultipleFindings.some(
    (f) => f.title === "Framing protection not observed",
  ),
  "Multiple valid ancestor sources should count as protection",
);
console.log("PASS: Multiple frame-ancestors sources");

// 26. An invalid source should not count as protection.
const frameInvalidFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'; frame-ancestors invalid-source",
  },
]);

assert.ok(
  frameInvalidFindings.some(
    (f) => f.title === "Framing protection not observed",
  ),
  "An invalid frame-ancestors source should not count as protection",
);
console.log("PASS: Invalid frame-ancestors source");

// 27. The first duplicate directive takes precedence.
const frameDuplicateFindings = getFindings([
  {
    name: "content-security-policy",
    value:
      "default-src 'self'; " +
      "frame-ancestors invalid-source; " +
      "frame-ancestors 'none'",
  },
]);

assert.ok(
  frameDuplicateFindings.some(
    (f) => f.title === "Framing protection not observed",
  ),
  "A later duplicate frame-ancestors directive should be ignored",
);
console.log("PASS: Duplicate frame-ancestors handling");

// 28. Evidence should identify the effective script directive.
const scriptElemEvidenceFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src 'self'; script-src-elem 'unsafe-inline'",
  },
]);

const scriptElemEvidenceFinding = scriptElemEvidenceFindings.find(
  (item) =>
    item.title === "CSP allows inline scripts" &&
    item.evidence.includes("script-src-elem"),
);

assert.ok(
  scriptElemEvidenceFinding,
  "Expected inline-script evidence to identify script-src-elem",
);

assert.strictEqual(
  scriptElemEvidenceFinding.evidence,
  "script-src-elem contains 'unsafe-inline'",
);

console.log("PASS: CSP evidence identifies script-src-elem");

// 29. A nonce in script-src-elem suppresses unsafe-inline for script elements.
const elemNonceFindings = getFindings([
  {
    name: "content-security-policy",
    value:
      "default-src 'self'; " +
      "script-src 'self'; " +
      "script-src-elem 'unsafe-inline' 'nonce-abc123'",
  },
]);

assert.ok(
  !elemNonceFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence === "script-src-elem contains 'unsafe-inline'",
  ),
  "A nonce in script-src-elem should suppress its unsafe-inline warning",
);

console.log("PASS: script-src-elem nonce handling");

// 30. A malformed nonce must not suppress unsafe-inline.
const malformedNonceFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src 'self' 'unsafe-inline' 'nonce-!!!'",
  },
]);

assert.ok(
  malformedNonceFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence === "script-src contains 'unsafe-inline'",
  ),
  "A malformed nonce should not suppress the unsafe-inline warning",
);

console.log("PASS: Malformed nonce handling");

// 30b. A nonce with invalid Base64 characters must not suppress unsafe-inline.
const invalidCharacterNonceFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src 'self' 'unsafe-inline' 'nonce-ab!123'",
  },
]);

assert.ok(
  invalidCharacterNonceFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence === "script-src contains 'unsafe-inline'",
  ),
  "A nonce with invalid Base64 characters must not suppress the unsafe-inline warning",
);

console.log("PASS: Invalid-character nonce handling");

// 31. A malformed SHA-256 hash must not suppress unsafe-inline.
const malformedHashFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src 'self' 'unsafe-inline' 'sha256-abcdefghijklmnop'",
  },
]);

assert.ok(
  malformedHashFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence === "script-src contains 'unsafe-inline'",
  ),
  "A malformed hash should not suppress the unsafe-inline warning",
);

console.log("PASS: Malformed hash handling");

// 32. A nonce in one CSP policy must not suppress
// unsafe-inline in a separate enforced policy.
const separatePolicyFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src 'self' 'nonce-abc123'",
  },
  {
    name: "content-security-policy",
    value: "script-src 'self' 'unsafe-inline'",
  },
]);

assert.ok(
  separatePolicyFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence === "script-src contains 'unsafe-inline'",
  ),
  "A nonce in one policy must not suppress unsafe-inline in another policy",
);

console.log("PASS: Independent CSP policy nonce handling");

// 33. An explicitly empty script-src should not be treated as absent.
const emptyScriptSrcFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'; script-src",
  },
]);

assert.ok(
  !emptyScriptSrcFindings.some(
    (f) =>
      f.title ===
      "CSP does not restrict scripts through script-src or default-src",
  ),
  "An explicitly present empty script-src should not be reported as absent",
);

console.log("PASS: Empty script-src presence handling");

// 34. An empty script-src-elem must not fall back to script-src.
const emptyScriptElemFindings = getFindings([
  {
    name: "content-security-policy",
    value:
      "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline'; " +
      "script-src-elem",
  },
]);

assert.ok(
  !emptyScriptElemFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence === "script-src contains 'unsafe-inline'",
  ),
  "An empty script-src-elem must take precedence over script-src",
);

console.log("PASS: Empty script-src-elem precedence");

// 35. A nonce in one CSP policy must not suppress unsafe-inline in another.
const conflictingPolicyFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src 'nonce-AbCd1234'",
  },
  {
    name: "content-security-policy",
    value: "script-src 'unsafe-inline'",
  },
]);

assert.ok(
  conflictingPolicyFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence === "script-src contains 'unsafe-inline'",
  ),
  "A nonce in one CSP policy must not suppress unsafe-inline in another",
);

console.log("PASS: Independent conflicting CSP policies");

// 36. unsafe-eval in one policy must still be reported when another is restrictive.

const multiPolicyEvalFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src 'self'",
  },
  {
    name: "content-security-policy",
    value: "script-src 'unsafe-eval'",
  },
]);

//console.log("DEBUG Test 36:", multiPolicyEvalFindings);

assert.ok(
  multiPolicyEvalFindings.some(
    (f) =>
      f.title === "CSP allows unsafe JavaScript evaluation" &&
      f.evidence === "script-src contains 'unsafe-eval'",
  ),
  "A restrictive CSP policy must not suppress unsafe-eval in another policy",
);

console.log("PASS: Independent CSP unsafe-eval policies");

// 37. An empty script-src in one policy must not hide unsafe-eval in another.
const emptyAndEvalPolicyFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src",
  },
  {
    name: "content-security-policy",
    value: "script-src 'unsafe-eval'",
  },
]);

assert.ok(
  emptyAndEvalPolicyFindings.some(
    (f) =>
      f.title === "CSP allows unsafe JavaScript evaluation" &&
      f.evidence === "script-src contains 'unsafe-eval'",
  ),
  "An empty script-src policy must not suppress unsafe-eval in another policy",
);

console.log("PASS: Empty and unsafe-eval CSP policies");

// 38. unsafe-eval in script-src-elem must not be treated as an unsafe-eval permission.
const elemUnsafeEvalFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src-elem 'unsafe-eval'; script-src 'self'",
  },
]);

assert.ok(
  !elemUnsafeEvalFindings.some(
    (f) =>
      f.title === "CSP allows unsafe JavaScript evaluation" &&
      f.evidence === "script-src-elem contains 'unsafe-eval'",
  ),
  "script-src-elem should not independently trigger the unsafe-eval finding",
);

console.log("PASS: script-src-elem unsafe-eval distinction");

// 39. unsafe-eval should be detected through default-src when script-src is absent.
const defaultUnsafeEvalFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self' 'unsafe-eval'",
  },
]);

assert.ok(
  defaultUnsafeEvalFindings.some(
    (f) =>
      f.title === "CSP allows unsafe JavaScript evaluation" &&
      f.evidence === "default-src contains 'unsafe-eval'",
  ),
  "unsafe-eval in default-src should be detected when script-src is absent",
);

console.log("PASS: unsafe-eval default-src fallback");

// 40. script-src must override default-src for unsafe-eval.
const scriptOverridesDefaultEvalFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self' 'unsafe-eval'; script-src 'self'",
  },
]);

assert.ok(
  !scriptOverridesDefaultEvalFindings.some(
    (f) => f.title === "CSP allows unsafe JavaScript evaluation",
  ),
  "unsafe-eval in default-src must not trigger when script-src is present without unsafe-eval",
);

console.log("PASS: script-src overrides default-src for unsafe-eval");

// 41. An empty script-src must override default-src for unsafe-eval.
const emptyScriptOverridesDefaultEvalFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self' 'unsafe-eval'; script-src",
  },
]);

assert.ok(
  !emptyScriptOverridesDefaultEvalFindings.some(
    (f) => f.title === "CSP allows unsafe JavaScript evaluation",
  ),
  "An empty script-src must override default-src for unsafe-eval",
);

console.log("PASS: Empty script-src overrides default-src for unsafe-eval");

// 42. script-src-elem must not override default-src for unsafe-eval.
const elemOverridesDefaultEvalFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'; script-src-elem 'unsafe-eval'",
  },
]);

assert.ok(
  !elemOverridesDefaultEvalFindings.some(
    (f) => f.title === "CSP allows unsafe JavaScript evaluation",
  ),
  "unsafe-eval in script-src-elem must not trigger the evaluation finding",
);

console.log(
  "PASS: script-src-elem does not override default-src for unsafe-eval",
);

// 43. An uppercase unsafe-eval keyword must not trigger the finding.
const uppercaseUnsafeEvalFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src 'UNSAFE-EVAL'",
  },
]);

assert.ok(
  !uppercaseUnsafeEvalFindings.some(
    (f) => f.title === "CSP allows unsafe JavaScript evaluation",
  ),
  "CSP keywords are case-sensitive; uppercase UNSAFE-EVAL is not the valid keyword",
);

console.log("PASS: Case-sensitive unsafe-eval keyword");

// 44. CSP directive names are case-insensitive.
const uppercaseDirectiveFindings = getFindings([
  {
    name: "content-security-policy",
    value: "SCRIPT-SRC 'self' 'unsafe-eval'",
  },
]);

assert.ok(
  uppercaseDirectiveFindings.some(
    (f) => f.title === "CSP allows unsafe JavaScript evaluation",
  ),
  "Uppercase SCRIPT-SRC should still recognize unsafe-eval",
);

console.log("PASS: Case-insensitive CSP directive names");

// 45. An empty CSP policy must not crash the analyzer.
assert.doesNotThrow(
  () =>
    getFindings([
      {
        name: "content-security-policy",
        value: "",
      },
    ]),
  "An empty CSP policy should be handled without throwing",
);

console.log("PASS: Empty CSP policy handled safely");

// 46. CSP directives with surrounding whitespace are parsed correctly.
const whitespaceDirectiveFindings = getFindings([
  {
    name: "content-security-policy",
    value: "  script-src   'self'   'unsafe-eval'  ",
  },
]);

assert.ok(
  whitespaceDirectiveFindings.some(
    (f) => f.title === "CSP allows unsafe JavaScript evaluation",
  ),
  "Extra whitespace should not prevent unsafe-eval detection",
);

console.log("PASS: CSP whitespace handled correctly");

// 47. script-src overrides default-src for unsafe-eval.
const scriptSrcOverrideFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self' 'unsafe-eval'; script-src 'self'",
  },
]);

assert.ok(
  !scriptSrcOverrideFindings.some(
    (f) => f.title === "CSP allows unsafe JavaScript evaluation",
  ),
  "unsafe-eval in default-src should not trigger when script-src is present",
);

console.log("PASS: script-src overrides default-src for unsafe-eval");

// 48. script-src-elem must not independently trigger unsafe-eval.
const scriptElemEvalFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src 'self'; script-src-elem 'unsafe-eval'",
  },
]);

assert.ok(
  !scriptElemEvalFindings.some(
    (f) => f.title === "CSP allows unsafe JavaScript evaluation",
  ),
  "unsafe-eval in script-src-elem alone must not trigger the finding",
);

console.log("PASS: script-src-elem does not trigger unsafe-eval");

// 49. script-src-attr should not trigger the script-element inline finding.
const scriptAttrInlineScopeFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src 'self'; script-src-attr 'unsafe-inline'",
  },
]);

assert.ok(
  !scriptAttrInlineScopeFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence !== "script-src-attr contains 'unsafe-inline'",
  ),
  "script-src-attr should not trigger the script-element inline finding",
);

console.log("PASS: script-src-attr finding is scoped correctly");

// 50. Empty script-src-attr must not trigger an inline-script finding.
const emptyScriptAttrFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src 'self'; script-src-attr",
  },
]);

assert.ok(
  !emptyScriptAttrFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence === "script-src-attr contains 'unsafe-inline'",
  ),
  "Empty script-src-attr must not trigger the unsafe-inline finding",
);

console.log("PASS: Empty script-src-attr handled correctly");

// 51. script-src-attr should produce its own specific finding.
const scriptAttrSpecificFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src 'self'; script-src-attr 'unsafe-inline'",
  },
]);

assert.ok(
  scriptAttrSpecificFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence === "script-src-attr contains 'unsafe-inline'",
  ),
  "Expected a specific finding for unsafe-inline in script-src-attr",
);

console.log("PASS: Specific script-src-attr finding");

// 52. Empty script-src-elem must not trigger an inline-script finding.
const emptyScriptElemInlineFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src 'self' 'unsafe-inline'; " + "script-src-elem",
  },
]);

assert.ok(
  !emptyScriptElemInlineFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence === "script-src contains 'unsafe-inline'",
  ),
  "An empty script-src-elem must take precedence over script-src",
);

console.log("PASS: Empty script-src-elem inline-script handling");

// 53. Empty script-src-elem in one policy must not hide
// unsafe-inline in another CSP policy.
const emptyElemMultiPolicyFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src-elem",
  },
  {
    name: "content-security-policy",
    value: "script-src 'self' 'unsafe-inline'",
  },
]);

assert.ok(
  emptyElemMultiPolicyFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence === "script-src contains 'unsafe-inline'",
  ),
  "An empty script-src-elem policy must not hide unsafe-inline in another policy",
);

console.log("PASS: Empty script-src-elem across multiple policies");

// 54. script-src-elem unsafe-inline must not override script-src.
const elemInlineOverrideFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src 'self'; script-src-elem 'unsafe-inline'",
  },
]);

assert.ok(
  !elemInlineOverrideFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence === "script-src contains 'unsafe-inline'",
  ),
  "script-src-elem must not be reported as script-src unsafe-inline",
);

console.log("PASS: script-src-elem inline scope handling");

// 55. script-src-elem should produce its own specific finding.
const elemInlineSpecificFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src 'self'; script-src-elem 'unsafe-inline'",
  },
]);

assert.ok(
  elemInlineSpecificFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence === "script-src-elem contains 'unsafe-inline'",
  ),
  "Expected a specific finding for unsafe-inline in script-src-elem",
);

console.log("PASS: Specific script-src-elem finding");

// 56. Empty script-src-elem must not produce an inline-script finding.
const emptyElemNoInlineFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src-elem",
  },
]);

assert.ok(
  !emptyElemNoInlineFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence === "script-src-elem contains 'unsafe-inline'",
  ),
  "An empty script-src-elem must not produce an unsafe-inline finding",
);

console.log("PASS: Empty script-src-elem inline handling");

// 57. Empty script-src-attr must not fall back to script-src.
const emptyAttrFallbackFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src 'self' 'unsafe-inline'; script-src-attr",
  },
]);

assert.ok(
  !emptyAttrFallbackFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence === "script-src-attr contains 'unsafe-inline'",
  ),
  "An empty script-src-attr must not produce an unsafe-inline finding",
);

console.log("PASS: Empty script-src-attr fallback handling");

// 58. Empty script-src-attr in one policy must not hide
// unsafe-inline in another CSP policy.
const emptyAttrMultiPolicyFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src-attr",
  },
  {
    name: "content-security-policy",
    value: "script-src-attr 'unsafe-inline'",
  },
]);

assert.ok(
  emptyAttrMultiPolicyFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence === "script-src-attr contains 'unsafe-inline'",
  ),
  "An empty script-src-attr policy must not hide unsafe-inline in another policy",
);

console.log("PASS: Empty script-src-attr across multiple policies");

// 59. script-src-attr must retain attribute-specific evidence.
const attrEvidenceIsolationFindings = getFindings([
  {
    name: "content-security-policy",
    value: "script-src 'self'; script-src-attr 'unsafe-inline'",
  },
]);

assert.ok(
  attrEvidenceIsolationFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence === "script-src-attr contains 'unsafe-inline'",
  ),
  "Expected attribute-specific evidence for script-src-attr",
);

assert.ok(
  !attrEvidenceIsolationFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence === "script-src contains 'unsafe-inline'",
  ),
  "script-src-attr must not be mislabeled as script-src",
);

console.log("PASS: script-src-attr evidence isolation");

// 60. Empty script-src-attr must not hide script-src-elem findings.
const emptyAttrElemFindings = getFindings([
  {
    name: "content-security-policy",
    value:
      "script-src 'self'; " +
      "script-src-attr; " +
      "script-src-elem 'unsafe-inline'",
  },
]);

assert.ok(
  emptyAttrElemFindings.some(
    (f) =>
      f.title === "CSP allows inline scripts" &&
      f.evidence === "script-src-elem contains 'unsafe-inline'",
  ),
  "An empty script-src-attr must not hide the script-src-elem finding",
);

console.log("PASS: Empty script-src-attr and script-src-elem handling");

// 61. A valid frame-ancestors source must survive an invalid source.
const mixedFrameAncestorFindings = getFindings([
  {
    name: "content-security-policy",
    value: "frame-ancestors 'self' invalid_source",
  },
]);

assert.ok(
  !mixedFrameAncestorFindings.some(
    (f) => f.title === "Framing protection not observed",
  ),
  "A valid frame-ancestors source must not be rejected because another source is invalid",
);

console.log("PASS: Mixed valid and invalid frame-ancestors sources");

// 62. When 'none' is combined with 'self', 'self' still restricts framing.
const noneSelfFrameFindings = getFindings([
  {
    name: "content-security-policy",
    value: "frame-ancestors 'none' 'self'",
  },
]);

assert.ok(
  !noneSelfFrameFindings.some(
    (f) => f.title === "Framing protection not observed",
  ),
  "'self' must still restrict framing when combined with 'none'",
);

console.log("PASS: Mixed 'none' and 'self' frame-ancestors");

// 63. An invalid-only frame-ancestors source must not count as protection.
const invalidOnlyFrameFindings = getFindings([
  {
    name: "content-security-policy",
    value: "frame-ancestors invalid_source",
  },
]);

assert.ok(
  invalidOnlyFrameFindings.some(
    (f) => f.title === "Framing protection not observed",
  ),
  "An invalid-only frame-ancestors source must not count as protection",
);

console.log("PASS: Invalid-only frame-ancestors source");

// 64. Empty frame-ancestors must not count as framing protection.
const emptyFrameAncestor64Findings = getFindings([
  {
    name: "content-security-policy",
    value: "frame-ancestors",
  },
]);

assert.ok(
  emptyFrameAncestor64Findings.some(
    (f) => f.title === "Framing protection not observed",
  ),
  "An empty frame-ancestors directive must not count as protection",
);

console.log("PASS: Empty frame-ancestors protection handling");

// 65. Invalid frame-ancestors in one policy must not hide
// valid framing protection in another CSP policy.
const invalidValidFrame65Findings = getFindings([
  {
    name: "content-security-policy",
    value: "frame-ancestors invalid_source",
  },
  {
    name: "content-security-policy",
    value: "frame-ancestors 'self'",
  },
]);

assert.ok(
  !invalidValidFrame65Findings.some(
    (f) => f.title === "Framing protection not observed",
  ),
  "Valid frame-ancestors protection in another policy must be recognized",
);

console.log("PASS: Independent frame-ancestors policy handling");

// 66. A CSP with valid frame-ancestors must not be reported as missing CSP.
const validFrameNoMissingCsp66Findings = getFindings([
  {
    name: "content-security-policy",
    value: "frame-ancestors 'self'",
  },
]);

assert.ok(
  !validFrameNoMissingCsp66Findings.some(
    (f) => f.title === "Content Security Policy not observed",
  ),
  "An observed CSP header must not be reported as missing",
);

assert.ok(
  !validFrameNoMissingCsp66Findings.some(
    (f) => f.title === "Framing protection not observed",
  ),
  "A valid frame-ancestors directive must count as framing protection",
);

console.log("PASS: Valid frame-ancestors and CSP presence");

// 67. Uppercase FRAME-ANCESTORS must still be recognized.
const uppercaseFrame67Findings = getFindings([
  {
    name: "content-security-policy",
    value: "FRAME-ANCESTORS 'self'",
  },
]);

assert.ok(
  !uppercaseFrame67Findings.some(
    (f) => f.title === "Framing protection not observed",
  ),
  "CSP directive names must be case-insensitive",
);

console.log("PASS: Case-insensitive frame-ancestors directive");

// 68. Extra whitespace must not break frame-ancestors detection.
const whitespaceFrame68Findings = getFindings([
  {
    name: "content-security-policy",
    value: "   frame-ancestors    'self'   ",
  },
]);

assert.ok(
  !whitespaceFrame68Findings.some(
    (f) => f.title === "Framing protection not observed",
  ),
  "Whitespace must not prevent valid frame-ancestors detection",
);

console.log("PASS: Whitespace handling for frame-ancestors");

// 69. An empty CSP policy must not hide valid framing protection
// provided by another CSP policy.
const emptyValidFrame69Findings = getFindings([
  {
    name: "content-security-policy",
    value: "",
  },
  {
    name: "content-security-policy",
    value: "frame-ancestors 'self'",
  },
]);

assert.ok(
  !emptyValidFrame69Findings.some(
    (f) => f.title === "Framing protection not observed",
  ),
  "Valid framing protection in another policy must be recognized",
);

console.log("PASS: Empty and valid framing policies");

// 70. Uppercase CSP header names must still be recognized.
const uppercaseHeader70Findings = getFindings([
  {
    name: "Content-Security-Policy",
    value: "frame-ancestors 'self'",
  },
]);

assert.ok(
  !uppercaseHeader70Findings.some(
    (f) => f.title === "Content Security Policy not observed",
  ),
  "CSP header names must be handled case-insensitively",
);

assert.ok(
  !uppercaseHeader70Findings.some(
    (f) => f.title === "Framing protection not observed",
  ),
  "Framing protection must be recognized with uppercase CSP header names",
);

console.log("PASS: Case-insensitive CSP header names");

// 71. CSP headers with different casing must both be recognized.
const mixedCaseHeaders71Findings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'",
  },
  {
    name: "Content-Security-Policy",
    value: "frame-ancestors 'self'",
  },
]);

assert.ok(
  !mixedCaseHeaders71Findings.some(
    (f) => f.title === "Framing protection not observed",
  ),
  "A CSP header with different casing must provide framing protection",
);

assert.ok(
  !mixedCaseHeaders71Findings.some(
    (f) => f.title === "Content Security Policy not observed",
  ),
  "Multiple CSP headers with different casing must not appear missing",
);

console.log("PASS: Mixed-case duplicate CSP headers");

// 72. An unrelated CSP policy must not hide valid framing protection.
const unrelatedPolicy72Findings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'; script-src 'unsafe-inline'",
  },
  {
    name: "content-security-policy",
    value: "frame-ancestors 'self'",
  },
]);

assert.ok(
  !unrelatedPolicy72Findings.some(
    (f) => f.title === "Framing protection not observed",
  ),
  "Valid framing protection must be recognized across CSP policies",
);

console.log("PASS: Framing protection across unrelated CSP policies");

// 73. Whitespace around 'none' must not break framing protection.
const whitespaceNone73Findings = getFindings([
  {
    name: "content-security-policy",
    value: "frame-ancestors    'none'   ",
  },
]);

assert.ok(
  !whitespaceNone73Findings.some(
    (f) => f.title === "Framing protection not observed",
  ),
  "frame-ancestors 'none' must count as framing protection",
);

console.log("PASS: Whitespace handling for frame-ancestors none");

// 74. A specific HTTPS origin must be recognized for frame-ancestors.
const httpsOriginFrame74Findings = getFindings([
  {
    name: "content-security-policy",
    value: "frame-ancestors https://trusted.example.com",
  },
]);

assert.ok(
  !httpsOriginFrame74Findings.some(
    (f) => f.title === "Framing protection not observed",
  ),
  "A valid HTTPS origin must be recognized in frame-ancestors",
);

console.log("PASS: HTTPS origin in frame-ancestors");

// 75. An invalid HTTPS origin must not count as framing protection.
const invalidHttpsFrame75Findings = getFindings([
  {
    name: "content-security-policy",
    value: "frame-ancestors https://",
  },
]);

assert.ok(
  invalidHttpsFrame75Findings.some(
    (f) => f.title === "Framing protection not observed",
  ),
  "An invalid HTTPS origin must not count as framing protection",
);

console.log("PASS: Invalid HTTPS origin in frame-ancestors");

// 76. Valid CSP framing protection overrides an invalid X-Frame-Options finding.
const cspValidXfoInvalidFindings = getFindings([
  {
    name: "content-security-policy",
    value: "frame-ancestors 'none'",
  },
  {
    name: "x-frame-options",
    value: "INVALID",
  },
]);

assert.ok(
  !cspValidXfoInvalidFindings.some(
    (f) =>
      f.title === "Framing protection not observed" ||
      f.title === "Ambiguous X-Frame-Options header",
  ),
  "Valid CSP framing protection should prevent a framing-protection finding",
);
console.log("PASS: Valid CSP with invalid X-Frame-Options");

// 77. Invalid X-Frame-Options with CSP lacking frame-ancestors is ambiguous.
const cspMissingXfoInvalidFindings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'",
  },
  {
    name: "x-frame-options",
    value: "INVALID",
  },
]);

assert.ok(
  cspMissingXfoInvalidFindings.some(
    (f) => f.title === "Ambiguous X-Frame-Options header",
  ),
  "Invalid X-Frame-Options should be reported as ambiguous when CSP lacks frame-ancestors",
);
console.log("PASS: CSP without frame-ancestors and invalid X-Frame-Options");

// 78. Valid CSP and valid X-Frame-Options should not trigger a framing finding.
const bothFramingValidFindings = getFindings([
  {
    name: "content-security-policy",
    value: "frame-ancestors 'self'",
  },
  {
    name: "x-frame-options",
    value: "SAMEORIGIN",
  },
]);

assert.ok(
  !bothFramingValidFindings.some(
    (f) =>
      f.title === "Framing protection not observed" ||
      f.title === "Ambiguous X-Frame-Options header",
  ),
  "Valid CSP and X-Frame-Options should not trigger a framing-protection finding",
);
console.log("PASS: Valid CSP and valid X-Frame-Options");

//79 Custom CSP-like header must not count as an enforced CSP.
const customCspFindings = getFindings([
  {
    name: "content-security-policy-insert",
    value: "default-src 'self'; script-src 'self'",
  },
]);

assert.ok(
  customCspFindings.some(
    (finding) => finding.title === "Content Security Policy not observed",
  ),
  "A custom CSP-like header must not count as a standard CSP header",
);

console.log("PASS: Custom CSP-like header is not treated as enforced CSP");

// 80. A standard CSP header must suppress the missing-CSP finding.
const standardCsp80Findings = getFindings([
  {
    name: "content-security-policy",
    value: "default-src 'self'; frame-ancestors 'self'",
  },
]);

assert.ok(
  !standardCsp80Findings.some(
    (finding) => finding.title === "Content Security Policy not observed",
  ),
  "A standard Content-Security-Policy header must not be reported missing",
);

console.log("PASS: Standard CSP header recognized");

// 81. Malformed header entries should not crash the analyzer.
const malformedHeaderEntryFindings = analyze(
  [
    null,
    {},
    { name: "", value: "some-value" },
    { name: "server", value: "" },
    { name: "x-powered-by", value: null },
    { name: "server", value: "ExampleServer" },
  ],
  true,
  "https://example.com",
);

assert.ok(
  Array.isArray(malformedHeaderEntryFindings),
  "Malformed header entries should still produce an array of findings",
);

assert.ok(
  malformedHeaderEntryFindings.some(
    (finding) =>
      finding.title === "Server or platform information disclosed" &&
      finding.evidence === "server: ExampleServer",
  ),
  "A valid header should still be processed alongside malformed entries",
);

console.log("PASS: Malformed header entries handled safely");

// 82. Non-array input should return an empty array.
const nonArrayInputFindings = analyze(null, true, "https://example.com");

assert.ok(
  Array.isArray(nonArrayInputFindings),
  "Non-array input should return an array",
);

assert.strictEqual(
  nonArrayInputFindings.length,
  0,
  "Non-array input should return zero findings",
);

console.log("PASS: Non-array input handled safely");

// 83. Missing arguments should be handled safely.
const missingArgumentsFindings = analyze();

assert.ok(
  Array.isArray(missingArgumentsFindings),
  "Missing arguments should return an array",
);

assert.strictEqual(
  missingArgumentsFindings.length,
  0,
  "Missing arguments should return zero findings",
);

console.log("PASS: Missing arguments handled safely");

// 84. String input should return an empty array.
const stringInputFindings = analyze(
  "server: ExampleServer",
  true,
  "https://example.com",
);

assert.ok(
  Array.isArray(stringInputFindings),
  "String input should return an array",
);

assert.strictEqual(
  stringInputFindings.length,
  0,
  "String input should return zero findings",
);

console.log("PASS: String input handled safely");

// 85. Empty headers should report missing-header findings.
const emptyHeadersFindings = analyze([], true, "https://example.com");

assert.ok(
  Array.isArray(emptyHeadersFindings),
  "Empty headers should return an array of findings",
);

assert.ok(
  emptyHeadersFindings.some(
    (finding) => finding.title === "Content Security Policy not observed",
  ),
  "Missing CSP should be reported when no headers are present",
);

assert.ok(
  emptyHeadersFindings.some(
    (finding) => finding.title === "HSTS header not observed",
  ),
  "Missing HSTS should be reported for an HTTPS response",
);

assert.ok(
  emptyHeadersFindings.some(
    (finding) => finding.title === "Framing protection not observed",
  ),
  "Missing framing protection should be reported",
);

console.log("PASS: Empty headers produce expected findings");

// 86. Observed disclosure findings should survive unavailable collection.
const uncapturedDisclosureFindings = analyze(
  [
    {
      name: "server",
      value: "ExampleServer",
    },
  ],
  false,
  "https://example.com",
);

assert.ok(
  uncapturedDisclosureFindings.some(
    (finding) =>
      finding.title === "Server or platform information disclosed" &&
      finding.evidence === "server: ExampleServer",
  ),
  "Observed server disclosure should be preserved when collection is unavailable",
);

assert.ok(
  !uncapturedDisclosureFindings.some(
    (finding) => finding.title === "Content Security Policy not observed",
  ),
  "Missing-header findings should not be generated when collection is unavailable",
);

console.log("PASS: Observed findings preserved when collection is unavailable");

console.log("\nAll tests passed.");
