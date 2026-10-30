"use strict";

const TechLensRiskAnalyzer = (() => {
  const SECURITY_HEADERS = new Set([
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
  ]);

  function analyze(headers, captured = false, pageUrl = "") {
    const findings = [];
    const seen = new Set();

    if (!Array.isArray(headers)) {
      return findings;
    }

    const headerMap = new Map();

    for (const header of headers) {
      const name = String(header?.name || "")
        .toLowerCase()
        .trim();
      const value = String(header?.value || "").trim();

      if (!name || !value) continue;

      if (!headerMap.has(name)) {
        headerMap.set(name, []);
      }

      headerMap.get(name).push(value);
    }

    function addFinding({
      title,
      category = "Security Configuration",
      severity = "Low",
      description,
      evidence = "",
      recommendation = "",
    }) {
      const key = `${title}:${evidence}`.toLowerCase();

      if (seen.has(key)) return;
      seen.add(key);

      findings.push({
        title,
        category,
        severity,
        description,
        evidence,
        recommendation,
      });
    }

    // Existing server and backend disclosure checks.
    for (const name of ["server", "x-powered-by"]) {
      for (const value of headerMap.get(name) || []) {
        if (name === "server") {
          addFinding({
            title: "Server or platform information disclosed",
            category: "Information Disclosure",
            severity: "Informational",
            description:
              `The response exposes its server identification: ${value}. ` +
              "This can help visitors identify server software, but does not prove a vulnerability.",
            evidence: `${name}: ${value}`,
            recommendation:
              "Consider reducing unnecessary server-version details where practical.",
          });
        } else {
          addFinding({
            title: "Backend technology disclosed",
            category: "Information Disclosure",
            severity: "Informational",
            description:
              `The X-Powered-By header exposes: ${value}. ` +
              "Its presence alone does not indicate a security flaw.",
            evidence: `${name}: ${value}`,
            recommendation:
              "Remove this header if it is unnecessary and can be safely disabled.",
          });
        }
      }
    }

    // Missing-header checks are only valid when collection succeeded.
    if (!captured) {
      return findings;
    }

    const isHttps = (() => {
      try {
        return new URL(pageUrl).protocol === "https:";
      } catch {
        return false;
      }
    })();

    const has = (name) => headerMap.has(name);
    const valueOf = (name) => (headerMap.get(name) || []).join("; ");

    // Content Security Policy: inspect individual directives.
    const cspPolicies = headerMap.get("content-security-policy") || [];
    let hasBaseUriDirective = false;
    let hasObjectSrcNone = false;

    if (cspPolicies.length === 0) {
      addFinding({
        title: "Content Security Policy not observed",
        severity: "Medium",
        description:
          "No Content-Security-Policy header was observed on the main document response. This removes one possible browser-enforced defense against some content-injection attacks, but does not prove the site is vulnerable.",
        evidence: "Content-Security-Policy header not observed",
        recommendation:
          "Consider a policy tailored to the application's required scripts, styles, frames, and other resources. Test changes carefully before enforcement.",
      });
    } else {
      for (const policy of cspPolicies) {
        const directives = new Map();

        for (const part of policy.split(";")) {
          const tokens = part.trim().split(/\s+/).filter(Boolean);
          if (!tokens.length) continue;

          const directiveName = tokens[0].toLowerCase();

          // CSP directive names are case-insensitive.
          // The first occurrence of a directive takes precedence.
          if (!directives.has(directiveName)) {
            directives.set(directiveName, tokens.slice(1));
          }
        }

        let scriptDirectiveName = null;
        let scriptSources = null;

        for (const name of ["script-src-elem", "script-src", "default-src"]) {
          if (directives.has(name)) {
            scriptDirectiveName = name;
            scriptSources = directives.get(name);
            break;
          }
        }

        const scriptAttrSources = directives.get("script-src-attr");

        if (
          scriptAttrSources &&
          scriptAttrSources.includes("'unsafe-inline'")
        ) {
          addFinding({
            title: "CSP allows inline scripts",
            severity: "Low",
            description:
              "The script-src-attr directive allows inline event-handler attributes, such as onclick. This is separate from script elements controlled by script-src-elem.",
            evidence: "script-src-attr contains 'unsafe-inline'",
            recommendation:
              "Avoid inline event handlers where practical, and use restrictive script-src-attr policies or external event listeners.",
          });
        }

        if (scriptSources === null) {
          addFinding({
            title:
              "CSP does not restrict scripts through script-src or default-src",
            severity: "Low",
            description:
              "The observed policy has neither script-src nor default-src. This means the policy does not provide those directives as a fallback for scripts; other controls may still apply.",
            evidence: "script-src and default-src directives not observed",
            recommendation:
              "Review whether script-src or default-src can be configured to restrict scripts to the sources the application actually needs.",
          });
        } else {
          const hasNonceOrHash = scriptSources.some((source) => {
            const nonceMatch = source.match(
              /^'nonce-([A-Za-z0-9+/_-]+={0,2})'$/,
            );

            if (nonceMatch) {
              return true;
            }

            const hashMatch = source.match(
              /^'(sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})'$/,
            );

            if (!hashMatch) {
              return false;
            }

            const expectedLengths = {
              sha256: 43,
              sha384: 64,
              sha512: 86,
            };

            const encodedHash = hashMatch[2].replace(/=+$/, "");

            return encodedHash.length === expectedLengths[hashMatch[1]];
          });

          if (scriptSources.includes("'unsafe-inline'") && !hasNonceOrHash) {
            addFinding({
              title: "CSP allows inline scripts",
              severity: "Low",
              description:
                "The effective script source directive includes 'unsafe-inline' without a nonce or hash source that would normally cause browsers to ignore this keyword under modern CSP processing.",
              evidence: `${scriptDirectiveName} contains 'unsafe-inline'`,
              recommendation:
                "Prefer nonces or hashes for inline scripts and remove 'unsafe-inline' when the application can support it.",
            });
          }

          const evalDirectiveSources = directives.has("script-src")
            ? directives.get("script-src")
            : directives.get("default-src");

          if (
            evalDirectiveSources &&
            evalDirectiveSources.includes("'unsafe-eval'")
          ) {
            addFinding({
              title: "CSP allows unsafe JavaScript evaluation",
              severity: "Low",
              description:
                "The effective script source directive includes 'unsafe-eval', which permits certain string-based JavaScript evaluation mechanisms.",
              evidence: `${directives.has("script-src") ? "script-src" : "default-src"} contains 'unsafe-eval'`,
              recommendation:
                "Remove 'unsafe-eval' if the application does not require it.",
            });
          }

          if (scriptSources.includes("*")) {
            addFinding({
              title: "CSP allows scripts from any host source",
              severity: "Medium",
              description:
                "The effective script source directive contains a wildcard source. This may allow scripts from a broad range of hosts, although scheme, nonce, hash, and other policy restrictions can affect the final result.",
              evidence: `${scriptDirectiveName} contains *`,
              recommendation:
                "Replace broad wildcard sources with explicitly trusted script origins where practical.",
            });
          }
        }

        const objectSources =
          directives.get("object-src") ?? directives.get("default-src") ?? null;

        if (objectSources && objectSources.includes("'none'")) {
          hasObjectSrcNone = true;
        }

        const baseSources = directives.get("base-uri");

        if (baseSources) {
          hasBaseUriDirective = true;
        }
      }

      if (cspPolicies.length > 0 && !hasObjectSrcNone) {
        addFinding({
          title: "CSP does not explicitly block plugin objects",
          severity: "Informational",
          description:
            "None of the observed enforced CSP policies explicitly blocks plugin objects using object-src 'none' or a default-src 'none' fallback. Other directives or browser behavior may affect risk, so this is a hardening recommendation rather than proof of a vulnerability.",
          evidence: "object-src 'none' not observed in enforced CSP policies",
          recommendation:
            "If the application does not require embedded plugin objects, consider adding object-src 'none'.",
        });
      }

      if (cspPolicies.length > 0 && !hasBaseUriDirective) {
        addFinding({
          title: "CSP base-uri directive not observed",
          severity: "Informational",
          description:
            "None of the observed enforced CSP policies explicitly restrict document base URLs. This directive can help reduce the impact of certain injected base elements.",
          evidence: "base-uri directive not observed in enforced CSP policies",
          recommendation:
            "Consider setting base-uri 'self' or base-uri 'none', depending on the application's requirements.",
        });
      }
    }

    // HSTS only applies to HTTPS.
    if (isHttps) {
      const hstsValues = headerMap.get("strict-transport-security") || [];

      if (hstsValues.length === 0) {
        addFinding({
          title: "HSTS header not observed",
          severity: "Medium",
          description:
            "The HTTPS response did not expose a Strict-Transport-Security header in the collected data. HSTS helps browsers use HTTPS for future connections.",
          evidence:
            "Strict-Transport-Security header not observed on HTTPS response",
          recommendation:
            "Consider enabling HSTS with an appropriate max-age after confirming HTTPS works correctly across the intended hostnames.",
        });
      } else {
        for (const hstsValue of hstsValues) {
          const maxAgeMatch = hstsValue.match(
            /(?:^|;)\s*max-age\s*=\s*([^;\s]*)/i,
          );

          if (!maxAgeMatch || !/^\d+$/.test(maxAgeMatch[1])) {
            addFinding({
              title: "Invalid HSTS header",
              severity: "Medium",
              description:
                "The observed Strict-Transport-Security header does not contain a valid non-negative integer max-age directive.",
              evidence: `Strict-Transport-Security: ${hstsValue}`,
              recommendation:
                "Set max-age to a non-negative integer representing the number of seconds browsers should remember the HTTPS-only policy.",
            });
          } else if (Number(maxAgeMatch[1]) === 0) {
            addFinding({
              title: "HSTS protection disabled",
              severity: "Medium",
              description:
                "The HSTS max-age is zero, which instructs browsers to delete the remembered HSTS policy for this host.",
              evidence: `Strict-Transport-Security: ${hstsValue}`,
              recommendation:
                "Use a positive max-age if you intend to enable HSTS protection.",
            });
          }
        }
      }
    }

    // MIME-sniffing protection.
    if (
      !has("x-content-type-options") ||
      (headerMap.get("x-content-type-options") || []).some(
        (value) => value.trim().toLowerCase() !== "nosniff",
      ) ||
      !(headerMap.get("x-content-type-options") || []).some(
        (value) => value.trim().toLowerCase() === "nosniff",
      )
    ) {
      addFinding({
        title: "MIME-sniffing protection not observed",
        severity: "Low",
        description:
          "The response did not expose X-Content-Type-Options: nosniff. This header can help prevent browsers from interpreting certain resources as a different content type.",
        evidence: has("x-content-type-options")
          ? `X-Content-Type-Options: ${valueOf("x-content-type-options")}`
          : "X-Content-Type-Options header not observed",
        recommendation:
          "For responses where appropriate, configure X-Content-Type-Options: nosniff and serve accurate Content-Type values.",
      });
    }

    // Framing protection: either CSP frame-ancestors or X-Frame-Options
    // can provide protection, so don't require both.

    // Framing protection: inspect each CSP policy independently.
    const cspPoliciesForFraming =
      headerMap.get("content-security-policy") || [];

    const hasFrameAncestors = cspPoliciesForFraming.some((policy) => {
      const directives = new Map();

      for (const part of policy.split(";")) {
        const tokens = part.trim().split(/\s+/).filter(Boolean);
        if (!tokens.length) continue;

        const name = tokens[0].toLowerCase();

        // Only the first occurrence of a directive is used.
        if (!directives.has(name)) {
          directives.set(name, tokens.slice(1));
        }
      }

      const sources = directives.get("frame-ancestors");

      if (!sources || sources.length === 0) {
        return false;
      }

      // Recognize common valid CSP frame-ancestor source expressions.
      return sources.some((source) => {
        const value = source.toLowerCase();

        return (
          value === "'none'" ||
          value === "'self'" ||
          /^https?:\/\/[^/\s]+(?::\d+)?$/.test(value) ||
          /^https?:$/.test(value) ||
          /^\/\/[^/\s]+(?::\d+)?$/.test(value) ||
          /^https?:\/\/\*\.[^/\s]+(?::\d+)?$/.test(value) ||
          /^https?:\/\/[^/\s]*\*[^/\s]*(?::\d+)?$/.test(value)
        );
      });
    });

    const xfoValues = (headerMap.get("x-frame-options") || [])
      .flatMap((value) => value.split(","))
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean);

    const hasUsefulXfo =
      xfoValues.length === 1 && ["deny", "sameorigin"].includes(xfoValues[0]);

    if (!hasFrameAncestors && !hasUsefulXfo) {
      const hasXfoHeader = xfoValues.length > 0;

      addFinding({
        title: hasXfoHeader
          ? "Ambiguous X-Frame-Options header"
          : "Framing protection not observed",
        severity: "Medium",
        description: hasXfoHeader
          ? "The observed X-Frame-Options header contains invalid or conflicting values. TechLens cannot confidently determine the intended framing protection from this header."
          : "Neither a CSP frame-ancestors directive nor a recognized X-Frame-Options value was observed. This may leave the page without these common browser-enforced framing protections.",
        evidence: hasXfoHeader
          ? `Unrecognized or ambiguous X-Frame-Options values: ${xfoValues.join(", ")}`
          : "No recognized frame-ancestors or X-Frame-Options protection observed",
        recommendation:
          "If the page should not be embedded, configure CSP frame-ancestors and/or a single valid X-Frame-Options value to match the intended embedding policy.",
      });
    }

    // Referrer-Policy validation.
    const validReferrerPolicies = new Set([
      "no-referrer",
      "no-referrer-when-downgrade",
      "origin",
      "origin-when-cross-origin",
      "same-origin",
      "strict-origin",
      "strict-origin-when-cross-origin",
      "unsafe-url",
    ]);

    const referrerValues = headerMap.get("referrer-policy") || [];

    if (referrerValues.length === 0) {
      addFinding({
        title: "Referrer-Policy not observed",
        severity: "Low",
        description:
          "The response did not expose a Referrer-Policy header in the collected data.",
        evidence: "Referrer-Policy header not observed",
        recommendation:
          "Consider setting an appropriate Referrer-Policy to control how much referrer information browsers send.",
      });
    } else {
      const policies = referrerValues.flatMap((value) =>
        value.split(",").map((item) => item.trim().toLowerCase()),
      );

      if (policies.some((policy) => !validReferrerPolicies.has(policy))) {
        addFinding({
          title: "Invalid Referrer-Policy header",
          severity: "Low",
          description:
            "The response contains an unrecognized Referrer-Policy value.",
          evidence: `Referrer-Policy: ${referrerValues.join("; ")}`,
          recommendation:
            "Use a recognized Referrer-Policy directive, such as strict-origin-when-cross-origin or no-referrer.",
        });
      }
    }

    // Permissions Policy.

    if (!has("permissions-policy")) {
      addFinding({
        title: "Permissions Policy recommendation",
        category: "Hardening Recommendation",
        severity: "Informational",
        description:
          "No Permissions-Policy header was observed. Not every website needs this header, and its absence does not prove a vulnerability.",
        evidence: "Permissions-Policy header not observed",
        recommendation:
          "Review which browser features the site uses and consider restricting features that are not required.",
      });
    }

    // Additional isolation headers are advisory, not universal requirements.

    return findings;
  }

  return { analyze };
})();
