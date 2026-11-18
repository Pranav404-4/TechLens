"use strict";

(function (root) {
  const NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

  /**
   * Check the basic structure of a CPE 2.3 formatted string.
   * Respects escaped colons inside components.
   */
  function isValidCpe23(cpe) {
    if (typeof cpe !== "string" || !cpe.startsWith("cpe:2.3:")) {
      return false;
    }

    const components = [];
    let current = "";

    for (let i = 0; i < cpe.length; i++) {
      const char = cpe[i];

      if (char === "\\") {
        if (i + 1 >= cpe.length) return false;
        current += char + cpe[i + 1];
        i++;
        continue;
      }

      if (char === ":") {
        components.push(current);
        current = "";
      } else {
        current += char;
      }
    }

    components.push(current);

    if (components.length !== 13) return false;
    if (components.some((component) => component.length === 0)) {
      return false;
    }

    if (components[0] !== "cpe" || components[1] !== "2.3") {
      return false;
    }

    const validParts = ["a", "o", "h", "*", "-"];

    if (!validParts.includes(components[2])) return false;
    if (!components[3] || !components[4]) return false;

    return true;
  }

  /**
   * Split a CPE 2.3 string into its 13 components.
   */
  function splitCpe23(cpe) {
    if (!isValidCpe23(cpe)) return null;

    const components = [];
    let current = "";

    for (let i = 0; i < cpe.length; i++) {
      const char = cpe[i];

      if (char === "\\") {
        current += char + cpe[i + 1];
        i++;
      } else if (char === ":") {
        components.push(current);
        current = "";
      } else {
        current += char;
      }
    }

    components.push(current);
    return components;
  }

  /**
   * Compare two numeric version components without integer overflow.
   */
  function compareNumericParts(left, right) {
    const a = left.replace(/^0+(?=\d)/, "");
    const b = right.replace(/^0+(?=\d)/, "");

    if (a.length !== b.length) {
      return a.length > b.length ? 1 : -1;
    }

    if (a === b) return 0;
    return a > b ? 1 : -1;
  }

  /**
   * Compare common dotted numeric versions.
   *
   * This deliberately rejects unsupported version formats rather
   * than guessing their ordering.
   */
  function compareVersions(left, right) {
    if (
      typeof left !== "string" ||
      typeof right !== "string" ||
      !/^\d+(?:\.\d+)*$/.test(left) ||
      !/^\d+(?:\.\d+)*$/.test(right)
    ) {
      return null;
    }

    const a = left.split(".");
    const b = right.split(".");
    const length = Math.max(a.length, b.length);

    for (let i = 0; i < length; i++) {
      const result = compareNumericParts(a[i] || "0", b[i] || "0");
      if (result !== 0) return result;
    }

    return 0;
  }

  /**
   * Check whether a version satisfies NVD version boundaries.
   */
  function matchesVersionRange(match, version) {
    if (!match || typeof version !== "string") return null;

    const cpeParts = splitCpe23(match.criteria);

    if (!cpeParts) return null;

    const criteriaVersion = cpeParts[5];

    const boundaries = [
      "versionStartIncluding",
      "versionStartExcluding",
      "versionEndIncluding",
      "versionEndExcluding",
    ];

    // Wildcard means any version.
    // An undefined CPE version cannot establish version applicability.
    if (criteriaVersion === "-") {
      return null;
    }

    if (criteriaVersion !== "*") {
      const comparison = compareVersions(version, criteriaVersion);

      if (comparison === null) return null;
      if (comparison !== 0) return false;
    }

    for (const field of boundaries) {
      const boundary = match[field];

      if (boundary === undefined || boundary === null) continue;

      if (typeof boundary !== "string" || !/^\d+(?:\.\d+)*$/.test(boundary)) {
        return null;
      }

      const comparison = compareVersions(version, boundary);

      if (comparison === null) return null;

      if (field === "versionStartIncluding" && comparison < 0) {
        return false;
      }

      if (field === "versionStartExcluding" && comparison <= 0) {
        return false;
      }

      if (field === "versionEndIncluding" && comparison > 0) {
        return false;
      }

      if (field === "versionEndExcluding" && comparison >= 0) {
        return false;
      }
    }

    return true;
  }

  /**
   * Match a CPE criteria string against the verified product identity.
   * Version is evaluated separately.
   */
  function matchesProductIdentity(criteria, productCpe) {
    const criteriaParts = splitCpe23(criteria);
    const productParts = splitCpe23(productCpe);

    // Invalid or unsupported CPE data is unknown.
    if (!criteriaParts || !productParts) return null;

    // Match part, vendor and product exactly.
    for (const index of [2, 3, 4]) {
      if (criteriaParts[index] !== productParts[index]) {
        return false;
      }
    }

    // Match non-version attributes when NVD specifies them.
    for (let index = 6; index < 13; index++) {
      const expected = criteriaParts[index];

      if (expected !== "*" && expected !== productParts[index]) {
        return false;
      }
    }

    return true;
  }

  /**
   * Evaluate one NVD CPE match.
   */
  function evaluateCpeMatch(match, product, version) {
    if (!match || typeof match !== "object") return null;

    // Environmental conditions cannot be verified using
    // the detected product alone.
    if (match.vulnerable !== true) {
      return null;
    }

    const identityMatch = matchesProductIdentity(match.criteria, product.cpe);

    if (identityMatch === null) return null;
    if (identityMatch === false) return false;

    return matchesVersionRange(match, version);
  }

  /**
   * Evaluate nested NVD configuration nodes.
   *
   * Returns true, false, or null when the structure cannot
   * be safely evaluated.
   */
  function evaluateConfigurationNode(node, product, version) {
    if (!node || typeof node !== "object") return null;

    const results = [];

    if (Array.isArray(node.cpeMatch)) {
      for (const match of node.cpeMatch) {
        results.push(evaluateCpeMatch(match, product, version));
      }
    }

    if (Array.isArray(node.nodes)) {
      for (const child of node.nodes) {
        results.push(evaluateConfigurationNode(child, product, version));
      }
    }

    if (results.length === 0) return null;

    let operator;

    if (
      typeof node.operator === "string" &&
      ["AND", "OR"].includes(node.operator.toUpperCase())
    ) {
      operator = node.operator.toUpperCase();
    } else if (
      node.operator === undefined &&
      !Array.isArray(node.cpeMatch) &&
      Array.isArray(node.nodes)
    ) {
      // Top-level configuration wrapper: evaluate its alternatives as OR.
      operator = "OR";
    } else {
      return null;
    }

    let result;

    if (operator === "AND") {
      if (results.includes(false)) {
        result = false;
      } else if (results.includes(null)) {
        result = null;
      } else {
        result = true;
      }
    } else if (operator === "OR") {
      if (results.includes(true)) {
        result = true;
      } else if (results.includes(null)) {
        result = null;
      } else {
        result = false;
      }
    } else {
      return null;
    }

    // Apply NVD node negation without converting unknown to known.
    if (node.negate === true) {
      return result === null ? null : !result;
    }

    return result;
  }

  /**
   * Determine whether a CVE configuration affects a product version.
   */
  function assessCveVersion(cve, product, version) {
    if (
      !cve ||
      !Array.isArray(cve.configurations) ||
      cve.configurations.length === 0 ||
      !product ||
      !isValidCpe23(product.cpe) ||
      typeof version !== "string"
    ) {
      return "unconfirmed";
    }

    const results = cve.configurations.map((configuration) =>
      evaluateConfigurationNode(configuration, product, version),
    );

    if (results.includes(true)) return "affected";
    if (results.every((result) => result === false)) {
      return "not_affected";
    }

    return "unconfirmed";
  }

  /**
   * Extract the highest available CVSS metric.
   */
  function getCvssMetric(metrics = {}) {
    const metricKeys = [
      "cvssMetricV40",
      "cvssMetricV31",
      "cvssMetricV30",
      "cvssMetricV2",
    ];

    for (const key of metricKeys) {
      const metric = metrics[key]?.[0];

      if (!metric?.cvssData) continue;

      return {
        version: metric.cvssData.version || null,
        score: metric.cvssData.baseScore ?? null,
        severity: metric.cvssData.baseSeverity || metric.baseSeverity || null,
        vector: metric.cvssData.vectorString || null,
      };
    }

    return null;
  }

  /**
   * Normalize one NVD vulnerability record.
   */
  function parseCveRecord(item) {
    const cve = item?.cve;

    if (!cve || typeof cve.id !== "string") {
      return null;
    }

    const description =
      cve.descriptions?.find((entry) => entry.lang === "en")?.value ||
      cve.descriptions?.[0]?.value ||
      null;

    return {
      id: cve.id,
      description,
      status: cve.vulnStatus || null,
      published: cve.published || null,
      lastModified: cve.lastModified || null,
      cvss: getCvssMetric(cve.metrics),
      references: (cve.references || [])
        .filter((reference) => reference.url)
        .map((reference) => ({
          url: reference.url,
          tags: reference.tags || [],
        })),
      configurations: cve.configurations || [],
    };
  }

  /**
   * Normalize an entire NVD API response.
   */
  function parseNvdResponse(data) {
    if (
      !data ||
      typeof data !== "object" ||
      !Array.isArray(data.vulnerabilities)
    ) {
      throw new Error("Invalid NVD response format.");
    }

    const vulnerabilities = data.vulnerabilities
      .map(parseCveRecord)
      .filter(Boolean);

    return {
      totalResults:
        Number.isInteger(data.totalResults) && data.totalResults >= 0
          ? data.totalResults
          : vulnerabilities.length,
      vulnerabilities,
    };
  }

  /**
   * Search NVD using a verified CPE identifier.
   * Fetch all result pages sequentially.
   */
  async function searchByCpe(product, options = {}) {
    if (
      !product ||
      product.cpeStatus !== "verified" ||
      !isValidCpe23(product.cpe)
    ) {
      throw new Error("A verified CPE identifier is required.");
    }

    const version = options.version;

    if (typeof version !== "string" || !/^\d+(?:\.\d+)*$/.test(version)) {
      throw new Error("A supported confirmed version is required.");
    }

    const queryCpeParts = splitCpe23(product.cpe);

    if (!queryCpeParts) {
      throw new Error("Invalid product CPE identifier.");
    }

    // Use the confirmed detected version for the NVD API query.
    queryCpeParts[5] = version;

    const queryCpe = queryCpeParts.join(":");

    const resultsPerPage = 2000;
    const pause = Number.isFinite(options.pause)
      ? Math.max(0, options.pause)
      : 6500;

    let startIndex = 0;
    let totalResults = null;
    const vulnerabilities = [];

    do {
      const params = new URLSearchParams({
        cpeName: queryCpe,
        resultsPerPage: String(resultsPerPage),
        startIndex: String(startIndex),
      });

      const response = await fetch(`${NVD_API_URL}?${params.toString()}`);

      if (response.status === 403 || response.status === 429) {
        throw new Error("NVD rate limit reached. Try again later.");
      }

      if (!response.ok) {
        throw new Error(`NVD API error: HTTP ${response.status}`);
      }

      const data = await response.json();
      const page = parseNvdResponse(data);

      if (totalResults === null) {
        totalResults = page.totalResults;
      }

      vulnerabilities.push(...page.vulnerabilities);

      const returnedCount = Array.isArray(data.vulnerabilities)
        ? data.vulnerabilities.length
        : 0;

      if (returnedCount === 0) break;

      startIndex += returnedCount;

      if (startIndex < totalResults && pause > 0) {
        await new Promise((resolve) => setTimeout(resolve, pause));
      }
    } while (startIndex < totalResults);

    const assessed = version
      ? vulnerabilities.map((cve) => ({
          ...cve,
          applicability: assessCveVersion(cve, product, version),
        }))
      : vulnerabilities.map((cve) => ({
          ...cve,
          applicability: "unconfirmed",
        }));

    return {
      totalResults: totalResults ?? vulnerabilities.length,
      vulnerabilities: assessed,
      affected: assessed.filter((cve) => cve.applicability === "affected"),
      notAffected: assessed.filter(
        (cve) => cve.applicability === "not_affected",
      ),
      unconfirmed: assessed.filter(
        (cve) => cve.applicability === "unconfirmed",
      ),
    };
  }

  root.TechLensCVE = {
    searchByCpe,
    isValidCpe23,
    parseCveRecord,
    getCvssMetric,
    parseNvdResponse,
    compareVersions,
    matchesVersionRange,
    matchesProductIdentity,
    assessCveVersion,
  };
})(globalThis);
