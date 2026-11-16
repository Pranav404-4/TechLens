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
        // A trailing escape is invalid.
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

    // CPE 2.3 contains 13 components:
    // cpe, 2.3, part, vendor, product, version,
    // update, edition, language, sw_edition,
    // target_sw, target_hw, other.
    if (components.length !== 13) return false;

    // Every CPE component must contain a value.
    if (components.some((component) => component.length === 0)) {
      return false;
    }

    if (components[0] !== "cpe" || components[1] !== "2.3") {
      return false;
    }

    const validParts = ["a", "o", "h", "*", "-"];

    if (!validParts.includes(components[2])) {
      return false;
    }

    // Vendor and product must not be empty.
    if (!components[3] || !components[4]) {
      return false;
    }

    return true;
  }

  /**
   * Search NVD using a verified CPE identifier.
   */
  async function searchByCpe(product) {
    if (
      !product ||
      product.cpeStatus !== "verified" ||
      !isValidCpe23(product.cpe)
    ) {
      throw new Error("A verified CPE identifier is required.");
    }

    const params = new URLSearchParams({
      cpeName: product.cpe,
      resultsPerPage: "100",
    });

    const response = await fetch(`${NVD_API_URL}?${params.toString()}`);

    if (response.status === 403 || response.status === 429) {
      throw new Error("NVD rate limit reached. Try again later.");
    }

    if (!response.ok) {
      throw new Error(`NVD API error: HTTP ${response.status}`);
    }

    return response.json();
  }

  root.TechLensCVE = {
    searchByCpe,
    isValidCpe23,
  };
})(globalThis);
