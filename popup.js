const api = typeof browser !== "undefined" ? browser : chrome;

let allDetections = [];
let currentFilter = "All";
let currentPage = null;
let allHeaders = [];
let securityFindings = [];
let isScanning = false;

const $ = (id) => document.getElementById(id);

// Return a confidence label based on the detection score.
function confidenceLevel(score) {
  if (score >= 85) return "high";
  if (score >= 65) return "medium";
  return "low";
}

// Generate initials for the technology logo.
function initials(name) {
  return name
    .split(/[\s/.-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0])
    .join("")
    .toUpperCase();
}

// Escape text before inserting it into HTML.
function esc(value) {
  return String(value).replace(
    /[&<>"']/g,
    (char) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[char],
  );
}

// Render detected technologies and update the dashboard.
function render() {
  // Build filters from the categories actually returned by the detector.
  const categories = [
    ...new Set(
      allDetections
        .map((detection) => detection.category)
        .filter((category) => typeof category === "string" && category.trim()),
    ),
  ].sort((a, b) => a.localeCompare(b));

  if (currentFilter !== "All" && !categories.includes(currentFilter)) {
    currentFilter = "All";
  }

  $("filters").innerHTML = ["All", ...categories]
    .map(
      (category) => `
    <button class="filter${category === currentFilter ? " active" : ""}"
      data-filter="${esc(category)}">${esc(category)}</button>
  `,
    )
    .join("");

  const shown = allDetections.filter(
    (detection) =>
      currentFilter === "All" || detection.category === currentFilter,
  );

  $("results").innerHTML = shown
    .map((detection) => {
      const score = Number.isFinite(detection.confidence)
        ? Math.max(0, Math.min(99, detection.confidence))
        : 70;
      const level = confidenceLevel(score);
      const version = detection.version ? ` ${esc(detection.version)}` : "";
      const evidence = Array.isArray(detection.evidence)
        ? detection.evidence
        : [];

      return `
      <article class="tech-card">
        <div class="tech-head">
          <div class="tech-logo">
            ${esc(initials(detection.name))}
          </div>

          <div class="tech-main">
            <div class="tech-name">
              ${esc(detection.name)}${version}
            </div>
            <div class="tech-category">
              ${esc(detection.category)}
            </div>
          </div>

          <span class="confidence ${level}">
            ${esc(level.toUpperCase())} · ${score}%
          </span>
        </div>

        <div class="evidence">
          <div class="evidence-label">Detection evidence</div>
          <ul>
            ${evidence.map((item) => `<li>${esc(item)}</li>`).join("")}
          </ul>
        </div>
      </article>
    `;
    })
    .join("");

  $("empty").hidden = shown.length > 0;
  $("results").hidden = shown.length === 0;

  $("detected-count").textContent = allDetections.length;
  $("high-count").textContent = allDetections.filter(
    (detection) =>
      Number.isFinite(detection.confidence) && detection.confidence >= 85,
  ).length;
  $("count").textContent = allDetections.length;

  if (allDetections.length === 0) {
    $("status").textContent =
      "No matching fingerprints found in accessible evidence.";
  } else {
    $("status").textContent =
      `Found ${allDetections.length} technologies · ` +
      `${shown.length} shown · confidence is heuristic`;
  }

  document.querySelectorAll(".filter").forEach((button) => {
    button.classList.toggle("active", button.dataset.filter === currentFilter);
  });
}

// Scan the active browser tab.
async function scan() {
  const scanStarted = performance.now();
  $("status").textContent = "Inspecting accessible page evidence…";
  $("results").innerHTML = "";
  $("empty").hidden = true;

  allHeaders = [];
  securityFindings = [];
  renderSecurityInsights();

  try {
    const tabs = await api.tabs.query({
      active: true,
      currentWindow: true,
    });

    const tab = tabs[0];

    if (!tab?.id || !tab.url || !/^https?:/i.test(tab.url)) {
      $("site-host").textContent = "This page cannot be inspected";
      $("site-title").textContent = "Open a regular HTTP or HTTPS website.";

      $("status").innerHTML =
        '<div class="error">Browser-internal pages, extension stores, ' +
        "and some protected tabs block inspection.</div>";

      allDetections = [];
      render();
      return;
    }

    currentPage = {
      url: tab.url,
      title: tab.title || "",
    };

    $("site-host").textContent = new URL(tab.url).hostname;
    $("site-title").textContent = tab.title || "";

    // Reuse the content script or inject it if necessary.
    let response;

    try {
      response = await api.tabs.sendMessage(tab.id, {
        type: "TECHLENS_SCAN",
      });
    } catch (_) {
      await api.scripting.executeScript({
        target: { tabId: tab.id },
        files: ["content.js"],
      });

      response = await api.tabs.sendMessage(tab.id, {
        type: "TECHLENS_SCAN",
      });
    }

    if (!response?.ok) {
      throw new Error(response?.error || "Could not collect page evidence.");
    }

    // Retrieve response headers collected by background.js.
    const headerResult = await api.runtime.sendMessage({
      type: "TECHLENS_GET_HEADERS",
      tabId: tab.id,
    });

    const headers = headerResult?.headers || [];

    allHeaders = headers;

    securityFindings = TechLensRiskAnalyzer.analyze(
      allHeaders,
      headerResult?.captured === true,
      tab.url,
    );
    renderSecurityInsights();

    // Run the technology fingerprint detector.

    // Recover runtime versions from the webpage's JavaScript context.
    try {
      const runtimeVersions = await api.scripting.executeScript({
        target: { tabId: tab.id },
        world: "MAIN",

        func: () => {
          const versions = [];
          const globals = [];

          const addVersion = (name, version) => {
            if (typeof version === "string" && version.trim()) {
              versions.push({ name, version: version.trim() });
            }
          };

          // jQuery
          addVersion("jQuery", window.jQuery?.fn?.jquery);

          // React
          addVersion("React", window.React?.version);

          // Vue.js
          addVersion("Vue.js", window.Vue?.version);

          // Angular
          const angularVersion =
            document.documentElement?.getAttribute("ng-version");
          addVersion("Angular", angularVersion);

          // Next.js: read the version exposed by its App Router runtime.
          // Only accept a version-shaped string; do not infer from build IDs.
          const nextVersion = window.next?.version;

          if (
            typeof nextVersion === "string" &&
            /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(
              nextVersion.trim(),
            )
          ) {
            addVersion("Next.js", nextVersion.trim());
          }

          // Axios
          addVersion("Axios", window.axios?.VERSION || window.axios?.version);

          // Lodash
          addVersion("Lodash", window._?.VERSION);

          // D3.js
          addVersion("D3.js", window.d3?.version);

          // GSAP
          addVersion("GSAP", window.gsap?.version);

          // Backbone.js
          addVersion("Backbone.js", window.Backbone?.VERSION);

          // Ember.js
          addVersion("Ember.js", window.Ember?.VERSION);

          // htmx
          addVersion("htmx", window.htmx?.version);

          if (typeof window.Vue !== "undefined") globals.push("Vue");
          if (typeof window.__VUE__ !== "undefined") globals.push("__VUE__");

          return { versions, globals };
        },
      });

      const runtimeResult = runtimeVersions?.[0]?.result || {};
      const versions = runtimeResult.versions || [];
      response.page.globals ??= [];

      for (const name of runtimeResult.globals || []) {
        if (!response.page.globals.includes(name)) {
          response.page.globals.push(name);
        }
      }
      response.page.versionHints ??= [];

      for (const item of versions) {
        const exists = response.page.versionHints.some(
          (hint) =>
            hint.name?.toLowerCase() === item.name.toLowerCase() &&
            hint.version,
        );

        if (!exists) {
          response.page.versionHints.push(item);
        }
      }
    } catch (error) {
      console.warn("TechLens: Could not collect runtime versions:", error);
    }

    // Recover Vue.js version from its runtime-core bundle.
    try {
      const runtimeResult = await api.scripting.executeScript({
        target: { tabId: tab.id },
        world: "MAIN",
        func: async () => {
          const urls = performance
            .getEntriesByType("resource")
            .map((entry) => entry.name)
            .filter((url) => /runtime-core\.esm-bundler/i.test(url));

          for (const url of urls) {
            try {
              const response = await fetch(url);
              if (!response.ok) continue;

              const source = await response.text();

              // Vue's runtime-core bundle exports its version
              // through a marker such as: var oo=`3.5.42`;
              const match = source.match(/var\s+\w+\s*=\s*`(3\.\d+\.\d+)`/);

              if (match) {
                return match[1];
              }
            } catch (_) {
              // Try another matching runtime resource.
            }
          }

          return null;
        },
      });

      const vueVersion = runtimeResult?.[0]?.result;

      if (vueVersion) {
        response.page.versionHints ??= [];

        const existingVueHint = response.page.versionHints.find(
          (hint) => hint.name?.toLowerCase() === "vue.js",
        );

        if (existingVueHint) {
          existingVueHint.version = vueVersion;
        } else {
          response.page.versionHints.push({
            name: "Vue.js",
            version: vueVersion,
          });
        }
      }
    } catch (error) {
      console.warn("TechLens: Could not collect Vue.js bundle version:", error);
    }

    // Recover React version from a loaded JavaScript bundle.
    try {
      const reactVersionResult = await api.scripting.executeScript({
        target: { tabId: tab.id },
        world: "MAIN",
        func: async () => {
          const urls = [
            ...new Set(
              performance
                .getEntriesByType("resource")
                .map((entry) => entry.name)
                .filter(
                  (url) =>
                    /\.js(?:\?|$)/i.test(url) &&
                    (/_next\/static\/chunks/i.test(url) ||
                      /githubassets\.com\/assets\/react(?:-dom|-dom-client)?-[^/]+\.js/i.test(
                        url,
                      )),
                ),
            ),
          ];

          for (const url of urls) {
            try {
              const response = await fetch(url);
              if (!response.ok) continue;

              const source = await response.text();

              // GitHub's React bundles expose version markers such as
              // t.version="19.3.1".
              const isGitHubReactBundle =
                /githubassets\.com\/assets\/react(?:-dom|-dom-client)?-[^/]+\.js/i.test(
                  url,
                );

              if (isGitHubReactBundle) {
                const githubMatch = source.match(
                  /\b\w+\.version\s*=\s*["'](\d+\.\d+\.\d+)["']/,
                );

                if (githubMatch) {
                  return githubMatch[1];
                }
              }

              // Accept the version marker only when the bundle also contains
              // the additional React-specific indicator.
              const match = source.match(
                /["'](\d+\.\d+\.\d+)["']!==(\w+)\)throw Error\(s\(527,\2,/,
              );

              if (match && source.includes("findDOMNode")) {
                return match[1];
              }
            } catch (_) {
              // Skip resources that cannot be inspected.
            }
          }

          return null;
        },
      });

      const reactVersion = reactVersionResult?.[0]?.result;

      if (reactVersion) {
        response.page.versionHints ??= [];

        const existingReactHint = response.page.versionHints.find(
          (hint) => hint.name?.toLowerCase() === "react",
        );

        if (existingReactHint) {
          existingReactHint.version = reactVersion;
        } else {
          response.page.versionHints.push({
            name: "React",
            version: reactVersion,
          });
        }
      }
    } catch (error) {
      console.warn("TechLens: Could not collect React bundle version:", error);
    }

    // Run the technology fingerprint detector.
    const detections = TechLensDetector.detect({
      page: response.page,
      headers,
    });

    allDetections = detections.map((detection) => ({
      name: detection.name,
      category: detection.category,
      confidence: Number.isFinite(detection.confidence)
        ? Math.max(0, Math.min(99, detection.confidence))
        : 70,
      version: detection.version || null,
      evidence: Array.isArray(detection.evidence) ? detection.evidence : [],
      sourceUrl: tab.url,
    }));

    render();
  } catch (error) {
    allDetections = [];
    allHeaders = [];
    securityFindings = [];

    $("status").innerHTML =
      `<div class="error">Scan failed: ` +
      `${esc(error.message || String(error))}<br>` +
      "Reload the website and try again.</div>";

    render();
  } finally {
    isScanning = false;
  }
}

// Render Security Insights separately from the scan function.

function renderSecurityInsights() {
  const container = $("risk-results");
  const count = $("risk-count");

  if (!container || !count) return;

  const disclosures = securityFindings.filter(
    (finding) => finding.category === "Information Disclosure",
  );

  const recommendations = securityFindings.filter(
    (finding) => finding.category === "Hardening Recommendation",
  );

  const configurations = securityFindings.filter(
    (finding) => finding.category === "Security Configuration",
  );

  // Informational disclosures and recommendations do not add risk points.
  // These weights are heuristics, not a vulnerability probability.
  const severityPoints = {
    Critical: 40,
    High: 25,
    Medium: 15,
    Low: 5,
    Informational: 0,
  };

  const priorityScore = Math.min(
    100,
    securityFindings.reduce((total, finding) => {
      // Recommendations are guidance, not confirmed security weaknesses.
      if (finding.category === "Hardening Recommendation") {
        return total;
      }

      return total + (severityPoints[finding.severity] ?? 0);
    }, 0),
  );

  let priorityLabel = "Low Priority";

  if (priorityScore >= 60) {
    priorityLabel = "High Priority";
  } else if (priorityScore >= 30) {
    priorityLabel = "Elevated Priority";
  } else if (priorityScore >= 10) {
    priorityLabel = "Moderate Priority";
  }

  count.textContent = securityFindings.length;

  if (securityFindings.length === 0) {
    container.innerHTML = `
      <p class="risk-empty">
        No findings were identified from the collected headers.
        This is not a complete security assessment.
      </p>
    `;
    return;
  }

  container.innerHTML = `
    <div class="risk-priority">
      <strong>Security Priority: ${priorityScore}/100</strong>
      <span>${esc(priorityLabel)}</span>
      <p>
        Heuristic indicator based on observed header findings.
        This is not a vulnerability probability or a complete security assessment.
      </p>
    </div>

    <div class="risk-summary">
      <div class="risk-summary-item">
        <strong>${disclosures.length}</strong>
        <span>Information Disclosure</span>
      </div>
      <div class="risk-summary-item">
        <strong>${configurations.length}</strong>
        <span>Security Configuration</span>
      </div>
      <div class="risk-summary-item">
        <strong>${recommendations.length}</strong>
        <span>Hardening Recommendations</span>
      </div>
    </div>

    ${securityFindings
      .map(
        (finding) => `
      <article class="risk-card">
        <div class="risk-card-heading">
          <strong>${esc(finding.title)}</strong>
          <span class="risk-severity">${esc(finding.severity)}</span>
        </div>
        <p>${esc(finding.description)}</p>
        ${
          finding.evidence
            ? `
          <div class="evidence-label">Evidence</div>
          <code>${esc(finding.evidence)}</code>
        `
            : ""
        }
        ${
          finding.recommendation
            ? `
          <div class="evidence-label">Recommendation</div>
          <p>${esc(finding.recommendation)}</p>
        `
            : ""
        }
      </article>
    `,
      )
      .join("")}
  `;
}

// Switch between Technologies and Security views.
document.querySelectorAll(".view-tab").forEach((button) => {
  button.addEventListener("click", () => {
    const selectedView = button.dataset.view;

    document.querySelectorAll(".view-tab").forEach((tab) => {
      const isActive = tab === button;

      tab.classList.toggle("active", isActive);
      tab.setAttribute("aria-selected", String(isActive));
    });

    $("technologies-view").hidden = selectedView !== "technologies";
    $("security-view").hidden = selectedView !== "security";
  });
});

// Handle category filters.
$("filters").addEventListener("click", (event) => {
  const button = event.target.closest(".filter");
  if (!button) return;
  currentFilter = button.dataset.filter;
  render();
});

// Rescan the current page.
$("refresh").addEventListener("click", scan);

// Export the current detections as a JSON report.

$("export").addEventListener("click", () => {
  if (isScanning) {
    $("status").textContent =
      "Please wait for the scan to finish before exporting.";
    return;
  }
  const report = {
    tool: "TechLens",
    version: "1.0.0",
    scannedAt: new Date().toISOString(),
    page: currentPage,
    detectionMethod: "passive browser-visible fingerprinting",
    technologies: allDetections,
    securityInsights: securityFindings,
    notes: [
      "Confidence is heuristic, not a probability.",
      "Undetected technologies may still be present.",
      "Security insights are limited to the evidence collected by TechLens.",
      "Informational findings do not establish that a vulnerability exists.",
    ],
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], {
    type: "application/json",
  });

  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;

  const hostname = currentPage?.url
    ? new URL(currentPage.url).hostname
    : "website";

  const websiteName = hostname
    .replace(/^www\./i, "")
    .split(".")[0]
    .replace(/[^a-zA-Z0-9-]/g, "-");

  const exportDate = new Date().toISOString().slice(0, 10);

  link.download = `TechLens Report - ${websiteName} - ${exportDate}.json`;
  link.click();

  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

// Export Security Insights as a separate JSON report.
$("export-security").addEventListener("click", () => {
  if (isScanning) {
    $("status").textContent =
      "Please wait for the scan to finish before exporting.";
    return;
  }
  const severityCounts = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Informational: 0,
  };

  const categoryCounts = {};

  securityFindings.forEach((finding) => {
    if (Object.hasOwn(severityCounts, finding.severity)) {
      severityCounts[finding.severity]++;
    }

    const category = finding.category || "Uncategorized";
    categoryCounts[category] = (categoryCounts[category] || 0) + 1;
  });

  const severityPoints = {
    Critical: 40,
    High: 25,
    Medium: 15,
    Low: 5,
    Informational: 0,
  };

  const priorityScore = Math.min(
    100,
    securityFindings.reduce((total, finding) => {
      if (finding.category === "Hardening Recommendation") {
        return total;
      }

      return total + (severityPoints[finding.severity] ?? 0);
    }, 0),
  );

  let priorityLabel = "Low Priority";

  if (priorityScore >= 60) {
    priorityLabel = "High Priority";
  } else if (priorityScore >= 30) {
    priorityLabel = "Elevated Priority";
  } else if (priorityScore >= 10) {
    priorityLabel = "Moderate Priority";
  }

  const report = {
    tool: "TechLens",
    reportType: "Security Insights",
    version: "1.0.0",
    generatedAt: new Date().toISOString(),
    page: currentPage,
    securityPriority: {
      score: priorityScore,
      label: priorityLabel,
      methodology: "Heuristic indicator, not a vulnerability probability",
    },
    summary: {
      totalFindings: securityFindings.length,
      bySeverity: severityCounts,
      byCategory: categoryCounts,
    },
    findings: securityFindings,
    notes: [
      "This report reflects only the evidence collected by TechLens.",
      "Missing or unobserved headers do not by themselves prove a vulnerability.",
      "The security priority score is heuristic and is not a complete security assessment.",
    ],
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], {
    type: "application/json",
  });

  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;

  const hostname = currentPage?.url
    ? new URL(currentPage.url).hostname
    : "website";

  const websiteName = hostname
    .replace(/^www\./i, "")
    .split(".")[0]
    .replace(/[^a-zA-Z0-9-]/g, "-");

  const exportDate = new Date().toISOString().slice(0, 10);

  link.download = `TechLens Security Report - ${websiteName} - ${exportDate}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();

  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

//Automatically scan when the popup opens.
scan();
