// Load dependencies in Chrome's service worker.
// Firefox loads these files through manifest.firefox.json.
if (typeof importScripts === "function") {
  importScripts("cveClient.js", "detector.js");
}

const api = typeof browser !== "undefined" ? browser : chrome;

// Store only the latest main-document response headers per tab.
const recentHeaders = new Map();

const ALLOWED_HEADERS = new Set([
  "server",
  "x-powered-by",
  "x-aspnet-version",
  "x-vercel-id",
  "cf-ray",
  "x-amz-cf-id",
  "x-amz-request-id",
  "x-nf-request-id",
  "x-render-origin-server",
  "x-runtime",
  "x-application-context",
  "x-varnish",
  "via",
  "x-cache",
  "x-drupal-cache",
  "x-generator",
  // Browser security headers
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

// Clear old headers as soon as a new main-page request starts.
api.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0 || details.type !== "main_frame") return;
    recentHeaders.delete(details.tabId);
  },
  {
    urls: ["http://*/*", "https://*/*"],
    types: ["main_frame"],
  },
);

// Capture headers from the main document only.
// Ignore subframes and API/XHR responses to reduce false positives.
api.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (
      details.tabId < 0 ||
      details.type !== "main_frame" ||
      details.frameId !== 0
    ) {
      return;
    }

    const safeHeaders = (details.responseHeaders || [])
      .filter(
        (header) =>
          header.name && ALLOWED_HEADERS.has(header.name.toLowerCase()),
      )
      .map((header) => ({
        name: header.name,
        value: String(header.value || ""),
      }));

    // Replace rather than merge, so old server clues cannot linger.
    recentHeaders.set(details.tabId, safeHeaders);
  },
  {
    urls: ["http://*/*", "https://*/*"],
    types: ["main_frame"],
  },
  ["responseHeaders"],
);

// Remove cached data when a tab closes.
api.tabs.onRemoved.addListener((tabId) => {
  recentHeaders.delete(tabId);
});

// Keep the message format compatible with popup.js.
api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Existing header-capture handler.
  if (message?.type === "TECHLENS_GET_HEADERS") {
    const captured = recentHeaders.has(message.tabId);

    sendResponse({
      headers: recentHeaders.get(message.tabId) || [],
      captured,
    });

    return;
  }

  // New CVE lookup handler.
  if (message?.type === "TECHLENS_GET_CVES") {
    const technologyId =
      typeof message.technologyId === "string"
        ? message.technologyId.trim()
        : "";

    if (!technologyId || technologyId.length > 100) {
      sendResponse({
        success: false,
        error: "Invalid technology ID.",
      });

      return;
    }

    // Find the product in TechLens's trusted detector catalogue.
    const rule = globalThis.TechLensDetector?.RULES?.find(
      (item) => item.id === technologyId,
    );

    const product = rule?.product;
    const searchByCpe = globalThis.TechLensCVE?.searchByCpe;

    if (
      !product ||
      product.cpeStatus !== "verified" ||
      typeof product.cpe !== "string" ||
      !product.cpe ||
      typeof searchByCpe !== "function"
    ) {
      sendResponse({
        success: false,
        error: "No verified CPE mapping exists for this technology.",
      });

      return;
    }

    const version =
      typeof message.version === "string" ? message.version.trim() : "";

    if (!version || version.length > 50) {
      sendResponse({
        success: false,
        error: "A valid confirmed version is required.",
      });

      return;
    }

    searchByCpe(product, { version })
      .then((result) => {
        sendResponse({
          success: true,
          data: result,
        });
      })
      .catch((error) => {
        sendResponse({
          success: false,
          error:
            typeof error?.message === "string"
              ? error.message
              : "An unexpected error occurred during CVE lookup.",
        });
      });

    return true;
  }
});
