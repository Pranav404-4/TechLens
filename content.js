(() => {
  async function collectPageEvidence() {
    // Collect scripts, stylesheets, links, and loaded resources.
    const scripts = [...document.scripts]
      .map((script) => script.src || script.textContent?.slice(0, 120) || "")
      .filter(Boolean)
      .slice(0, 250);

    const styles = [...document.querySelectorAll('link[rel="stylesheet"]')]
      .map((link) => link.href)
      .slice(0, 150);

    const links = [...document.querySelectorAll("link[href]")]
      .map((link) => link.href)
      .slice(0, 250);

    const resources = [
      ...new Set(
        performance
          .getEntriesByType("resource")
          .map((entry) => entry.name)
          .filter(Boolean),
      ),
    ].slice(0, 500);

    // Collect metadata, including Open Graph and other property-based metadata.
    const meta = [...document.querySelectorAll("meta")]
      .map((element) => {
        const key =
          element.getAttribute("name") ||
          element.getAttribute("property") ||
          element.getAttribute("http-equiv") ||
          "";

        return `${key}:${element.content || ""}`;
      })
      .slice(0, 150);

    // Check for recognizable JavaScript globals.
    const globalNames = [
      "React",
      "ReactDOM",
      "Vue",
      "ng",
      "jQuery",
      "$",
      "Shopify",
      "Drupal",
      "Magento",
      "gtag",
      "google_tag_manager",
      "_paq",
      "__NEXT_DATA__",
      "__NUXT__",
      "__VUE__",
      "__REACT_DEVTOOLS_GLOBAL_HOOK__",
      "Alpine",
      "axios",
      "htmx",
      "d3",
      "THREE",
      "gsap",
      "_",
      "Backbone",
      "Ember",
      "Meteor",
      "ko",
      "Handlebars",
      "Mustache",
      "bootstrap",
      "__SENTRY__",
    ];

    const globals = globalNames.filter((name) => {
      try {
        return typeof window[name] !== "undefined";
      } catch (_) {
        return false;
      }
    });
    console.log("[TechLens DEBUG] Vue globals:", {
      Vue: globals.includes("Vue"),
      __VUE__: globals.includes("__VUE__"),
      globals,
    });

    // Collect DOM fingerprints.
    const domHints = [];
    const selectors = [
      "[data-reactroot]",
      "[data-reactid]",
      "[data-v-app]",
      "[data-server-rendered='true']",
      "[ng-version]",
      "[_nghost]",
      "#__next",
      "#__nuxt",
      "[class*='svelte-']",
      ".container-fluid",
      ".btn.btn-primary",
    ];

    for (const selector of selectors) {
      try {
        if (document.querySelector(selector)) {
          domHints.push(selector);
        }
      } catch (_) {
        // Ignore unsupported selectors.
      }
    }

    // Cookie names only; do not collect cookie values.
    const cookies = [];

    try {
      cookies.push(
        ...document.cookie
          .split(";")
          .map((cookie) => cookie.trim().split("=")[0])
          .filter(Boolean),
      );
    } catch (_) {
      // Some cookies are inaccessible to page JavaScript.
    }

    // Build version hints without inventing missing versions.
    const versionHints = [];
    const seenVersions = new Set();

    function addVersion(name, version) {
      if (version === undefined || version === null) return;

      const value = String(version).trim();

      if (!value || value.length > 80) return;
      if (/^(undefined|null|unknown|false)$/i.test(value)) return;

      const key = name.toLowerCase();

      // Keep the first available hint for each technology.
      if (seenVersions.has(key)) return;

      seenVersions.add(key);
      versionHints.push({ name, version: value });
    }

    // Read versions exposed by runtime globals.
    // These properties may not be visible in every browser's
    // extension content-script environment.

    try {
      if (window.jQuery?.fn?.jquery) {
        addVersion("jQuery", window.jQuery.fn.jquery);
      }
    } catch (_) {}

    try {
      if (window.React?.version) {
        addVersion("React", window.React.version);
      }
    } catch (_) {}

    try {
      if (window.Vue?.version) {
        addVersion("Vue.js", window.Vue.version);
      }
    } catch (_) {}

    try {
      const version = document
        .querySelector("[ng-version]")
        ?.getAttribute("ng-version");

      if (version) addVersion("Angular", version);
    } catch (_) {}

    try {
      if (window.axios?.VERSION) {
        addVersion("Axios", window.axios.VERSION);
      }
    } catch (_) {}

    try {
      if (window.htmx?.version) {
        addVersion("HTMX", window.htmx.version);
      }
    } catch (_) {}

    try {
      if (window.d3?.version) {
        addVersion("D3.js", window.d3.version);
      }
    } catch (_) {}

    try {
      if (window.gsap?.version) {
        addVersion("GSAP", window.gsap.version);
      }
    } catch (_) {}

    try {
      if (window._?.VERSION) {
        addVersion("Lodash", window._.VERSION);
      }
    } catch (_) {}

    try {
      if (window.Backbone?.VERSION) {
        addVersion("Backbone", window.Backbone.VERSION);
      }
    } catch (_) {}

    try {
      if (window.Ember?.VERSION) {
        addVersion("Ember", window.Ember.VERSION);
      }
    } catch (_) {}

    try {
      if (window.Handlebars?.VERSION) {
        addVersion("Handlebars", window.Handlebars.VERSION);
      }
    } catch (_) {}

    try {
      if (window.Mustache?.version) {
        addVersion("Mustache", window.Mustache.version);
      }
    } catch (_) {}

    try {
      if (window.bootstrap?.Tooltip?.VERSION) {
        addVersion("Bootstrap", window.bootstrap.Tooltip.VERSION);
      } else if (window.jQuery?.fn?.tooltip?.Constructor?.VERSION) {
        addVersion("Bootstrap", window.jQuery.fn.tooltip.Constructor.VERSION);
      }
    } catch (_) {}

    // Read CMS versions from public generator metadata.
    try {
      const generator =
        document.querySelector('meta[name="generator"]')?.content || "";

      const match = generator.match(
        /\b(WordPress|Drupal|MediaWiki|Joomla|Ghost)\b[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i,
      );

      if (match) {
        const names = {
          wordpress: "WordPress",
          drupal: "Drupal",
          mediawiki: "MediaWiki",
          joomla: "Joomla",
          ghost: "Ghost",
        };

        addVersion(names[match[1].toLowerCase()], match[2]);
      }
    } catch (_) {}

    // Extract versions from recognizable package URLs.
    // Only match URLs that explicitly identify the technology and version.
    const versionPatterns = [
      ["jQuery", /jquery(?:[-/])([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?=[./?_-]|$)/i],
      [
        "React",
        /(?:react|react-dom)@([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?=[/?._-]|$)/i,
      ],
      ["Vue.js", /vue@([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?=[/?._-]|$)/i],
      ["Angular", /@angular\/core@([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?=[/?._-]|$)/i],
      ["Bootstrap", /bootstrap@([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?=[/?._-]|$)/i],
      [
        "Tailwind CSS",
        /tailwindcss@([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?=[/?._-]|$)/i,
      ],
      ["Axios", /axios@([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?=[/?._-]|$)/i],
      ["Lodash", /lodash@([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?=[/?._-]|$)/i],
      [
        "D3.js",
        /d3(?:-array|-selection|-scale)?@([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?=[/?._-]|$)/i,
      ],
      ["GSAP", /gsap@([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?=[/?._-]|$)/i],
      ["Next.js", /next@([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?=[/?._-]|$)/i],
      ["Nuxt", /nuxt@([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?=[/?._-]|$)/i],
      ["Svelte", /svelte@([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?=[/?._-]|$)/i],
      ["Alpine.js", /alpinejs@([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?=[/?._-]|$)/i],
      ["HTMX", /htmx\.org@([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?=[/?._-]|$)/i],
      [
        "Sentry",
        /(?:sentry(?:\.d|@)|browser\.sentry-cdn\.com\/|sentry\.javascript\.[^/?&\s]*%2F)([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i,
      ],
    ];

    const allUrls = [...scripts, ...styles, ...links, ...resources];

    // Extract versions from recognizable package URLs.
    for (const [name, pattern] of versionPatterns) {
      if (seenVersions.has(name.toLowerCase())) continue;

      for (const url of allUrls) {
        const match = url.match(pattern);

        if (match) {
          addVersion(name, match[1]);
          break;
        }
      }
    }

    // Use the runtime version only if URL/bundle detection found none.
    if (!seenVersions.has("sentry")) {
      try {
        const sentryVersion =
          window.__SENTRY__?.version ?? window.__SENTRY__?.hub?._version;

        if (sentryVersion != null) {
          addVersion("Sentry", sentryVersion);
        }
      } catch (_) {}
    }

    console.log(
      "[TechLens DEBUG] jQuery runtime version:",
      window.jQuery?.fn?.jquery ?? "not visible to content script",
    );
    console.log(
      "[TechLens] Sentry global available:",
      typeof window.__SENTRY__ !== "undefined",
    );

    return {
      url: location.href,
      title: document.title,
      hostname: location.hostname,
      scripts,
      styles,
      links,
      resources,
      meta,
      globals,
      domHints,
      cookies,
      versionHints,
      scannedAt: new Date().toISOString(),
    };
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type !== "TECHLENS_SCAN") return;

    collectPageEvidence()
      .then((page) => {
        console.log("[TechLens DEBUG] Scanned URL:", page.url);
        console.log(
          "[TechLens DEBUG] Scanned metadata:",
          page.meta.filter((item) =>
            /og:title|og:type|og:image|og:url/i.test(item),
          ),
        );
        sendResponse({ ok: true, page });
      })
      .catch((error) => {
        sendResponse({
          ok: false,
          error: String(error),
        });
      });

    return true;
  });
})();
