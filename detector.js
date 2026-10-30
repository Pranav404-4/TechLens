const RULES = [
  // Analytics
  {
    name: "Fathom Analytics",
    category: "Analytics",
    confidence: 95,
    tests: [["script", "cdn.usefathom.com/script.js"]],
  },
  {
    name: "Umami",
    category: "Analytics",
    confidence: 94,
    tests: [
      ["script", "cloud.umami.is/script.js"],
      ["script", "analytics.umami.is/script.js"],
    ],
  },
  {
    name: "Simple Analytics",
    category: "Analytics",
    confidence: 94,
    tests: [["script", "scripts.simpleanalyticscdn.com"]],
  },
  {
    name: "Pirsch Analytics",
    category: "Analytics",
    confidence: 93,
    tests: [["script", "api.pirsch.io"]],
  },
  {
    name: "Yandex Metrica",
    category: "Analytics",
    confidence: 94,
    tests: [
      ["script", "mc.yandex.ru/metrika"],
      ["script", "mc.yandex.ru/watch"],
    ],
  },
  {
    name: "Adobe Analytics",
    category: "Analytics",
    confidence: 88,
    tests: [
      ["script", "omtrdc.net"],
      ["script", "adobedtm.com"],
      ["script", "alloy.js"],
    ],
  },
  {
    name: "Amplitude",
    category: "Analytics",
    confidence: 90,
    tests: [
      ["script", "cdn.amplitude.com"],
      ["script", "amplitude.com/libs"],
    ],
  },
  {
    name: "Google Analytics",
    category: "Analytics",
    confidence: 95,
    tests: [
      ["script", "googletagmanager.com/gtag/js"],
      ["script", "google-analytics.com/analytics.js"],
      ["global", "gtag"],
    ],
  },
  {
    name: "PostHog",
    category: "Product Analytics",
    confidence: 95,
    tests: [
      ["script", "posthog"],
      ["script", "us.i.posthog.com"],
      ["resource", "us.i.posthog.com"],
      ["resource", "eu.i.posthog.com"],
    ],
  },
  {
    name: "Google Tag Manager",
    category: "Analytics",
    confidence: 96,
    tests: [
      ["script", "googletagmanager.com/gtm.js"],
      ["global", "google_tag_manager"],
    ],
  },
  {
    name: "Hotjar",
    category: "Analytics",
    confidence: 92,
    tests: [
      ["script", "static.hotjar.com"],
      ["script", "hotjar.com"],
    ],
  },
  {
    name: "Matomo",
    category: "Analytics",
    confidence: 93,
    tests: [
      ["script", "matomo.js"],
      ["script", "piwik.js"],
      ["global", "_paq"],
    ],
  },
  {
    name: "Microsoft Clarity",
    category: "Analytics",
    confidence: 92,
    tests: [
      ["script", "clarity.ms/tag/"],
      ["script", "clarity.ms"],
    ],
  },
  {
    name: "Mixpanel",
    category: "Analytics",
    confidence: 90,
    tests: [
      ["script", "cdn.mxpnl.com"],
      ["script", "mixpanel.com"],
    ],
  },
  {
    name: "Heap",
    category: "Product Analytics",
    confidence: 93,
    tests: [
      ["script", "heapanalytics.com"],
      ["script", "heap.io"],
      ["resource", "heapanalytics.com"],
    ],
  },
  {
    name: "Datadog RUM",
    category: "Application Performance Monitoring",
    confidence: 94,
    tests: [
      ["script", "datadoghq-browser-agent.com"],
      ["script", "datadog-rum"],
      ["resource", "browser-intake-datadoghq.com"],
      ["global", "DD_RUM"],
    ],
  },
  {
    name: "Statsig",
    category: "Analytics",
    confidence: 95,
    tests: [
      ["script", "statsig"],
      ["script", "cdn.jsdelivr.net/npm/@statsig/"],
      ["script", "statsig.com"],
      ["resource", "statsigapi.net"],
      ["resource", "statsig.com"],
    ],
  },
  {
    name: "Plausible",
    category: "Analytics",
    confidence: 95,
    tests: [
      ["script", "plausible.io/js/script"],
      ["script", "plausible.io/js/pa-"],
      ["resource", "plausible.io/api/event"],
      ["resource", "plausible.io/js/"],
    ],
  },
  {
    name: "New Relic",
    category: "Application Performance Monitoring",
    confidence: 95,
    tests: [
      ["script", "js-agent.newrelic.com"],
      ["script", "bam.nr-data.net"],
      ["resource", "bam.nr-data.net"],
    ],
  },
  {
    name: "Segment",
    category: "Analytics",
    confidence: 92,
    tests: [
      ["script", "cdn.segment.com/analytics.js"],
      ["script", "segment.io"],
    ],
  },

  // Backend frameworks and clues
  {
    name: "ASP.NET",
    category: "Backend clue",
    confidence: 90,
    tests: [
      ["header", "x-powered-by:asp.net"],
      ["cookie", "asp.net_sessionid"],
    ],
  },
  {
    name: "ASP.NET Core",
    category: "Backend framework",
    confidence: 85,
    tests: [
      ["cookie", ".aspnetcore."],
      ["header", "x-aspnet-version"],
    ],
  },
  {
    name: "Django",
    category: "Backend framework",
    confidence: 82,
    tests: [
      ["cookie", "csrftoken"],
      ["cookie", "django_language"],
    ],
  },
  {
    name: "Express / Node.js",
    category: "Backend clue",
    confidence: 75,
    tests: [["header", "x-powered-by:express"]],
  },
  {
    name: "Java / Spring",
    category: "Backend framework",
    confidence: 80,
    tests: [
      ["cookie", "jsessionid"],
      ["header", "x-application-context"],
    ],
  },
  {
    name: "Laravel",
    category: "Backend framework",
    confidence: 85,
    tests: [
      ["cookie", "laravel_session"],
      ["cookie", "xsrf-token"],
    ],
  },
  {
    name: "PHP",
    category: "Backend clue",
    confidence: 75,
    tests: [
      ["header", "x-powered-by:php"],
      ["cookie", "phpsessid"],
    ],
  },
  {
    name: "Ruby on Rails",
    category: "Backend framework",
    confidence: 88,
    tests: [
      ["cookie", "_session_id"],
      ["header", "x-runtime"],
    ],
  },

  // CMS and website builders

  {
    name: "Adobe Experience Manager",
    category: "CMS",
    confidence: 94,
    tests: [
      ["script", "/etc.clientlibs/"],
      ["link", "/etc.clientlibs/"],
      ["link", "/content/dam/"],
      ["meta", "generator:adobe experience manager"],
    ],
  },
  {
    name: "Contentful",
    category: "Headless CMS",
    confidence: 90,
    tests: [
      ["script", "cdn.contentful.com"],
      ["script", "images.ctfassets.net"],
    ],
  },
  {
    name: "Craft CMS",
    category: "CMS",
    confidence: 91,
    tests: [
      ["meta", "generator:craft cms"],
      ["script", "/cpresources/"],
      ["link", "/cpresources/"],
    ],
  },
  {
    name: "Sanity",
    category: "Headless CMS",
    confidence: 89,
    tests: [
      ["script", "cdn.sanity.io"],
      ["script", "sanity.io"],
    ],
  },
  {
    name: "TYPO3",
    category: "CMS",
    confidence: 92,
    tests: [
      ["meta", "generator:typo3"],
      ["script", "/typo3temp/"],
      ["link", "/typo3temp/"],
    ],
  },
  {
    name: "BigCommerce",
    category: "E-commerce",
    confidence: 94,
    tests: [
      ["script", "cdn11.bigcommerce.com"],
      ["script", "stencil-utils"],
      ["meta", "generator:bigcommerce"],
    ],
  },
  {
    name: "PrestaShop",
    category: "E-commerce",
    confidence: 92,
    tests: [
      ["meta", "generator:prestashop"],
      ["script", "prestashop"],
    ],
  },
  {
    name: "OpenCart",
    category: "E-commerce",
    confidence: 91,
    tests: [
      ["meta", "generator:opencart"],
      ["script", "catalog/view/javascript/"],
      ["link", "catalog/view/theme/"],
    ],
  },
  {
    name: "Drupal",
    category: "CMS",
    confidence: 95,
    tests: [
      ["meta", "generator:drupal"],
      ["script", "/sites/default/files/"],
      ["global", "Drupal"],
    ],
  },
  {
    name: "Ghost",
    category: "CMS",
    confidence: 90,
    tests: [
      ["meta", "generator:ghost"],
      ["script", "ghost.org"],
      ["link", "/ghost/"],
    ],
  },
  {
    name: "Joomla",
    category: "CMS",
    confidence: 92,
    tests: [
      ["meta", "generator:joomla"],
      ["script", "/media/system/js/"],
      ["link", "/media/system/"],
    ],
  },
  {
    name: "Magento",
    category: "E-commerce",
    confidence: 95,
    tests: [
      ["script", "/static/frontend/"],
      ["global", "Magento"],
    ],
  },
  {
    name: "MediaWiki",
    category: "CMS / Wiki",
    confidence: 92,
    tests: [
      ["meta", "generator:mediawiki"],
      ["script", "mediawiki."],
      ["link", "/w/load.php"],
    ],
  },
  {
    name: "Shopify",
    category: "E-commerce",
    confidence: 98,
    tests: [
      ["global", "Shopify"],
      ["script", "cdn.shopify.com"],
      ["meta", "shopify"],
    ],
  },
  {
    name: "Squarespace",
    category: "CMS / Website builder",
    confidence: 90,
    tests: [
      ["script", "static1.squarespace.com"],
      ["script", "squarespace-cdn.com"],
      ["meta", "generator:squarespace"],
    ],
  },
  {
    name: "Webflow",
    category: "CMS / Website builder",
    confidence: 90,
    tests: [
      ["script", "webflow.js"],
      ["css", "webflow.css"],
      ["meta", "generator:webflow"],
    ],
  },
  {
    name: "Wix",
    category: "CMS / Website builder",
    confidence: 90,
    tests: [
      ["script", "static.parastorage.com"],
      ["script", "wixstatic.com"],
      ["meta", "generator:wix"],
    ],
  },
  {
    name: "WordPress",
    category: "CMS",
    confidence: 98,
    tests: [
      ["meta", "generator:wordpress"],
      ["script", "/wp-content/"],
      ["link", "/wp-content/"],
      ["link", "/wp-includes/"],
    ],
  },

  // CSS frameworks

  {
    name: "Ant Design",
    category: "UI library",
    confidence: 92,
    tests: [
      ["css", "antd"],
      ["dom", ".ant-btn"],
      ["dom", ".ant-design"],
    ],
  },
  {
    name: "Bulma",
    category: "CSS framework",
    confidence: 90,
    minMatches: 2,
    tests: [
      ["css", "bulma"],
      ["dom", ".is-primary"],
      ["dom", ".navbar-burger"],
    ],
  },
  {
    name: "Chakra UI",
    category: "UI library",
    confidence: 90,
    tests: [
      ["css", "chakra"],
      ["dom", "chakra-provider"],
      ["dom", "data-chakra-component"],
    ],
  },
  {
    name: "DaisyUI",
    category: "CSS framework",
    confidence: 88,
    tests: [
      ["css", "daisyui"],
      ["dom", ".btn-primary"],
      ["dom", ".card-body"],
    ],
  },
  {
    name: "Foundation",
    category: "CSS framework",
    confidence: 90,
    tests: [
      ["css", "foundation"],
      ["dom", ".grid-container"],
      ["dom", ".callout"],
    ],
  },
  {
    name: "Mantine",
    category: "UI library",
    confidence: 92,
    tests: [
      ["css", "mantine"],
      ["dom", ".mantine-"],
      ["dom", "data-mantine-color-scheme"],
    ],
  },
  {
    name: "Material UI (MUI)",
    category: "UI library",
    confidence: 92,
    tests: [
      ["css", "material-ui"],
      ["css", "@mui"],
      ["dom", ".MuiButton-root"],
    ],
  },
  {
    name: "Materialize",
    category: "CSS framework",
    confidence: 90,
    tests: [
      ["css", "materialize"],
      ["dom", ".waves-effect"],
      ["dom", ".material-icons"],
    ],
  },
  {
    name: "PrimeVue",
    category: "UI library",
    confidence: 90,
    tests: [
      ["css", "primevue"],
      ["dom", ".p-component"],
      ["dom", ".p-button"],
    ],
  },
  {
    name: "Radix UI",
    category: "UI library",
    confidence: 88,
    tests: [
      ["css", "radix"],
      ["dom", "data-radix-collection-item"],
      ["dom", "data-radix-popper-content-wrapper"],
    ],
  },
  {
    name: "Semantic UI",
    category: "CSS framework",
    confidence: 90,
    tests: [
      ["css", "semantic-ui"],
      ["dom", ".ui.button"],
      ["dom", ".ui.menu"],
    ],
  },
  {
    name: "UnoCSS",
    category: "CSS framework",
    confidence: 88,
    tests: [
      ["css", "uno.css"],
      ["css", "unocss"],
      ["meta", "generator:unocss"],
    ],
  },
  {
    name: "Vuetify",
    category: "UI library",
    confidence: 92,
    tests: [
      ["css", "vuetify"],
      ["dom", ".v-btn"],
      ["dom", ".v-application"],
    ],
  },
  {
    name: "Bootstrap",
    category: "CSS framework",
    confidence: 92,
    tests: [
      ["css", "bootstrap"],
      ["dom", ".container-fluid"],
      ["dom", ".btn.btn-primary"],
    ],
  },
  {
    name: "Tailwind CSS",
    category: "CSS framework",
    confidence: 80,
    minMatches: 1,
    tests: [
      ["resource", "tailwindcss"],
      ["resource", "tailwind.css"],
      ["css", "tailwind"],
    ],
  },

  // Frontend frameworks

  {
    name: "Astro",
    category: "Frontend framework",
    confidence: 96,
    tests: [
      ["script", "/_astro/"],
      ["dom", "astro-island"],
    ],
  },
  {
    name: "Gatsby",
    category: "Frontend framework",
    confidence: 94,
    tests: [
      ["dom", "#___gatsby"],
      ["global", "__gatsby"],
      ["script", "gatsby"],
    ],
  },
  {
    name: "Lit",
    category: "Frontend framework",
    confidence: 90,
    tests: [
      ["script", "lit-html"],
      ["script", "@lit/"],
      ["global", "LitElement"],
    ],
  },
  {
    name: "Mithril",
    category: "Frontend framework",
    confidence: 90,
    tests: [["script", "mithril.js"]],
  },
  {
    name: "Preact",
    category: "Frontend framework",
    confidence: 92,
    tests: [
      ["script", "preact.min.js"],
      ["script", "preact.module.js"],
      ["global", "preact"],
    ],
  },
  {
    name: "Qwik",
    category: "Frontend framework",
    confidence: 96,
    tests: [
      ["script", "qwikloader"],
      ["dom", "q:container"],
    ],
  },
  {
    name: "Remix",
    category: "Frontend framework",
    confidence: 94,
    tests: [
      ["global", "__remixcontext"],
      ["script", "entry.client"],
    ],
  },
  {
    name: "SolidJS",
    category: "Frontend framework",
    confidence: 90,
    tests: [
      ["script", "solid-js"],
      ["dom", "[data-hk]"],
    ],
  },

  {
    name: "Angular",
    category: "Frontend framework",
    confidence: 97,
    tests: [
      ["global", "ng"],
      ["dom", "[ng-version]"],
      ["dom", "[_nghost]"],
      ["script", "angular."],
    ],
  },
  {
    name: "Next.js",
    category: "Frontend framework",
    confidence: 99,
    tests: [
      ["dom", "#__next"],
      ["script", "/_next/"],
      ["global", "__NEXT_DATA__"],
    ],
  },
  {
    name: "Nuxt",
    category: "Frontend framework",
    confidence: 98,
    tests: [
      ["dom", "#__nuxt"],
      ["script", "/_nuxt/"],
      ["global", "__NUXT__"],
    ],
  },
  {
    name: "React",
    category: "Frontend framework",
    confidence: 95,
    tests: [
      ["global", "__REACT_DEVTOOLS_GLOBAL_HOOK__"],
      ["global", "React"],
      ["global", "ReactDOM"],
      ["script", "react-dom"],
      ["script", "react.production"],
      ["resource", "react-dom"],
      ["resource", "react"],
      ["dom", "[data-reactroot]"],
      ["dom", "[data-reactid]"],
    ],
  },
  {
    name: "Svelte",
    category: "Frontend framework",
    confidence: 82,
    tests: [
      ["dom", "[class*='svelte-']"],
      ["script", "svelte"],
    ],
  },
  {
    name: "Vue.js",
    category: "Frontend framework",
    confidence: 95,
    tests: [
      ["global", "Vue"],
      ["global", "__VUE__"],
      ["global", "__VP_SITE_DATA__"],
      ["script", "vue.runtime"],
      ["resource", "vitepress"],
      ["dom", "[data-v-app]"],
      ["dom", "[data-server-rendered='true']"],
    ],
  },

  // Hosting, CDN and platforms
  {
    name: "AWS",
    category: "Hosting / Platform",
    confidence: 75,
    tests: [
      ["header", "x-amz-cf-id"],
      ["header", "x-amz-request-id"],
      ["header", "server:amazons3"],
    ],
  },
  {
    name: "Cloudflare",
    category: "CDN / Security",
    confidence: 90,
    tests: [
      ["header", "server:cloudflare"],
      ["header", "cf-ray"],
      ["cookie", "__cf_bm"],
    ],
  },
  {
    name: "Netlify",
    category: "Hosting / Platform",
    confidence: 90,
    tests: [
      ["header", "server:netlify"],
      ["header", "x-nf-request-id"],
    ],
  },
  {
    name: "Render",
    category: "Hosting / Platform",
    confidence: 85,
    tests: [
      ["header", "server:render"],
      ["header", "x-render-origin-server"],
    ],
  },
  {
    name: "Vercel",
    category: "Hosting / Platform",
    confidence: 90,
    tests: [
      ["header", "x-vercel-id"],
      ["header", "server:vercel"],
    ],
  },

  // JavaScript libraries
  {
    name: "Alpine.js",
    category: "JavaScript library",
    confidence: 90,
    tests: [
      ["script", "alpinejs"],
      ["script", "alpine.min.js"],
    ],
  },
  {
    name: "Axios",
    category: "JavaScript library",
    confidence: 88,
    tests: [
      ["script", "axios.min.js"],
      ["script", "axios.js"],
    ],
  },
  {
    name: "D3.js",
    category: "JavaScript library",
    confidence: 88,
    tests: [
      ["script", "d3.min.js"],
      ["script", "d3.v"],
    ],
  },
  {
    name: "GSAP",
    category: "JavaScript library",
    confidence: 90,
    tests: [
      ["script", "gsap.min.js"],
      ["script", "greensock.com"],
    ],
  },
  {
    name: "HTMX",
    category: "JavaScript library",
    confidence: 92,
    tests: [
      ["script", "htmx.org"],
      ["script", "htmx.min.js"],
    ],
  },
  {
    name: "jQuery",
    category: "JavaScript library",
    confidence: 96,
    tests: [
      ["global", "jQuery"],
      ["resource", "jquery"],
    ],
  },
  {
    name: "Lodash",
    category: "JavaScript library",
    confidence: 85,
    tests: [["script", "lodash"]],
  },
  {
    name: "Three.js",
    category: "JavaScript library",
    confidence: 90,
    tests: [
      ["script", "three.min.js"],
      ["script", "three.module.js"],
    ],
  },

  // Monitoring
  // Monitoring
  {
    name: "Sentry",
    category: "Monitoring",
    confidence: 90,
    tests: [
      ["script", "browser.sentry-cdn.com"],
      ["script", "sentry.io"],
      ["script", "/sentry."],
      ["global", "__SENTRY__"],
    ],
  },

  // Web servers, caches and proxies

  {
    name: "Microsoft IIS",
    category: "Web server",
    confidence: 92,
    tests: [["header", "server:microsoft-iis"]],
  },
  {
    name: "OpenResty",
    category: "Web server",
    confidence: 92,
    tests: [["header", "server:openresty"]],
  },
  {
    name: "Envoy",
    category: "Web server / Proxy",
    confidence: 90,
    tests: [["header", "server:envoy"]],
  },
  {
    name: "Gunicorn",
    category: "Application server",
    confidence: 90,
    tests: [["header", "server:gunicorn"]],
  },
  {
    name: "Uvicorn",
    category: "Application server",
    confidence: 90,
    tests: [["header", "server:uvicorn"]],
  },
  {
    name: "Kestrel",
    category: "Application server",
    confidence: 90,
    tests: [["header", "server:kestrel"]],
  },
  {
    name: "Apache HTTP Server",
    category: "Web server",
    confidence: 85,
    tests: [["header", "server:apache"]],
  },
  {
    name: "Apache Traffic Server",
    category: "Web server / Proxy",
    confidence: 95,
    tests: [["header", "server:ats"]],
  },
  {
    name: "Caddy",
    category: "Web server",
    confidence: 88,
    tests: [["header", "server:caddy"]],
  },
  {
    name: "LiteSpeed",
    category: "Web server",
    confidence: 88,
    tests: [["header", "server:litespeed"]],
  },
  {
    name: "Nginx",
    category: "Web server",
    confidence: 85,
    tests: [["header", "server:nginx"]],
  },
  {
    name: "Varnish",
    category: "Cache / Proxy",
    confidence: 85,
    tests: [
      ["header", "via:varnish"],
      ["header", "x-varnish"],
    ],
  },

  // Advertising and marketing pixels
  {
    name: "Meta Pixel",
    category: "Advertising",
    confidence: 97,
    tests: [
      ["script", "connect.facebook.net/en_us/fbevents.js"],
      ["global", "fbq"],
    ],
  },
  {
    name: "TikTok Pixel",
    category: "Advertising",
    confidence: 96,
    tests: [
      ["script", "analytics.tiktok.com/i18n/pixel/events.js"],
      ["script", "analytics.tiktok.com/i18n/pixel"],
    ],
  },
  {
    name: "LinkedIn Insight Tag",
    category: "Advertising",
    confidence: 96,
    tests: [["script", "snap.licdn.com/li.lms-analytics/insight.min.js"]],
  },
  {
    name: "Pinterest Tag",
    category: "Advertising",
    confidence: 95,
    tests: [["script", "s.pinimg.com/ct/core.js"]],
  },
  {
    name: "Snapchat Pixel",
    category: "Advertising",
    confidence: 95,
    tests: [["script", "sc-static.net/scevent.min.js"]],
  },
  {
    name: "Reddit Pixel",
    category: "Advertising",
    confidence: 94,
    tests: [["script", "alb.reddit.com/snoo.js"]],
  },
  {
    name: "Microsoft Advertising UET",
    category: "Advertising",
    confidence: 94,
    tests: [["script", "bat.bing.com/bat.js"]],
  },

  // Session replay and user behavior
  {
    name: "FullStory",
    category: "Session Replay",
    confidence: 95,
    tests: [
      ["script", "fullstory.com/s/fs.js"],
      ["script", "edge.fullstory.com/s/fs.js"],
    ],
  },
  {
    name: "LogRocket",
    category: "Session Replay",
    confidence: 95,
    tests: [
      ["script", "cdn.logrocket.io"],
      ["script", "cdn.lr-ingest.io"],
    ],
  },
  {
    name: "Smartlook",
    category: "Session Replay",
    confidence: 94,
    tests: [["script", "rec.smartlook.com/recorder.js"]],
  },
  {
    name: "Crazy Egg",
    category: "Session Replay",
    confidence: 93,
    tests: [["script", "script.crazyegg.com/pages/scripts/"]],
  },
  {
    name: "Inspectlet",
    category: "Session Replay",
    confidence: 93,
    tests: [["script", "cdn.inspectlet.com/inspectlet.js"]],
  },
  {
    name: "Lucky Orange",
    category: "Session Replay",
    confidence: 92,
    tests: [["script", "tools.luckyorange.com"]],
  },

  // Experimentation and feature flags
  {
    name: "Optimizely",
    category: "A/B Testing",
    confidence: 95,
    tests: [
      ["script", "cdn.optimizely.com/js/"],
      ["script", "logx.optimizely.com"],
    ],
  },
  {
    name: "VWO",
    category: "A/B Testing",
    confidence: 94,
    tests: [["script", "dev.visualwebsiteoptimizer.com"]],
  },
  {
    name: "AB Tasty",
    category: "A/B Testing",
    confidence: 94,
    tests: [["script", "try.abtasty.com"]],
  },
  {
    name: "LaunchDarkly",
    category: "Feature Management",
    confidence: 94,
    tests: [
      ["script", "app.launchdarkly.com/sdk"],
      ["script", "clientstream.launchdarkly.com"],
    ],
  },
  {
    name: "GrowthBook",
    category: "Feature Management",
    confidence: 93,
    tests: [["script", "cdn.growthbook.io"]],
  },

  // Consent management
  {
    name: "OneTrust",
    category: "Consent Management",
    confidence: 96,
    tests: [
      ["script", "cdn.cookielaw.org/consent/"],
      ["script", "optanonconsent"],
      ["resource", "cdn.cookielaw.org"],
      ["resource", "onetrust.com"],
    ],
  },
  {
    name: "Cookiebot",
    category: "Consent Management",
    confidence: 96,
    tests: [
      ["script", "consent.cookiebot.com/uc.js"],
      ["resource", "consent.cookiebot.com"],
      ["resource", "consent.cookiebot.eu"],
    ],
  },
  {
    name: "Usercentrics",
    category: "Consent Management",
    confidence: 95,
    tests: [
      ["script", "app.usercentrics.eu/browser-ui/"],
      ["script", "web.cmp.usercentrics.eu"],
    ],
  },
  {
    name: "iubenda",
    category: "Consent Management",
    confidence: 94,
    tests: [
      ["script", "cdn.iubenda.com/cs/iubenda_cs.js"],
      ["script", "embeds.iubenda.com"],
    ],
  },

  // Customer support and chat
  {
    name: "Intercom",
    category: "Customer Support",
    confidence: 96,
    tests: [
      ["script", "widget.intercom.io/widget/"],
      ["script", "js.intercomcdn.com"],
      ["resource", "widget.intercom.io"],
      ["global", "Intercom"],
    ],
  },
  {
    name: "Zendesk",
    category: "Customer Support",
    confidence: 95,
    tests: [
      ["script", "static.zdassets.com/ekr/snippet.js"],
      ["script", "ekr.zdassets.com"],
      ["resource", "static.zdassets.com"],
      ["resource", "zendesk.com/embeddable"],
    ],
  },
  {
    name: "Drift",
    category: "Customer Support",
    confidence: 94,
    tests: [["script", "js.driftt.com/include/"]],
  },
  {
    name: "Crisp",
    category: "Customer Support",
    confidence: 95,
    tests: [["script", "client.crisp.chat/l.js"]],
  },
  {
    name: "Tawk.to",
    category: "Customer Support",
    confidence: 95,
    tests: [["script", "embed.tawk.to"]],
  },
  {
    name: "HubSpot",
    category: "Marketing / CRM",
    confidence: 95,
    tests: [
      ["script", "js.hs-scripts.com/"],
      ["script", "js.hsforms.net/forms/embed/"],
    ],
  },

  // Payment providers
  {
    name: "Stripe",
    category: "Payments",
    confidence: 97,
    tests: [
      ["script", "js.stripe.com/v3/"],
      ["resource", "js.stripe.com"],
      ["global", "Stripe"],
    ],
  },
  {
    name: "PayPal",
    category: "Payments",
    confidence: 96,
    tests: [
      ["resource", "paypal.com/sdk/js"],
      ["global", "paypal"],
    ],
  },
  {
    name: "Adyen",
    category: "Payments",
    confidence: 95,
    tests: [
      ["script", "checkoutshopper-live.adyen.com"],
      ["script", "checkoutshopper-test.adyen.com"],
    ],
  },
  {
    name: "Braintree",
    category: "Payments",
    confidence: 95,
    tests: [["script", "js.braintreegateway.com"]],
  },
  {
    name: "Paddle",
    category: "Payments",
    confidence: 94,
    tests: [["script", "cdn.paddle.com/paddle/"]],
  },

  // Search
  {
    name: "Algolia",
    category: "Search",
    confidence: 95,
    tests: [
      ["script", "algolia.net/"],
      ["script", "algoliasearch"],
    ],
  },
  {
    name: "Typesense",
    category: "Search",
    confidence: 93,
    tests: [["script", "typesense"]],
  },

  // Performance monitoring
  {
    name: "Google Lighthouse",
    category: "Performance",
    tests: [
      ["script", "lighthouse"],
      ["global", "lighthouse"],
    ],
  },
  {
    name: "web-vitals",
    category: "Performance",
    tests: [
      ["script", "web-vitals"],
      ["global", "webVitals"],
    ],
  },
  {
    name: "SpeedCurve",
    category: "Performance",
    tests: [
      ["script", "speedcurve"],
      ["resource", "speedcurve.com"],
    ],
  },
  {
    name: "Calibre",
    category: "Performance",
    tests: [
      ["resource", "calibreapp.com"],
      ["script", "calibre"],
    ],
  },
  {
    name: "DebugBear",
    category: "Performance",
    tests: [
      ["resource", "debugbear.com"],
      ["script", "debugbear"],
    ],
  },
  {
    name: "Sentry Performance",
    category: "Performance",
    tests: [
      ["resource", "sentry.io"],
      ["resource", "sentry-cdn.com"],
      ["global", "Sentry"],
    ],
    minMatches: 2,
  },
  {
    name: "New Relic Browser",
    category: "Performance",
    tests: [
      ["resource", "js-agent.newrelic.com"],
      ["resource", "bam.nr-data.net"],
      ["global", "newrelic"],
    ],
  },
  {
    name: "Elastic APM",
    category: "Performance",
    tests: [
      ["resource", "elastic-apm"],
      ["resource", "rum-agent"],
      ["global", "elasticApm"],
    ],
  },
  {
    name: "AppDynamics",
    category: "Performance",
    tests: [
      ["resource", "adrum"],
      ["resource", "appdynamics"],
      ["global", "ADRUM"],
    ],
  },

  // Performance optimization
  {
    name: "Google PageSpeed Insights",
    category: "Performance",
    tests: [["resource", "pagespeed.web.dev"]],
  },
  {
    name: "Partytown",
    category: "Performance",
    tests: [
      ["resource", "partytown"],
      ["script", "partytown"],
    ],
  },
  {
    name: "Quicklink",
    category: "Performance",
    tests: [
      ["resource", "quicklink"],
      ["script", "quicklink"],
    ],
  },
  {
    name: "Instant.page",
    category: "Performance",
    tests: [
      ["resource", "instant.page"],
      ["script", "instantpage"],
    ],
  },
  {
    name: "Quicklink Prefetching",
    category: "Performance",
    tests: [["resource", "quicklink"]],
  },
  {
    name: "NitroPack",
    category: "Performance",
    tests: [
      ["resource", "nitrocdn.com"],
      ["resource", "nitropack.io"],
      ["dom", "nitro"],
    ],
  },
  {
    name: "WP Rocket",
    category: "Performance",
    tests: [
      ["resource", "wp-rocket"],
      ["resource", "cache/wp-rocket"],
    ],
  },
  {
    name: "LiteSpeed Cache",
    category: "Performance",
    tests: [
      ["header", "x-litespeed-cache"],
      ["resource", "litespeed-cache"],
    ],
  },
  {
    name: "Cloudflare Polish",
    category: "Performance",
    tests: [
      ["header", "cf-polished"],
      ["header", "cf-cache-status"],
    ],
    minMatches: 2,
  },
  {
    name: "Bunny Optimizer",
    category: "Performance",
    tests: [
      ["resource", "bunny.net"],
      ["resource", "b-cdn.net"],
    ],
    minMatches: 2,
  },
  {
    name: "ImageKit",
    category: "Performance",
    tests: [
      ["resource", "ik.imagekit.io"],
      ["resource", "imagekit.io"],
    ],
  },
  {
    name: "Cloudinary",
    category: "Performance",
    tests: [
      ["resource", "res.cloudinary.com"],
      ["resource", "cloudinary.com"],
    ],
  },
  {
    name: "Imgix",
    category: "Performance",
    tests: [["resource", "imgix.net"]],
  },
  {
    name: "Fastly Image Optimizer",
    category: "Performance",
    tests: [
      ["resource", "fastly"],
      ["header", "x-served-by"],
    ],
    minMatches: 2,
  },

  // JavaScript utility libraries
  {
    name: "Underscore.js",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "underscore"],
      ["global", "_"],
    ],
    minMatches: 2,
  },
  {
    name: "Moment.js",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "moment.min.js"],
      ["global", "moment"],
    ],
  },
  {
    name: "Day.js",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "dayjs"],
      ["global", "dayjs"],
    ],
  },
  {
    name: "date-fns",
    category: "JavaScript Libraries",
    tests: [["resource", "date-fns"]],
  },
  {
    name: "Luxon",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "luxon"],
      ["global", "luxon"],
    ],
  },
  {
    name: "Ramda",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "ramda"],
      ["global", "R"],
    ],
    minMatches: 2,
  },
  {
    name: "Immer",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "immer"],
      ["global", "immer"],
    ],
  },
  {
    name: "Immutable.js",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "immutable.min.js"],
      ["resource", "immutable.js"],
      ["resource", "immutable@"],
      ["global", "Immutable"],
    ],
  },
  {
    name: "RxJS",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "rxjs"],
      ["global", "rxjs"],
    ],
  },
  {
    name: "Lodash-es",
    category: "JavaScript Libraries",
    tests: [["resource", "lodash-es"]],
  },

  // Animation and graphics
  {
    name: "Anime.js",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "anime.min.js"],
      ["global", "anime"],
    ],
  },
  {
    name: "Motion",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "motion.dev"],
      ["resource", "framer-motion"],
    ],
  },
  {
    name: "Lottie",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "lottie"],
      ["global", "lottie"],
    ],
  },
  {
    name: "AOS",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "aos.js"],
      ["resource", "aos.css"],
      ["dom", "data-aos"],
    ],
  },
  {
    name: "ScrollReveal",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "scrollreveal"],
      ["global", "ScrollReveal"],
    ],
  },
  {
    name: "PixiJS",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "pixi.js"],
      ["global", "PIXI"],
    ],
  },
  {
    name: "Babylon.js",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "babylon.js"],
      ["global", "BABYLON"],
    ],
  },
  {
    name: "Chart.js",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "chart.js"],
      ["global", "Chart"],
    ],
  },
  {
    name: "Apache ECharts",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "echarts"],
      ["global", "echarts"],
    ],
  },
  {
    name: "Highcharts",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "highcharts"],
      ["global", "Highcharts"],
    ],
  },
  {
    name: "Plotly.js",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "plotly"],
      ["global", "Plotly"],
    ],
  },
  {
    name: "Visx",
    category: "JavaScript Libraries",
    tests: [["resource", "@visx/"]],
  },

  // Networking and APIs
  {
    name: "Ky",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "/ky/"],
      ["resource", "/ky.min."],
      ["resource", "ky@"],
      ["resource", "ky/distribution/"],
      ["global", "ky"],
    ],
  },
  {
    name: "SuperAgent",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "superagent"],
      ["global", "superagent"],
    ],
  },
  {
    name: "Socket.IO",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "socket.io"],
      ["global", "io"],
    ],
  },
  {
    name: "Pusher",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "pusher"],
      ["global", "Pusher"],
    ],
  },
  {
    name: "Apollo Client",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "@apollo/client"],
      ["resource", "apollo-client"],
    ],
  },
  {
    name: "urql",
    category: "JavaScript Libraries",
    tests: [["resource", "urql"]],
  },
  {
    name: "TanStack Query",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "@tanstack/query"],
      ["resource", "react-query"],
    ],
  },
  {
    name: "SWR",
    category: "JavaScript Libraries",
    tests: [["resource", "swr"]],
  },

  // State management
  {
    name: "Redux",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "redux"],
      ["global", "Redux"],
    ],
  },
  {
    name: "Zustand",
    category: "JavaScript Libraries",
    tests: [["resource", "zustand"]],
  },
  {
    name: "MobX",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "mobx"],
      ["global", "mobx"],
    ],
  },
  {
    name: "XState",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "xstate"],
      ["global", "XState"],
    ],
  },
  {
    name: "Jotai",
    category: "JavaScript Libraries",
    tests: [["resource", "jotai"]],
  },
  {
    name: "Recoil",
    category: "JavaScript Libraries",
    tests: [["resource", "recoil"]],
  },

  // Validation and forms
  {
    name: "Zod",
    category: "JavaScript Libraries",
    tests: [["resource", "zod"]],
  },
  {
    name: "Yup",
    category: "JavaScript Libraries",
    tests: [["resource", "yup"]],
  },
  {
    name: "AJV",
    category: "JavaScript Libraries",
    tests: [["resource", "ajv"]],
  },
  {
    name: "Formik",
    category: "JavaScript Libraries",
    tests: [["resource", "formik"]],
  },
  {
    name: "React Hook Form",
    category: "JavaScript Libraries",
    tests: [["resource", "react-hook-form"]],
  },

  // Developer tooling
  {
    name: "RequireJS",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "require.js"],
      ["global", "requirejs"],
    ],
  },
  {
    name: "SystemJS",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "system.js"],
      ["global", "System"],
    ],
  },
  {
    name: "core-js",
    category: "JavaScript Libraries",
    tests: [["resource", "core-js"]],
  },
  {
    name: "regenerator-runtime",
    category: "JavaScript Libraries",
    tests: [["resource", "regenerator-runtime"]],
  },
  {
    name: "Zone.js",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "zone.js"],
      ["global", "Zone"],
    ],
  },
  {
    name: "Prism.js",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "prism.js"],
      ["global", "Prism"],
    ],
  },
  {
    name: "Highlight.js",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "highlight.js"],
      ["global", "hljs"],
    ],
  },
  {
    name: "Marked",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "marked"],
      ["global", "marked"],
    ],
  },
  {
    name: "DOMPurify",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "dompurify"],
      ["global", "DOMPurify"],
    ],
  },

  // JavaScript Frameworks
  {
    name: "Polymer",
    category: "JavaScript Frameworks",
    tests: [
      ["resource", "polymer"],
      ["global", "Polymer"],
      ["dom", "polymer-element"],
    ],
    minMatches: 2,
  },

  // Video Players
  {
    name: "YouTube",
    category: "Video Players",
    tests: [
      ["resource", "youtube.com/embed/"],
      ["resource", "youtube-nocookie.com/embed/"],
      ["resource", "youtube.com/iframe_api"],
      ["dom", "youtube.com/embed/"],
      ["dom", "ytplayer"],
    ],
  },
  {
    name: "YouTube Player API",
    category: "Video Players",
    tests: [
      ["resource", "youtube.com/iframe_api"],
      ["global", "YT"],
    ],
    minMatches: 2,
  },

  // Miscellaneous

  {
    name: "Open Graph",
    category: "Miscellaneous",
    confidence: 95,
    tests: [
      ["meta", "og:title"],
      ["meta", "og:type"],
      ["meta", "og:image"],
      ["meta", "og:url"],
    ],
    minMatches: 2,
  },
  {
    name: "HTTP/3 Advertisement",
    category: "Miscellaneous",
    tests: [["header", "alt-svc"]],
  },

  // PWA

  {
    name: "Progressive Web App",
    category: "PWA",
    tests: [
      ["dom", "manifest"],
      ["dom", "serviceworker"],
      ["dom", "service-worker"],
    ],
    minMatches: 2,
  },
  {
    name: "Web App Manifest",
    category: "PWA",
    tests: [["link", "manifest"]],
  },

  // JavaScript Libraries

  {
    name: "Hammer.js",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "hammer.min.js"],
      ["resource", "hammer.js"],
      ["global", "Hammer"],
    ],
  },
  {
    name: "XRegExp",
    category: "JavaScript Libraries",
    tests: [
      ["resource", "xregexp"],
      ["global", "XRegExp"],
    ],
  },

  // Font Scripts

  {
    name: "Google Font API",
    category: "Font Scripts",
    tests: [
      ["resource", "fonts.googleapis.com"],
      ["resource", "fonts.gstatic.com"],
    ],
  },
  // Miscellaneous technologies
  {
    name: "Google reCAPTCHA",
    category: "Miscellaneous",
    confidence: 95,
    tests: [
      ["resource", "google.com/recaptcha/"],
      ["resource", "gstatic.com/recaptcha/"],
      ["dom", "g-recaptcha"],
    ],
  },
  {
    name: "hCaptcha",
    category: "Miscellaneous",
    confidence: 95,
    tests: [
      ["resource", "hcaptcha.com/"],
      ["dom", "h-captcha"],
    ],
  },
  {
    name: "Gravatar",
    category: "Miscellaneous",
    confidence: 85,
    tests: [["resource", "gravatar.com/avatar/"]],
  },
  {
    name: "ShareThis",
    category: "Miscellaneous",
    confidence: 90,
    tests: [
      ["resource", "platform-api.sharethis.com"],
      ["resource", "sharethis.com"],
    ],
  },
  {
    name: "HTTP/2",
    category: "Miscellaneous",
    confidence: 95,
    tests: [["protocol", "http/2"]],
  },
  {
    name: "HTTP/3",
    category: "Miscellaneous",
    confidence: 95,
    tests: [["protocol", "http/3"]],
  },
  {
    name: "RSS",
    category: "Miscellaneous",
    confidence: 90,
    tests: [["link", "application/rss+xml"]],
  },
  {
    name: "Popper",
    category: "Miscellaneous",
    confidence: 85,
    tests: [
      ["resource", "popper.min.js"],
      ["resource", "popper.js"],
    ],
  },
  {
    name: "Webpack",
    category: "Miscellaneous",
    confidence: 80,
    tests: [
      ["resource", "webpack"],
      ["global", "webpackChunk"],
    ],
  },
  {
    name: "Prism",
    category: "Miscellaneous",
    confidence: 90,
    tests: [
      ["resource", "prism.js"],
      ["global", "Prism"],
    ],
  },
  {
    name: "Vite",
    category: "Miscellaneous",
    confidence: 90,
    tests: [
      ["resource", "/@vite/client"],
      ["resource", "vite.svg"],
    ],
  },
  {
    name: "LottieFiles",
    category: "Miscellaneous",
    confidence: 90,
    tests: [
      ["resource", "lottie-player"],
      ["resource", "dotlottie-player"],
    ],
  },
];

function detect(input) {
  const { page = {}, headers = [] } = input || {};

  // Normalize page evidence for case-insensitive matching.
  const scripts = (page.scripts || []).map((item) =>
    String(item).toLowerCase(),
  );
  const styles = (page.styles || []).map((item) => String(item).toLowerCase());
  const metas = (page.meta || []).map((item) => String(item).toLowerCase());
  const links = (page.links || []).map((item) => String(item).toLowerCase());
  const resources = (page.resources || []).map((item) =>
    String(item).toLowerCase(),
  );
  const globals = (page.globals || []).map((item) =>
    String(item).toLowerCase(),
  );
  const dom = (page.domHints || []).map((item) => String(item).toLowerCase());
  const cookies = (page.cookies || []).map((item) =>
    String(item).toLowerCase(),
  );

  const normalizedHeaders = headers.map((header) => ({
    name: String(header.name || "").toLowerCase(),
    value: String(header.value || "").toLowerCase(),
  }));

  const found = [];

  // Find a response header by name.
  function getHeader(name) {
    return normalizedHeaders.find((header) => header.name === name);
  }

  // Extract a version only when the page or response exposes one.
  function getVersion(name) {
    const hints = page.versionHints || [];

    const hint = hints.find(
      (item) => item.name?.toLowerCase() === name.toLowerCase() && item.version,
    );

    if (hint) {
      return String(hint.version);
    }

    const server = getHeader("server")?.value || "";

    const serverPatterns = {
      Nginx: /\bnginx\/([0-9][\w.-]*)/i,
      "Apache HTTP Server": /\bApache\/([0-9][\w.-]*)/i,
      "Apache Traffic Server": /\bATS\/([0-9][\w.-]*)/i,
      LiteSpeed: /\bLiteSpeed\/([0-9][\w.-]*)/i,
      Caddy: /\bCaddy\/([0-9][\w.-]*)/i,
      "Microsoft IIS": /\bMicrosoft-IIS\/([0-9][\w.-]*)/i,
      OpenResty: /\bopenresty\/([0-9][\w.-]*)/i,
      Envoy: /\benvoy\/([0-9][\w.-]*)/i,
      Gunicorn: /\bgunicorn\/([0-9][\w.-]*)/i,
      Uvicorn: /\buvicorn\/([0-9][\w.-]*)/i,
      Kestrel: /\bKestrel\/([0-9][\w.-]*)/i,
    };

    const serverPattern = serverPatterns[name];

    if (serverPattern) {
      const match = server.match(serverPattern);
      if (match) return match[1];
    }

    if (name === "PHP") {
      const poweredBy = getHeader("x-powered-by")?.value || "";
      const match = poweredBy.match(/\bPHP\/([0-9][\w.-]*)/i);

      if (match) return match[1];
    }

    if (name === "ASP.NET") {
      const version = getHeader("x-aspnet-version")?.value;

      if (version && /^[0-9][\w.-]*$/.test(version)) {
        return version;
      }
    }

    return null;
  }

  // Some fingerprints are too generic to identify a technology alone.
  function hasReliableEvidence(ruleName, evidence) {
    const matched = evidence.map((item) => item.toLowerCase());

    if (ruleName === "Django") {
      return matched.some((item) => item.includes("django_language"));
    }

    if (ruleName === "Laravel") {
      return matched.some((item) => item.includes("laravel_session"));
    }

    if (ruleName === "Java / Spring") {
      return matched.some((item) => item.includes("x-application-context"));
    }

    if (ruleName === "Ruby on Rails") {
      return matched.some((item) => item.includes("_session_id"));
    }

    if (ruleName === "ASP.NET Core") {
      return matched.some((item) => item.includes(".aspnetcore."));
    }

    return true;
  }

  // Evaluate each technology fingerprint.
  for (const rule of RULES) {
    const evidence = [];

    for (const [kind, needle] of rule.tests) {
      const search = needle.toLowerCase();
      let match = false;

      switch (kind) {
        case "resource":
          match = resources.some((item) => item.includes(search));
          break;

        case "script":
          match =
            scripts.some((item) => item.includes(search)) ||
            resources.some((item) => item.includes(search));
          break;

        case "css":
          match =
            styles.some((item) => item.includes(search)) ||
            resources.some((item) => item.includes(search));
          break;

        case "meta":
          match = metas.some((item) => item.includes(search));
          break;

        case "link":
          match =
            links.some((item) => item.includes(search)) ||
            resources.some((item) => item.includes(search));
          break;

        case "global":
          // A generic "$" global is too ambiguous to prove jQuery.
          if (search === "$") break;

          match = globals.some(
            (item) => item === search || item.includes(search),
          );
          break;

        case "dom":
          match = dom.some((item) => item.includes(search));
          break;

        case "cookie":
          match = cookies.some((item) => item.includes(search));
          break;

        case "header":
          // Match headers only, never URLs or page resources.
          match = normalizedHeaders.some((header) =>
            `${header.name}:${header.value}`.includes(search),
          );
          break;

        case "protocol": {
          const nav = performance.getEntriesByType("navigation")[0];
          const protocol = nav?.nextHopProtocol?.toLowerCase() || "";

          match =
            search === "http/3"
              ? protocol.startsWith("h3")
              : search === "http/2"
                ? protocol === "h2"
                : false;
          break;
        }
      }

      if (match) {
        evidence.push(`${kind}: ${needle}`);
      }
    }

    const uniqueEvidence = [...new Set(evidence)];

    if (uniqueEvidence.length === 0) continue;

    // Some class names and asset fragments are common across unrelated sites.
    // Rules may require multiple independent clues; existing rules default to one.
    const minMatches = Number.isInteger(rule.minMatches) ? rule.minMatches : 1;
    if (uniqueEvidence.length < minMatches) continue;

    if (!hasReliableEvidence(rule.name, uniqueEvidence)) {
      continue;
    }

    // Use a safe baseline when a rule has no valid confidence value.
    const baseConfidence = Number.isFinite(rule.confidence)
      ? Math.max(0, Math.min(99, rule.confidence))
      : 70;

    const confidence = Math.min(
      99,
      baseConfidence + Math.min(4, (uniqueEvidence.length - 1) * 2),
    );

    found.push({
      ...rule,
      confidence,
      version: getVersion(rule.name),
      evidence: uniqueEvidence,
    });
  }

  return found.sort(
    (a, b) => b.confidence - a.confidence || a.name.localeCompare(b.name),
  );
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { detect, RULES };
} else {
  globalThis.TechLensDetector = { detect, RULES };
}
