const RULES = [
  // Analytics
  {
    id: "fathom-analytics",
    name: "Fathom Analytics",
    category: "Analytics",
    product: {
      vendor: "Fathom",
      name: "Fathom Analytics",
      cpe: null,
      cpeStatus: "unmapped",
      purl: null,
      aliases: [],
      versionScope: "unknown",
    },
    confidence: 95,
    signatures: [
      {
        type: "script",
        pattern: "cdn.usefathom.com/script.js",
        match: "contains",
        weight: 95,
      },
    ],
  },
  {
    id: "umami",
    name: "Umami",
    category: "Analytics",
    product: {
      vendor: "Umami",
      name: "Umami",
      cpe: null,
      cpeStatus: "unmapped",
      purl: null,
      aliases: [],
      versionScope: "unknown",
    },
    confidence: 94,
    signatures: [
      {
        type: "script",
        pattern: "cloud.umami.is/script.js",
        match: "contains",
        weight: 95,
      },
      {
        type: "script",
        pattern: "analytics.umami.is/script.js",
        match: "contains",
        weight: 95,
      },
    ],
  },
  {
    id: "simple-analytics",
    name: "Simple Analytics",
    category: "Analytics",
    product: {
      vendor: "Simple Analytics",
      name: "Simple Analytics",
      cpe: null,
      cpeStatus: "unmapped",
      purl: null,
      aliases: [],
      versionScope: "unknown",
    },
    confidence: 94,
    signatures: [
      {
        type: "script",
        pattern: "scripts.simpleanalyticscdn.com",
        match: "contains",
        weight: 95,
      },
    ],
  },
  {
    id: "pirsch-analytics",
    name: "Pirsch Analytics",
    category: "Analytics",
    product: {
      vendor: "Pirsch",
      name: "Pirsch Analytics",
      cpe: null,
      cpeStatus: "unmapped",
      purl: null,
      aliases: [],
      versionScope: "unknown",
    },
    confidence: 95,
    signatures: [
      {
        type: "script",
        pattern: "api.pirsch.io/pa.js",
        match: "contains",
        weight: 95,
      },
    ],
  },
  {
    id: "yandex-metrica",
    name: "Yandex Metrica",
    category: "Analytics",
    product: {
      vendor: "Yandex",
      name: "Yandex Metrica",
      cpe: null,
      cpeStatus: "unmapped",
      purl: null,
      aliases: [],
      versionScope: "unknown",
    },
    confidence: 95,
    signatures: [
      {
        type: "script",
        pattern: "mc.yandex.ru/metrika/tag.js",
        match: "contains",
        weight: 95,
      },
      {
        type: "script",
        pattern: "mc.yandex.com/metrika/tag.js",
        match: "contains",
        weight: 95,
      },
    ],
  },
  {
    id: "adobe-analytics",
    name: "Adobe Analytics",
    category: "Analytics",
    product: {
      vendor: "Adobe",
      name: "Adobe Analytics",
      cpe: null,
      cpeStatus: "unmapped",
      purl: null,
      aliases: [],
      versionScope: "unknown",
    },
    confidence: 95,
    signatures: [
      {
        type: "script",
        pattern: "AppMeasurement.js",
        match: "contains",
        weight: 95,
      },
      {
        type: "global",
        pattern: "s_gi",
        match: "equals",
        weight: 95,
      },
    ],
  },
  {
    id: "amplitude",
    name: "Amplitude",
    category: "Analytics",
    product: {
      vendor: "Amplitude",
      name: "Amplitude Analytics",
      cpe: null,
      cpeStatus: "unmapped",
      purl: null,
      aliases: [],
      versionScope: "unknown",
    },
    confidence: 95,
    signatures: [
      {
        type: "script",
        pattern: "cdn.amplitude.com/libs/amplitude-",
        match: "contains",
        weight: 95,
      },
      {
        type: "script",
        pattern: "cdn.amplitude.com/script/",
        match: "contains",
        weight: 95,
      },
    ],
  },
  {
    id: "google-analytics",
    name: "Google Analytics",
    category: "Analytics",
    product: {
      vendor: "Google",
      name: "Google Analytics",
      cpe: null,
      cpeStatus: "unmapped",
      purl: null,
      aliases: [],
      versionScope: "unknown",
    },
    confidence: 95,
    signatures: [
      {
        type: "script",
        pattern: "googletagmanager.com/gtag/js",
        match: "contains",
        weight: 95,
      },
      {
        type: "script",
        pattern: "google-analytics.com/analytics.js",
        match: "contains",
        weight: 95,
      },
      {
        type: "script",
        pattern: "google-analytics.com/ga.js",
        match: "contains",
        weight: 95,
      },
    ],
  },
  {
    id: "posthog",
    name: "PostHog",
    category: "Product Analytics",
    product: {
      vendor: "PostHog",
      name: "PostHog",
      cpe: null,
      cpeStatus: "unmapped",
      purl: "pkg:npm/posthog-js",
      aliases: [],
      versionScope: "client",
    },
    confidence: 95,
    signatures: [
      {
        type: "global",
        pattern: "posthog",
        match: "equals",
        weight: 95,
      },
      {
        type: "script",
        pattern: "-assets.i.posthog.com/static/array.js",
        match: "contains",
        weight: 95,
      },
      {
        type: "resource",
        pattern: "us.i.posthog.com",
        match: "contains",
        weight: 90,
      },
      {
        type: "resource",
        pattern: "eu.i.posthog.com",
        match: "contains",
        weight: 90,
      },
    ],
  },
  {
    id: "google-tag-manager",
    name: "Google Tag Manager",
    category: "Tag Management",
    product: {
      vendor: "Google",
      name: "Google Tag Manager",
      cpe: null,
      cpeStatus: "unmapped",
      purl: null,
      aliases: [],
      versionScope: "unknown",
    },
    confidence: 97,
    signatures: [
      {
        type: "script",
        pattern: "googletagmanager.com/gtm.js",
        match: "contains",
        weight: 98,
      },
      {
        type: "global",
        pattern: "google_tag_manager",
        match: "equals",
        weight: 95,
      },
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
    id: "django",
    category: "Backend framework",
    product: {
      vendor: "djangoproject",
      name: "django",
      cpe: "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: "pkg:pypi/django",
      aliases: [],
      versionScope: "server",
    },
    confidence: 82,
    tests: [
      ["cookie", "csrftoken"],
      ["cookie", "django_language"],
    ],
  },
  {
    name: "Flask",
    id: "flask",
    category: "Backend framework",
    product: {
      vendor: "palletsprojects",
      name: "flask",
      cpe: "cpe:2.3:a:palletsprojects:flask:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: "pkg:pypi/flask",
      aliases: [],
      versionScope: "server",
    },
    confidence: 65,
    tests: [],
  },
  {
    name: "Node.js",
    id: "nodejs",
    category: "Backend clue",
    product: {
      vendor: "nodejs",
      name: "node.js",
      cpe: "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: null,
      aliases: [],
      versionScope: "server",
    },
    confidence: 60,
    tests: [
      ["header", "x-powered-by:node.js"],
      ["header", "x-powered-by:node"],
      ["header", "server:node.js"],
    ],
  },
  {
    name: "Redis",
    id: "redis",
    category: "Backend clue",
    product: {
      vendor: "redis",
      name: "redis",
      cpe: "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: "pkg:docker/redis",
      aliases: [],
      versionScope: "server",
    },
    confidence: 95,
    tests: [],
  },
  {
    name: "Memcached",
    id: "memcached",
    category: "Backend clue",
    product: {
      vendor: "memcached",
      name: "memcached",
      cpe: "cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: "pkg:docker/memcached",
      aliases: [],
      versionScope: "server",
    },
    confidence: 95,
    tests: [],
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
    id: "laravel",
    category: "Backend framework",
    product: {
      vendor: "laravel",
      name: "framework",
      cpe: "cpe:2.3:a:laravel:framework:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: "pkg:composer/laravel/framework",
      aliases: [],
      versionScope: "server",
    },
    confidence: 85,
    tests: [
      ["cookie", "laravel_session"],
      ["cookie", "xsrf-token"],
    ],
  },
  {
    name: "Symfony",
    id: "symfony",
    category: "Backend framework",
    product: {
      vendor: "sensiolabs",
      name: "symfony",
      cpe: "cpe:2.3:a:sensiolabs:symfony:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: "pkg:composer/symfony/symfony",
      aliases: [],
      versionScope: "server",
    },
    confidence: 95,
    signatures: [
      {
        type: "header",
        pattern: "x-debug-token",
        match: "contains",
        weight: 95,
      },
      {
        type: "header",
        pattern: "x-debug-token-link",
        match: "contains",
        weight: 95,
      },
    ],
  },
  {
    name: "Express.js",
    id: "express",
    category: "Backend framework",
    product: {
      vendor: "openjsf",
      name: "express",
      cpe: "cpe:2.3:a:openjsf:express:*:*:*:*:*:node.js:*:*",
      cpeStatus: "verified",
      purl: "pkg:npm/express",
      aliases: [],
      versionScope: "server",
    },
    confidence: 90,
    signatures: [
      {
        type: "header",
        pattern: "x-powered-by:express",
        match: "contains",
        weight: 90,
      },
    ],
  },
  {
    name: "PHP",
    id: "php",
    category: "Backend clue",
    product: {
      vendor: "php",
      name: "php",
      cpe: "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: null,
      aliases: [],
      versionScope: "server",
    },
    confidence: 75,
    tests: [
      ["header", "x-powered-by:php"],
      ["cookie", "phpsessid"],
    ],
  },
  {
    name: "CodeIgniter",
    id: "codeigniter",
    category: "Backend framework",
    product: {
      vendor: "codeigniter",
      name: "codeigniter",
      cpe: "cpe:2.3:a:codeigniter:codeigniter:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: null,
      aliases: [],
      versionScope: "server",
    },
    confidence: 75,
    tests: [["cookie", "ci_session"]],
  },
  {
    name: "CakePHP",
    id: "cakephp",
    category: "Backend framework",
    product: {
      vendor: "cakephp",
      name: "cakephp",
      cpe: "cpe:2.3:a:cakephp:cakephp:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: "pkg:composer/cakephp/cakephp",
      aliases: [],
      versionScope: "server",
    },
    confidence: 75,
    tests: [["cookie", "CAKEPHP"]],
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
    id: "drupal",
    category: "CMS",
    product: {
      vendor: "drupal",
      name: "drupal",
      cpe: "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: null,
      aliases: [],
      versionScope: "server",
    },
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
    id: "joomla",
    category: "CMS",
    product: {
      vendor: "joomla",
      name: "joomla!",
      cpe: "cpe:2.3:a:joomla:joomla\\!:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: null,
      aliases: [],
      versionScope: "server",
    },
    confidence: 92,
    tests: [
      ["meta", "generator:joomla"],
      ["script", "/media/system/js/"],
      ["link", "/media/system/"],
    ],
  },
  {
    name: "Magento",
    id: "magento",
    category: "E-commerce",
    product: {
      vendor: "adobe",
      name: "magento",
      cpe: null,
      cpeStatus: "unmapped",
      purl: null,
      aliases: [],
      versionScope: "server",
    },
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
    id: "wordpress",
    category: "CMS",
    product: {
      vendor: "wordpress",
      name: "wordpress",
      cpe: "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: null,
      aliases: [],
      versionScope: "server",
    },
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
    id: "bootstrap",
    category: "CSS framework",
    product: {
      vendor: "getbootstrap",
      name: "bootstrap",
      cpe: "cpe:2.3:a:getbootstrap:bootstrap:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: "pkg:npm/bootstrap",
      aliases: [],
      versionScope: "client",
    },
    confidence: 92,
    minMatches: 2,
    tests: [
      ["css", "bootstrap"],
      ["dom", ".container-fluid"],
      ["dom", ".btn.btn-primary"],
    ],
  },
  {
    name: "Tailwind CSS",
    id: "tailwindcss",
    category: "CSS framework",
    product: {
      vendor: "tailwindlabs",
      name: "tailwindcss",
      cpe: null,
      cpeStatus: "unmapped",
      purl: "pkg:npm/tailwindcss",
      aliases: [],
      versionScope: "unknown",
    },
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
    id: "nextjs",
    category: "Frontend framework",
    product: {
      vendor: "vercel",
      name: "next.js",
      cpe: "cpe:2.3:a:vercel:next.js:*:*:*:*:*:node.js:*:*",
      cpeStatus: "verified",
      purl: "pkg:npm/next",
      aliases: [],
      versionScope: "server",
    },
    confidence: 99,
    tests: [
      ["dom", "#__next"],
      ["script", "/_next/"],
      ["global", "__NEXT_DATA__"],
    ],
  },
  {
    name: "Nuxt",
    id: "nuxt",
    category: "Frontend framework",
    product: {
      vendor: "nuxt",
      name: "nuxt",
      cpe: "cpe:2.3:a:nuxt:nuxt:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: "pkg:npm/nuxt",
      aliases: [],
      versionScope: "unknown",
    },
    confidence: 98,
    tests: [
      ["dom", "#__nuxt"],
      ["script", "/_nuxt/"],
      ["global", "__NUXT__"],
    ],
  },
  {
    name: "NestJS",
    id: "nestjs",
    category: "Backend framework",
    product: {
      vendor: "nestjs",
      name: "nestjs",
      cpe: "cpe:2.3:a:nestjs:nest:*:*:*:*:*:node.js:*:*",
      cpeStatus: "verified",
      purl: "pkg:npm/%40nestjs/core",
      aliases: [],
      versionScope: "server",
    },
    confidence: 90,
    signatures: [
      {
        type: "resource",
        pattern: "@nestjs/core",
        match: "contains",
        weight: 90,
      },
    ],
  },
  {
    name: "React",
    id: "react",
    category: "Frontend framework",
    product: {
      vendor: "facebook",
      name: "react",
      cpe: "cpe:2.3:a:facebook:react:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: "pkg:npm/react",
      aliases: [],
      versionScope: "client",
    },
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
    id: "vue",
    category: "Frontend framework",
    product: {
      vendor: "vuejs",
      name: "vue",
      cpe: "cpe:2.3:a:vuejs:vue:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: "pkg:npm/vue",
      aliases: [],
      versionScope: "client",
    },
    confidence: 95,
    tests: [
      ["global", "Vue"],
      ["global", "__VUE__"],
      ["global", "__VP_SITE_DATA__"],
      ["script", "vue.runtime"],
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
    id: "cloudflare",
    category: "CDN / Security",
    product: {
      vendor: "cloudflare",
      name: "cloudflare",
      cpe: null,
      cpeStatus: "unmapped",
      purl: null,
      aliases: [],
      versionScope: "unknown",
    },
    confidence: 90,
    signatures: [
      {
        type: "header",
        pattern: "server:cloudflare",
        match: "contains",
        weight: 90,
      },
      {
        type: "header",
        pattern: "cf-ray",
        match: "contains",
        weight: 98,
      },
      {
        type: "cookie",
        pattern: "__cf_bm",
        match: "contains",
        weight: 90,
      },
    ],
  },
  {
    id: "netlify",
    name: "Netlify",
    category: "Hosting / Platform",
    product: {
      vendor: "Netlify",
      name: "Netlify",
      cpe: null,
      cpeStatus: "unmapped",
      purl: null,
      aliases: [],
      versionScope: "unknown",
    },
    confidence: 95,
    signatures: [
      {
        type: "header",
        pattern: "x-nf-request-id",
        match: "contains",
        weight: 98,
      },
      {
        type: "header",
        pattern: "server:netlify",
        match: "contains",
        weight: 85,
      },
    ],
  },
  {
    id: "render",
    name: "Render",
    category: "Hosting / Platform",
    product: {
      vendor: "Render",
      name: "Render",
      cpe: null,
      cpeStatus: "unmapped",
      purl: null,
      aliases: [],
      versionScope: "unknown",
    },
    confidence: 95,
    signatures: [
      {
        type: "header",
        pattern: "x-render-origin-server:render",
        match: "contains",
        weight: 98,
      },
    ],
  },
  {
    id: "vercel",
    name: "Vercel",
    category: "Hosting / Platform",
    product: {
      vendor: "Vercel",
      name: "Vercel",
      cpe: null,
      cpeStatus: "unmapped",
      purl: null,
      aliases: [],
      versionScope: "unknown",
    },
    confidence: 95,
    signatures: [
      {
        type: "header",
        pattern: "x-vercel-id",
        match: "contains",
        weight: 98,
      },
      {
        type: "header",
        pattern: "server:vercel",
        match: "contains",
        weight: 90,
      },
    ],
  },

  // JavaScript libraries
  {
    id: "alpine-js",
    name: "Alpine.js",
    category: "JavaScript library",
    product: {
      vendor: "Alpine.js",
      name: "Alpine.js",
      cpe: null,
      cpeStatus: "unmapped",
      purl: "pkg:npm/alpinejs",
      aliases: [],
      versionScope: "client",
    },
    confidence: 95,
    signatures: [
      {
        type: "script",
        pattern: "dist/cdn.min.js",
        match: "contains",
        weight: 98,
      },
      {
        type: "script",
        pattern: "unpkg.com/alpinejs",
        match: "contains",
        weight: 95,
      },
      {
        type: "global",
        pattern: "Alpine",
        match: "equals",
        weight: 95,
      },
    ],
  },
  {
    id: "axios",
    name: "Axios",
    category: "JavaScript library",
    product: {
      vendor: "Axios",
      name: "Axios",
      cpe: null,
      cpeStatus: "unmapped",
      purl: "pkg:npm/axios",
      aliases: [],
      versionScope: "client",
    },
    confidence: 95,
    signatures: [
      {
        type: "script",
        pattern: "axios/dist/axios.min.js",
        match: "contains",
        weight: 98,
      },
      {
        type: "script",
        pattern: "axios/dist/axios.js",
        match: "contains",
        weight: 95,
      },
      {
        type: "global",
        pattern: "axios",
        match: "equals",
        weight: 95,
      },
    ],
  },
  {
    id: "d3",
    name: "D3.js",
    category: "JavaScript library",
    product: {
      vendor: "D3",
      name: "D3",
      cpe: null,
      cpeStatus: "unmapped",
      purl: "pkg:npm/d3",
      aliases: [],
      versionScope: "client",
    },
    confidence: 95,
    signatures: [
      {
        type: "script",
        pattern: "d3.min.js",
        match: "contains",
        weight: 98,
      },
      {
        type: "script",
        pattern: "d3.v",
        match: "contains",
        weight: 95,
      },
    ],
  },
  {
    id: "gsap",
    name: "GSAP",
    category: "JavaScript library",
    product: {
      vendor: "GreenSock",
      name: "GSAP",
      cpe: null,
      cpeStatus: "unmapped",
      purl: "pkg:npm/gsap",
      aliases: ["GreenSock Animation Platform"],
      versionScope: "client",
    },
    confidence: 95,
    signatures: [
      {
        type: "script",
        pattern: "gsap.min.js",
        match: "contains",
        weight: 98,
      },
      {
        type: "global",
        pattern: "gsap",
        match: "equals",
        weight: 95,
      },
    ],
  },
  {
    id: "htmx",
    name: "HTMX",
    category: "JavaScript library",
    product: {
      vendor: "Big Sky Software",
      name: "htmx",
      cpe: null,
      cpeStatus: "unmapped",
      purl: "pkg:npm/htmx.org",
      aliases: [],
      versionScope: "client",
    },
    confidence: 95,
    signatures: [
      {
        type: "script",
        pattern: "htmx.min.js",
        match: "contains",
        weight: 98,
      },
      {
        type: "script",
        pattern: "htmx.js",
        match: "contains",
        weight: 95,
      },
      {
        type: "global",
        pattern: "htmx",
        match: "equals",
        weight: 95,
      },
    ],
  },
  {
    id: "jquery",
    name: "jQuery",
    category: "JavaScript library",
    product: {
      vendor: "OpenJS Foundation",
      name: "jQuery",
      cpe: "cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: "pkg:npm/jquery",
      aliases: [],
      versionScope: "client",
    },
    confidence: 96,
    signatures: [
      {
        type: "global",
        pattern: "jQuery",
        match: "equals",
        weight: 98,
      },
      {
        type: "resource",
        pattern: "code.jquery.com/jquery-",
        match: "contains",
        weight: 95,
      },
      {
        type: "resource",
        pattern: "jquery.min.js",
        match: "contains",
        weight: 95,
      },
      {
        type: "resource",
        pattern: "jquery.js",
        match: "contains",
        weight: 95,
      },
    ],
  },
  {
    id: "lodash",
    name: "Lodash",
    category: "JavaScript library",
    product: {
      vendor: "OpenJS Foundation",
      name: "Lodash",
      cpe: "cpe:2.3:a:lodash:lodash:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: "pkg:npm/lodash",
      aliases: [],
      versionScope: "client",
    },
    confidence: 95,
    signatures: [
      {
        type: "global",
        pattern: "_",
        match: "equals",
        weight: 95,
      },
      {
        type: "script",
        pattern: "lodash.min.js",
        match: "contains",
        weight: 98,
      },
      {
        type: "script",
        pattern: "lodash.js",
        match: "contains",
        weight: 95,
      },
    ],
  },
  {
    id: "three-js",
    name: "Three.js",
    category: "JavaScript library",
    product: {
      vendor: "Three.js",
      name: "Three.js",
      cpe: null,
      cpeStatus: "unmapped",
      purl: "pkg:npm/three",
      aliases: [],
      versionScope: "client",
    },
    confidence: 95,
    signatures: [
      {
        type: "script",
        pattern: "three.module.js",
        match: "contains",
        weight: 98,
      },
      {
        type: "script",
        pattern: "three.min.js",
        match: "contains",
        weight: 95,
      },
    ],
  },

  // Monitoring
  {
    id: "sentry",
    name: "Sentry",
    category: "Monitoring",
    product: {
      vendor: "Sentry",
      name: "Sentry JavaScript SDK",
      cpe: null,
      cpeStatus: "unmapped",
      purl: "pkg:npm/%40sentry/browser",
      aliases: [],
      versionScope: "client",
    },
    confidence: 95,
    signatures: [
      {
        type: "script",
        pattern: "browser.sentry-cdn.com",
        match: "contains",
        weight: 98,
      },
      {
        type: "global",
        pattern: "Sentry",
        match: "equals",
        weight: 95,
      },
      {
        type: "global",
        pattern: "__SENTRY__",
        match: "equals",
        weight: 95,
      },
    ],
  },
  {
    name: "Grafana",
    id: "grafana",
    category: "Monitoring",
    product: {
      vendor: "grafana",
      name: "grafana",
      cpe: "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: null,
      aliases: [],
      versionScope: "server",
    },
    confidence: 95,
    signatures: [
      {
        type: "global",
        pattern: "grafanaBootData",
        match: "equals",
        weight: 98,
      },
    ],
  },

  // Web servers, caches and proxies

  {
    id: "microsoft-iis",
    name: "Microsoft IIS",
    category: "Web server",
    product: {
      vendor: "microsoft",
      name: "internet_information_services",
      cpe: "cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: null,
      aliases: ["IIS", "Internet Information Services"],
      versionScope: "server",
    },
    confidence: 95,
    signatures: [
      {
        type: "header",
        pattern: "server:microsoft-iis",
        match: "contains",
        weight: 98,
      },
    ],
  },

  {
    id: "openresty",
    name: "OpenResty",
    category: "Web server",
    product: {
      vendor: "openresty",
      name: "openresty",
      cpe: "cpe:2.3:a:openresty:openresty:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: "pkg:generic/openresty",
      aliases: [],
      versionScope: "server",
    },
    confidence: 95,
    signatures: [
      {
        type: "header",
        pattern: "server:openresty",
        match: "contains",
        weight: 98,
      },
    ],
  },
  {
    id: "envoy",
    name: "Envoy",
    category: "Web server / Proxy",
    product: {
      vendor: "envoyproxy",
      name: "envoy",
      cpe: "cpe:2.3:a:envoyproxy:envoy:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: "pkg:generic/envoy",
      aliases: [],
      versionScope: "server",
    },
    confidence: 95,
    signatures: [
      {
        type: "header",
        pattern: "server:envoy",
        match: "contains",
        weight: 98,
      },
    ],
  },

  {
    id: "gunicorn",
    name: "Gunicorn",
    category: "Application server",
    product: {
      vendor: "gunicorn",
      name: "gunicorn",
      cpe: "cpe:2.3:a:gunicorn:gunicorn:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: "pkg:pypi/gunicorn",
      aliases: [],
      versionScope: "server",
    },
    confidence: 95,
    signatures: [
      {
        type: "header",
        pattern: "server:gunicorn",
        match: "contains",
        weight: 98,
      },
    ],
  },

  {
    name: "Uvicorn",
    id: "uvicorn",
    category: "Application server",
    confidence: 90,
    product: {
      vendor: "encode",
      name: "uvicorn",
      cpe: "cpe:2.3:a:encode:uvicorn:*:*:*:*:*:*:*:*",
      cpeStatus: "unmapped",
      purl: "pkg:pypi/uvicorn",
      aliases: [],
      versionScope: "server",
    },
    tests: [["header", "server:uvicorn"]],
  },
  {
    name: "Kestrel",
    id: "kestrel",
    category: "Application server",
    confidence: 90,
    product: {
      vendor: "microsoft",
      name: "kestrel",
      cpe: null,
      cpeStatus: "unmapped",
      purl: "pkg:nuget/microsoft.aspnetcore.server.kestrel",
      aliases: [],
      versionScope: "server",
    },
    tests: [["header", "server:kestrel"]],
  },
  {
    name: "Apache Tomcat",
    id: "apache-tomcat",
    category: "Application server",
    product: {
      vendor: "apache",
      name: "tomcat",
      cpe: "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: null,
      aliases: [],
      versionScope: "server",
    },
    confidence: 90,
    tests: [["header", "server:apache-coyote"]],
  },
  {
    name: "Apache HTTP Server",
    id: "apache-http-server",
    category: "Web server",
    product: {
      vendor: "apache",
      name: "http_server",
      cpe: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: null,
      aliases: [],
      versionScope: "server",
    },
    confidence: 85,
    tests: [["header", "server:apache"]],
  },
  {
    name: "Apache Traffic Server",
    id: "apache-traffic-server",
    category: "Web server / Proxy",
    confidence: 95,
    product: {
      vendor: "apache",
      name: "traffic_server",
      cpe: "cpe:2.3:a:apache:traffic_server:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: null,
      aliases: [],
      versionScope: "server",
    },
    tests: [["header", "server:ats"]],
  },
  {
    name: "Caddy",
    id: "caddy",
    category: "Web server",
    product: {
      vendor: "caddyserver",
      name: "caddy",
      cpe: "cpe:2.3:a:caddyserver:caddy:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: "pkg:golang/github.com/caddyserver/caddy/v2",
      aliases: [],
      versionScope: "server",
    },
    confidence: 88,
    tests: [["header", "server:caddy"]],
  },
  {
    name: "LiteSpeed",
    id: "litespeed",
    category: "Web server",
    product: {
      vendor: "litespeedtech",
      name: "litespeed",
      cpe: null,
      cpeStatus: "unmapped",
      purl: null,
      aliases: ["OpenLiteSpeed", "LiteSpeed Web Server"],
      versionScope: "server",
    },
    confidence: 88,
    tests: [["header", "server:litespeed"]],
  },
  {
    name: "Nginx",
    id: "nginx",
    category: "Web server",
    product: {
      vendor: "f5",
      name: "nginx",
      cpe: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
      cpeStatus: "verified",
      purl: null,
      aliases: [],
      versionScope: "server",
    },
    confidence: 85,
    tests: [["header", "server:nginx"]],
  },
  {
    name: "Varnish",
    id: "varnish",
    category: "Cache / Proxy",
    confidence: 85,
    product: {
      vendor: "varnishcache",
      name: "varnish",
      cpe: null,
      cpeStatus: "unmapped",
      purl: "pkg:generic/varnish-cache",
      aliases: [],
      versionScope: "server",
    },
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
    id: "litespeed-cache",
    category: "Performance",
    confidence: 95,
    product: {
      vendor: "litespeed",
      name: "litespeed_cache",
      cpe: null,
      cpeStatus: "unmapped",
      purl: "pkg:wordpress/litespeed-cache",
      aliases: [],
      versionScope: "unknown",
    },
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
    id: "apache-echarts",
    category: "JavaScript Libraries",
    product: {
      vendor: "apache",
      name: "echarts",
      cpe: null,
      cpeStatus: "unmapped",
      purl: "pkg:npm/echarts",
      aliases: [],
      versionScope: "client",
    },
    confidence: 90,
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

// ============================================================
// TECHLENS CVE PRODUCT METADATA
// ============================================================

// Convert technology names into stable IDs.
// Explicit IDs already defined in RULES are preserved.
function createTechnologyId(name) {
  return String(name)
    .normalize("NFKD")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

// Identify the scope of a technology version.
// This prevents frontend versions from being matched against
// backend vulnerabilities.
function getVersionScope(rule) {
  const name = rule.name.toLowerCase();
  const category = rule.category.toLowerCase();

  const serverTechnologies = [
    "asp.net",
    "asp.net core",
    "django",
    "express.js",
    "node.js",
    "java / spring",
    "laravel",
    "php",
    "ruby on rails",
    "microsoft iis",
    "openresty",
    "envoy",
    "gunicorn",
    "uvicorn",
    "kestrel",
    "apache http server",
    "apache traffic server",
    "caddy",
    "litespeed",
    "nginx",
    "varnish",
    "wordpress",
  ];

  if (serverTechnologies.includes(name)) {
    return "server";
  }

  const clientCategories = [
    "frontend framework",
    "javascript library",
    "javascript libraries",
    "javascript frameworks",
    "css framework",
    "ui library",
  ];

  if (clientCategories.includes(category)) {
    return "client";
  }

  return "unknown";
}

// Never invent a CPE.
// A mapping must be explicitly reviewed and verified.
function validateProductMetadata(product) {
  if (!product || typeof product !== "object") {
    return false;
  }

  const validStatuses = ["verified", "unmapped", "not_applicable"];
  const validScopes = ["client", "server", "unknown"];

  if (!validStatuses.includes(product.cpeStatus)) {
    return false;
  }

  if (!validScopes.includes(product.versionScope)) {
    return false;
  }

  if (!Array.isArray(product.aliases)) {
    return false;
  }

  if (product.cpeStatus === "verified") {
    if (
      typeof product.cpe !== "string" ||
      !/^cpe:2\.3:[aho]:/i.test(product.cpe)
    ) {
      return false;
    }
  } else if (product.cpeStatus === "unmapped") {
    // Unverified candidate CPEs may be stored as metadata,
    // but must never be used for CVE queries.
    if (
      product.cpe !== null &&
      (typeof product.cpe !== "string" ||
        !/^cpe:2\.3:[aho]:/i.test(product.cpe))
    ) {
      return false;
    }
  } else if (product.cpe !== null) {
    // not_applicable must not have a CPE.
    return false;
  }

  return true;
}

// Give every existing technology a consistent CVE-ready structure.
for (const rule of RULES) {
  if (!rule.id) {
    rule.id = createTechnologyId(rule.name);
  }

  if (!rule.product) {
    rule.product = {
      vendor: null,
      name: rule.name,
      cpe: null,
      cpeStatus: "unmapped",
      purl: null,
      aliases: [],
      versionScope: getVersionScope(rule),
    };
  }

  // Normalize missing optional metadata without overwriting
  // explicitly supplied product information.
  rule.product.vendor ??= null;
  rule.product.name ??= rule.name;
  rule.product.cpe ??= null;
  rule.product.cpeStatus ??= "unmapped";
  rule.product.purl ??= null;
  rule.product.aliases ??= [];
  rule.product.versionScope ??= getVersionScope(rule);

  if (!validateProductMetadata(rule.product)) {
    throw new Error(
      `Invalid CVE product metadata for technology: ${rule.name}`,
    );
  }
}

// Look up a technology using its trusted catalogue ID.
function getTechnologyById(technologyId) {
  if (
    typeof technologyId !== "string" ||
    technologyId.length === 0 ||
    technologyId.length > 100
  ) {
    return null;
  }

  return RULES.find((rule) => rule.id === technologyId) || null;
}

// Determine whether a detected technology is eligible for
// a version-aware NVD CVE lookup.
function getCveReadiness(rule, versionInfo) {
  if (!rule || !rule.product) {
    return {
      eligible: false,
      reason: "Product metadata is unavailable.",
    };
  }

  const product = rule.product;

  if (product.cpeStatus === "not_applicable") {
    return {
      eligible: false,
      reason: "This technology is not applicable to CPE-based CVE lookup.",
    };
  }

  if (product.cpeStatus !== "verified" || !product.cpe) {
    return {
      eligible: false,
      reason: "No verified CPE mapping exists for this technology.",
    };
  }

  if (versionInfo?.status === "ambiguous") {
    return {
      eligible: false,
      reason: "Conflicting version observations prevent reliable CVE matching.",
    };
  }

  if (versionInfo?.status !== "confirmed" || !versionInfo.version) {
    return {
      eligible: false,
      reason: "A confirmed technology version is required.",
      cpe: product.cpe,
      version: null,
    };
  }

  if (product.versionScope === "unknown") {
    return {
      eligible: false,
      reason: "The version scope is unknown.",
    };
  }

  return {
    eligible: true,
    reason: null,
  };
}

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

  function getVersionInfo(name) {
    const hints = (page.versionHints || []).filter(
      (item) => item.name?.toLowerCase() === name.toLowerCase() && item.version,
    );

    if (hints.length === 0) {
      const version = getVersion(name);

      if (version) {
        return {
          status: "confirmed",
          version: String(version),
          source: "header",
          confidence: 90,
          observations: [],
        };
      }

      return {
        status: "unknown",
        version: null,
        source: null,
        confidence: null,
        observations: [],
      };
    }

    const sourcePriority = {
      runtime: 4,
      bundle: 4,
      dom: 3,
      resource: 2,
      meta: 1,
    };

    const observations = hints.map((hint) => ({
      version: String(hint.version),
      source: hint.source || "unknown",
      confidence: Number.isFinite(hint.confidence)
        ? Math.max(0, Math.min(99, hint.confidence))
        : 70,
    }));

    const ranked = observations
      .map((observation) => ({
        ...observation,
        score:
          observation.confidence + (sourcePriority[observation.source] || 0),
      }))
      .sort((a, b) => b.score - a.score);

    const best = ranked[0];

    const conflictingBest = ranked.some(
      (item) => item.version !== best.version && item.score === best.score,
    );

    if (conflictingBest) {
      return {
        status: "ambiguous",
        version: null,
        source: null,
        confidence: null,
        observations,
      };
    }

    return {
      status: "confirmed",
      version: best.version,
      source: best.source,
      confidence: best.confidence,
      observations,
    };
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
    const matchedWeights = [];

    const checks = rule.signatures
      ? rule.signatures.map((signature) => ({
          kind: signature.type,
          pattern: signature.pattern,
          matchType: signature.match || "contains",
          weight: signature.weight,
        }))
      : (rule.tests || []).map(([kind, pattern]) => ({
          kind,
          pattern,
          matchType: "contains",
        }));

    for (const check of checks) {
      const { kind, pattern, matchType } = check;

      const search = String(pattern).toLowerCase();
      let match = false;

      function matches(value) {
        const normalized = String(value).toLowerCase();

        if (matchType === "equals") {
          return normalized === search;
        }

        return normalized.includes(search);
      }

      switch (kind) {
        case "resource":
          match = resources.some(matches);
          break;

        case "script":
          match = scripts.some(matches) || resources.some(matches);
          break;

        case "css":
          match = styles.some(matches) || resources.some(matches);
          break;

        case "meta":
          match = metas.some(matches);
          break;

        case "link":
          match = links.some(matches) || resources.some(matches);
          break;

        case "global":
          // A generic "$" global is too ambiguous to prove jQuery.
          if (search === "$") break;

          match = globals.some(matches);
          break;

        case "dom":
          match = dom.some(matches);
          break;

        case "cookie":
          match = cookies.some(matches);
          break;

        case "header":
          // Match headers only, never URLs or page resources.
          match = normalizedHeaders.some((header) =>
            matches(`${header.name}:${header.value}`),
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
        evidence.push(`${kind}: ${pattern}`);

        if (rule.signatures) {
          const weight = Number.isFinite(check.weight)
            ? Math.max(0, Math.min(99, check.weight))
            : 70;

          matchedWeights.push(weight);
        }
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

    const confidence = rule.signatures
      ? Math.round(
          matchedWeights.reduce((total, weight) => total + weight, 0) /
            matchedWeights.length,
        )
      : Math.min(
          99,
          baseConfidence + Math.min(4, (uniqueEvidence.length - 1) * 2),
        );

    const versionInfo = getVersionInfo(rule.name);

    const cveReadiness = rule.product
      ? getCveReadiness(rule, versionInfo)
      : {
          eligible: false,
          reason: "Product metadata is unavailable.",
        };

    found.push({
      ...rule,
      confidence,
      version: versionInfo.version,
      versionInfo,
      evidence: uniqueEvidence,

      // CVE intelligence metadata
      cve: {
        eligible: cveReadiness.eligible,
        reason: cveReadiness.reason,
        cpe: rule.product?.cpeStatus === "verified" ? rule.product.cpe : null,
        version: cveReadiness.eligible ? versionInfo.version : null,
        versionScope: rule.product?.versionScope || "unknown",
      },
    });
  }

  return found.sort(
    (a, b) => b.confidence - a.confidence || a.name.localeCompare(b.name),
  );
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    detect,
    RULES,
    getTechnologyById,
    getCveReadiness,
    validateProductMetadata,
  };
} else {
  globalThis.TechLensDetector = {
    detect,
    RULES,
    getTechnologyById,
    getCveReadiness,
    validateProductMetadata,
  };
}
