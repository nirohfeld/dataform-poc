/**
 * Cross-Tenant Shared Worker State Probe
 *
 * This probe tests whether V8 compilation workers are shared across tenants
 * by checking for state persistence in:
 * - /tmp filesystem
 * - Global prototype modifications
 * - require.cache module injection
 * - Global scope variables
 */

const fs = require ? require("fs") : null;
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
// TEST 1: /tmp Filesystem Persistence
// ============================================
try {
  const tmpMarkerPath = "/tmp/dataform_cross_tenant_marker";
  const tmpCanaryPath = "/tmp/dataform_canary_" + uniqueId;

  // Check if previous marker exists (from other tenant or previous compilation)
  let existingMarkers = [];
  let tmpDirContents = [];

  if (fs && fs.existsSync) {
    // Try to read /tmp directory
    try {
      tmpDirContents = fs.readdirSync("/tmp").filter(f => f.includes("dataform"));
    } catch (e) {
      tmpDirContents = ["ERROR: " + e.message];
    }

    // Check for existing marker file
    if (fs.existsSync(tmpMarkerPath)) {
      try {
        existingMarkers.push({
          path: tmpMarkerPath,
          content: fs.readFileSync(tmpMarkerPath, "utf8")
        });
      } catch (e) {
        existingMarkers.push({path: tmpMarkerPath, error: e.message});
      }
    }

    // Try to write our marker
    let writeSuccess = false;
    try {
      fs.writeFileSync(tmpMarkerPath, JSON.stringify({
        written_by: canaryMarker,
        timestamp: new Date().toISOString(),
        message: "If you see this, /tmp is shared!"
      }));
      writeSuccess = true;
    } catch (e) {
      writeSuccess = "ERROR: " + e.message;
    }

    probeResults.tests.tmpFilesystem = {
      available: true,
      existingMarkers: existingMarkers,
      tmpDirContents: tmpDirContents,
      writeSuccess: writeSuccess,
      markerPath: tmpMarkerPath
    };
  } else {
    probeResults.tests.tmpFilesystem = {
      available: false,
      reason: "fs module not available"
    };
  }
} catch (e) {
  probeResults.tests.tmpFilesystem = {
    available: false,
    error: e.message
  };
}

// ============================================
// TEST 2: Global Prototype Pollution
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

  // Also try Array prototype
  const hasArrayCanary = Array.prototype.__crossTenantCanary !== undefined;
  const existingArrayCanary = Array.prototype.__crossTenantCanary;
  Array.prototype.__crossTenantCanary = canaryMarker;

  // Try Function prototype
  const hasFunctionCanary = Function.prototype.__crossTenantCanary !== undefined;
  const existingFunctionCanary = Function.prototype.__crossTenantCanary;
  Function.prototype.__crossTenantCanary = canaryMarker;

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
    }
  };
} catch (e) {
  probeResults.tests.prototypePollution = {
    error: e.message
  };
}

// ============================================
// TEST 3: require.cache Inspection & Injection
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
    const dataformCorePath = cacheKeys.find(k => k.includes("@dataform/core"));
    if (dataformCorePath && require.cache[dataformCorePath]) {
      dataformCoreInfo = {
        path: dataformCorePath,
        hasExports: !!require.cache[dataformCorePath].exports,
        exportKeys: Object.keys(require.cache[dataformCorePath].exports || {}).slice(0, 20)
      };
    }

    probeResults.tests.requireCache = {
      available: true,
      totalModules: cacheKeys.length,
      dataformModules: dataformModules.slice(0, 10),
      hadInjectedMarker: hasInjectedMarker,
      existingInjection: existingInjection,
      setOurInjection: true,
      dataformCoreInfo: dataformCoreInfo
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
// TEST 4: Global Scope Canary
// ============================================
try {
  // Check if global scope has markers from previous compilations
  const globalKeys = Object.keys(global || globalThis || {});
  const suspiciousGlobals = globalKeys.filter(k =>
    k.includes("canary") || k.includes("marker") || k.includes("CANARY")
  );

  // Check our specific global marker
  const hasGlobalCanary = (global || globalThis).__dataformCrossTenantCanary !== undefined;
  const existingGlobalCanary = (global || globalThis).__dataformCrossTenantCanary;

  // Set our global canary
  (global || globalThis).__dataformCrossTenantCanary = {
    marker: canaryMarker,
    timestamp: new Date().toISOString(),
    pid: typeof process !== "undefined" ? process.pid : "N/A"
  };

  probeResults.tests.globalScope = {
    totalGlobals: globalKeys.length,
    suspiciousGlobals: suspiciousGlobals,
    hadCanary: hasGlobalCanary,
    existingCanaryValue: existingGlobalCanary,
    setOurCanary: true,
    globalSample: globalKeys.slice(0, 30)
  };
} catch (e) {
  probeResults.tests.globalScope = {
    error: e.message
  };
}

// ============================================
// TEST 5: Process & Environment Info
// ============================================
try {
  if (typeof process !== "undefined") {
    probeResults.tests.processInfo = {
      pid: process.pid,
      ppid: process.ppid,
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version,
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      cwd: process.cwd(),
      execPath: process.execPath,
      argv: process.argv
    };
  } else {
    probeResults.tests.processInfo = { available: false };
  }
} catch (e) {
  probeResults.tests.processInfo = { error: e.message };
}

// ============================================
// TEST 6: Module System Info
// ============================================
try {
  probeResults.tests.moduleInfo = {
    __dirname: typeof __dirname !== "undefined" ? __dirname : "N/A",
    __filename: typeof __filename !== "undefined" ? __filename : "N/A",
    moduleId: typeof module !== "undefined" ? module.id : "N/A",
    modulePaths: typeof module !== "undefined" ? module.paths : []
  };
} catch (e) {
  probeResults.tests.moduleInfo = { error: e.message };
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
    ${probeResults.tests.tmpFilesystem && probeResults.tests.tmpFilesystem.available} as tmp_fs_available,
    ${probeResults.tests.prototypePollution && probeResults.tests.prototypePollution.objectPrototype && probeResults.tests.prototypePollution.objectPrototype.hadCanary} as found_prototype_canary,
    ${probeResults.tests.requireCache && probeResults.tests.requireCache.hadInjectedMarker} as found_require_cache_marker,
    ${probeResults.tests.globalScope && probeResults.tests.globalScope.hadCanary} as found_global_canary
`);
