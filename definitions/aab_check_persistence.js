/**
 * Cross-Tenant Persistence Check
 *
 * This file checks for markers left by previous compilations.
 * If we find markers, it means state persists across compilations
 * (potentially cross-tenant if workers are shared).
 *
 * Run this AFTER aaa_shared_worker_probe.js in a SEPARATE compilation.
 */

const fs = require ? require("fs") : null;
const checkTimestamp = Date.now();
const checkId = Math.random().toString(36).substring(2, 15);

const persistenceCheck = {
  checkTimestamp: new Date().toISOString(),
  checkId: `CHECK_${checkTimestamp}_${checkId}`,
  foundMarkers: [],
  tests: {}
};

// ============================================
// CHECK 1: /tmp Filesystem Markers
// ============================================
try {
  if (fs && fs.existsSync) {
    const tmpMarkerPath = "/tmp/dataform_cross_tenant_marker";

    // List all dataform-related files in /tmp
    let tmpFiles = [];
    try {
      tmpFiles = fs.readdirSync("/tmp").filter(f =>
        f.includes("dataform") || f.includes("canary") || f.includes("CANARY")
      );
    } catch (e) {
      tmpFiles = ["ERROR: " + e.message];
    }

    // Read the marker file
    let markerContent = null;
    if (fs.existsSync(tmpMarkerPath)) {
      try {
        markerContent = JSON.parse(fs.readFileSync(tmpMarkerPath, "utf8"));
        persistenceCheck.foundMarkers.push({
          type: "tmp_file",
          path: tmpMarkerPath,
          content: markerContent
        });
      } catch (e) {
        markerContent = { error: e.message, raw: fs.readFileSync(tmpMarkerPath, "utf8") };
      }
    }

    persistenceCheck.tests.tmpFilesystem = {
      available: true,
      tmpFiles: tmpFiles,
      markerExists: fs.existsSync(tmpMarkerPath),
      markerContent: markerContent,
      CROSS_TENANT_INDICATOR: markerContent && markerContent.written_by ? "POTENTIAL CROSS-TENANT STATE SHARING!" : null
    };
  } else {
    persistenceCheck.tests.tmpFilesystem = { available: false };
  }
} catch (e) {
  persistenceCheck.tests.tmpFilesystem = { error: e.message };
}

// ============================================
// CHECK 2: Prototype Pollution Persistence
// ============================================
try {
  // Check Object.prototype
  const objectCanary = Object.prototype.__crossTenantCanary;
  const arrayCanary = Array.prototype.__crossTenantCanary;
  const functionCanary = Function.prototype.__crossTenantCanary;

  // Check for any unexpected properties on Object.prototype
  const unexpectedProps = [];
  for (let key in {}) {
    unexpectedProps.push(key);
  }

  persistenceCheck.tests.prototypePollution = {
    objectPrototypeCanary: objectCanary || null,
    arrayPrototypeCanary: arrayCanary || null,
    functionPrototypeCanary: functionCanary || null,
    unexpectedObjectProps: unexpectedProps,
    CROSS_TENANT_INDICATOR: (objectCanary || arrayCanary || functionCanary) ? "PROTOTYPE POLLUTION PERSISTS ACROSS COMPILATIONS!" : null
  };

  if (objectCanary) {
    persistenceCheck.foundMarkers.push({
      type: "object_prototype",
      value: objectCanary
    });
  }
} catch (e) {
  persistenceCheck.tests.prototypePollution = { error: e.message };
}

// ============================================
// CHECK 3: require.cache Persistence
// ============================================
try {
  if (typeof require !== "undefined" && require.cache) {
    const injection = require.cache.__crossTenantInjection;

    persistenceCheck.tests.requireCache = {
      injectionFound: !!injection,
      injectionValue: injection || null,
      CROSS_TENANT_INDICATOR: injection ? "REQUIRE.CACHE INJECTION PERSISTS!" : null
    };

    if (injection) {
      persistenceCheck.foundMarkers.push({
        type: "require_cache",
        value: injection
      });
    }
  } else {
    persistenceCheck.tests.requireCache = { available: false };
  }
} catch (e) {
  persistenceCheck.tests.requireCache = { error: e.message };
}

// ============================================
// CHECK 4: Global Scope Canary
// ============================================
try {
  const globalCanary = (global || globalThis).__dataformCrossTenantCanary;

  persistenceCheck.tests.globalScope = {
    canaryFound: !!globalCanary,
    canaryValue: globalCanary || null,
    CROSS_TENANT_INDICATOR: globalCanary ? "GLOBAL SCOPE STATE PERSISTS ACROSS COMPILATIONS!" : null
  };

  if (globalCanary) {
    persistenceCheck.foundMarkers.push({
      type: "global_scope",
      value: globalCanary
    });
  }
} catch (e) {
  persistenceCheck.tests.globalScope = { error: e.message };
}

// ============================================
// SUMMARY: Cross-Tenant Vulnerability Detection
// ============================================
persistenceCheck.summary = {
  totalMarkersFound: persistenceCheck.foundMarkers.length,
  vulnerabilityDetected: persistenceCheck.foundMarkers.length > 0,
  message: persistenceCheck.foundMarkers.length > 0
    ? "CRITICAL: State persistence detected! This may indicate shared workers across tenants."
    : "No markers found from previous compilation. Run aaa_shared_worker_probe.js first, then recompile.",
  markerTypes: persistenceCheck.foundMarkers.map(m => m.type)
};

// ============================================
// Create Dataform Actions with Results
// ============================================

dataform.projectConfig.defaultDatabase = "shir-research-3";
dataform.projectConfig.defaultSchema = "dataform_poc";

operate("persistence_check_results").queries([
  `-- Persistence Check Results - ${persistenceCheck.checkId}
   CREATE OR REPLACE TABLE \`shir-research-3.dataform_poc.persistence_check_results\` AS
   SELECT
     '${persistenceCheck.checkId}' as check_id,
     CURRENT_TIMESTAMP() as check_time,
     ${persistenceCheck.summary.vulnerabilityDetected} as vulnerability_detected,
     ${persistenceCheck.foundMarkers.length} as markers_found,
     '${persistenceCheck.summary.message.replace(/'/g, "\\'")}' as message,
     '${JSON.stringify(persistenceCheck).replace(/'/g, "\\'")}' as full_results_json`
]);

publish("persistence_check_view").query(`
  SELECT
    '${persistenceCheck.checkTimestamp}' as check_timestamp,
    '${persistenceCheck.checkId}' as check_id,
    ${persistenceCheck.summary.vulnerabilityDetected} as vulnerability_detected,
    ${persistenceCheck.foundMarkers.length} as markers_found,
    '${persistenceCheck.summary.message.replace(/'/g, "''")}' as summary_message,
    '${JSON.stringify(persistenceCheck.summary.markerTypes)}' as marker_types
`);
