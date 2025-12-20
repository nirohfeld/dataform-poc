/**
 * Cross-Tenant Persistence Check
 * Version 2: No fs module (blocked)
 *
 * This file checks for markers left by previous compilations.
 * If we find markers, it means state persists across compilations
 * (potentially cross-tenant if workers are shared).
 *
 * Run this AFTER aaa_shared_worker_probe.js in a SEPARATE compilation.
 */

const checkTimestamp = Date.now();
const checkId = Math.random().toString(36).substring(2, 15);

const persistenceCheck = {
  checkTimestamp: new Date().toISOString(),
  checkId: `CHECK_${checkTimestamp}_${checkId}`,
  foundMarkers: [],
  tests: {}
};

// ============================================
// CHECK 1: Prototype Pollution Persistence
// ============================================
try {
  // Check Object.prototype
  const objectCanary = Object.prototype.__crossTenantCanary;
  const objectTimestamp = Object.prototype.__crossTenantTimestamp;
  const arrayCanary = Array.prototype.__crossTenantCanary;
  const functionCanary = Function.prototype.__crossTenantCanary;
  const stringCanary = String.prototype.__crossTenantCanary;

  // Check for any unexpected properties on Object.prototype
  const unexpectedProps = [];
  for (let key in {}) {
    unexpectedProps.push(key);
  }

  persistenceCheck.tests.prototypePollution = {
    objectPrototypeCanary: objectCanary || null,
    objectPrototypeTimestamp: objectTimestamp || null,
    arrayPrototypeCanary: arrayCanary || null,
    functionPrototypeCanary: functionCanary || null,
    stringPrototypeCanary: stringCanary || null,
    unexpectedObjectProps: unexpectedProps,
    CROSS_TENANT_INDICATOR: (objectCanary || arrayCanary || functionCanary || stringCanary) ? "CRITICAL: PROTOTYPE POLLUTION PERSISTS ACROSS COMPILATIONS!" : null
  };

  if (objectCanary) {
    persistenceCheck.foundMarkers.push({
      type: "object_prototype",
      value: objectCanary,
      timestamp: objectTimestamp
    });
  }
  if (arrayCanary) {
    persistenceCheck.foundMarkers.push({
      type: "array_prototype",
      value: arrayCanary
    });
  }
  if (functionCanary) {
    persistenceCheck.foundMarkers.push({
      type: "function_prototype",
      value: functionCanary
    });
  }
} catch (e) {
  persistenceCheck.tests.prototypePollution = { error: e.message };
}

// ============================================
// CHECK 2: require.cache Persistence
// ============================================
try {
  if (typeof require !== "undefined" && require.cache) {
    const injection = require.cache.__crossTenantInjection;

    persistenceCheck.tests.requireCache = {
      injectionFound: !!injection,
      injectionValue: injection || null,
      CROSS_TENANT_INDICATOR: injection ? "CRITICAL: REQUIRE.CACHE INJECTION PERSISTS!" : null
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
// CHECK 3: Global Scope Canary
// ============================================
try {
  const globalObj = typeof global !== "undefined" ? global : (typeof globalThis !== "undefined" ? globalThis : {});
  const globalCanary = globalObj.__dataformCrossTenantCanary;
  const ctMarker = globalObj.__CT_MARKER;

  // Look for any suspicious global variables
  const globalKeys = Object.keys(globalObj);
  const suspiciousGlobals = globalKeys.filter(k =>
    k.includes("canary") || k.includes("marker") || k.includes("CANARY") ||
    k.includes("crossTenant") || k.includes("__CT") || k.includes("inject")
  );

  persistenceCheck.tests.globalScope = {
    canaryFound: !!globalCanary,
    canaryValue: globalCanary || null,
    ctMarkerFound: !!ctMarker,
    ctMarkerValue: ctMarker || null,
    suspiciousGlobals: suspiciousGlobals,
    CROSS_TENANT_INDICATOR: (globalCanary || ctMarker) ? "CRITICAL: GLOBAL SCOPE STATE PERSISTS ACROSS COMPILATIONS!" : null
  };

  if (globalCanary) {
    persistenceCheck.foundMarkers.push({
      type: "global_scope",
      value: globalCanary
    });
  }
  if (ctMarker) {
    persistenceCheck.foundMarkers.push({
      type: "ct_marker",
      value: ctMarker
    });
  }
} catch (e) {
  persistenceCheck.tests.globalScope = { error: e.message };
}

// ============================================
// CHECK 4: Dataform Object Canary
// ============================================
try {
  const dataformCanary = dataform.__crossTenantCanary;

  persistenceCheck.tests.dataformObject = {
    canaryFound: !!dataformCanary,
    canaryValue: dataformCanary || null,
    CROSS_TENANT_INDICATOR: dataformCanary ? "CRITICAL: DATAFORM OBJECT STATE PERSISTS ACROSS COMPILATIONS!" : null
  };

  if (dataformCanary) {
    persistenceCheck.foundMarkers.push({
      type: "dataform_object",
      value: dataformCanary
    });
  }
} catch (e) {
  persistenceCheck.tests.dataformObject = { error: e.message };
}

// ============================================
// SUMMARY: Cross-Tenant Vulnerability Detection
// ============================================
persistenceCheck.summary = {
  totalMarkersFound: persistenceCheck.foundMarkers.length,
  vulnerabilityDetected: persistenceCheck.foundMarkers.length > 0,
  message: persistenceCheck.foundMarkers.length > 0
    ? "CRITICAL: State persistence detected! This indicates shared workers across tenants. Cross-tenant attack is possible."
    : "No markers found from previous compilation. This is expected for the first run. Compile again to check for persistence.",
  markerTypes: persistenceCheck.foundMarkers.map(m => m.type),
  severity: persistenceCheck.foundMarkers.length > 0 ? "CRITICAL" : "INFO"
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
     '${persistenceCheck.summary.severity}' as severity,
     '${persistenceCheck.summary.message.replace(/'/g, "\\'")}' as message,
     '${JSON.stringify(persistenceCheck).replace(/'/g, "\\'")}' as full_results_json`
]);

publish("persistence_check_view").query(`
  SELECT
    '${persistenceCheck.checkTimestamp}' as check_timestamp,
    '${persistenceCheck.checkId}' as check_id,
    ${persistenceCheck.summary.vulnerabilityDetected} as vulnerability_detected,
    ${persistenceCheck.foundMarkers.length} as markers_found,
    '${persistenceCheck.summary.severity}' as severity,
    '${persistenceCheck.summary.message.replace(/'/g, "''")}' as summary_message,
    '${JSON.stringify(persistenceCheck.summary.markerTypes)}' as marker_types
`);
