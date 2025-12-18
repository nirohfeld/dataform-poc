# Dataform Application Layer Vulnerability PoC

This directory contains proof-of-concept files for testing Dataform application layer vulnerabilities.

## Attack Vectors

### 1. SQLX JavaScript Execution (`definitions/ace_poc.sqlx`)

**Hypothesis:** JavaScript in SQLX files executes during compilation with full Node.js capabilities.

**What it tests:**
- `child_process.execSync()` - Command execution
- `process.env` - Environment variable access
- GCP metadata service - Credential theft via SSRF
- `fs` module - File system access
- Network egress - Ability to exfiltrate data

**Usage:**
1. Push this repository to a Git server
2. Connect Dataform to the repository
3. Trigger a compilation (manual or via workflow)
4. Check compiled SQL output for base64-encoded results

### 2. Webhook Exfiltration (`definitions/exfil_poc.sqlx`)

**Purpose:** Exfiltrate data to attacker-controlled endpoint even if compiled SQL isn't visible.

**Setup:**
1. Create a webhook endpoint (webhook.site, requestbin, or your own server)
2. Replace `EXFIL_URL` in the file with your endpoint
3. Deploy and trigger compilation
4. Check your webhook for incoming POST with stolen data

### 3. npm Lifecycle Scripts (`package.json`)

**Hypothesis:** Dataform runs `npm install` and executes lifecycle scripts.

**What it tests:**
- `postinstall` script execution
- GCP metadata service access from npm context
- Command execution capability

**Usage:**
1. Deploy repository
2. Check if Dataform runs `npm install`
3. Monitor logs or webhook for `POSTINSTALL_POC` output

## Expected Results

### If SQLX JS is NOT sandboxed:
- `whoami` returns actual user
- `gcp_token` contains JSON with `access_token`
- Webhook receives POST with credentials

### If SQLX JS IS sandboxed:
- Operations throw errors like "require is not defined" or "blocked"
- No webhook callback received

## Files

```
dataform/
├── dataform.json          # Dataform project config
├── package.json           # npm config with lifecycle script PoC
├── definitions/
│   ├── ace_poc.sqlx       # Main RCE test (outputs to compiled SQL)
│   └── exfil_poc.sqlx     # Webhook exfiltration (works if output hidden)
└── README.md              # This file
```

## Deployment

```bash
# Initialize git repo
cd poc/dataform
git init
git add .
git commit -m "Initial Dataform PoC"

# Push to your rogue server or GitHub
git remote add origin https://your-server/repo.git
git push -u origin main

# Connect Dataform to this repository
# Trigger compilation and check results
```

## Interpreting Results

### Base64 Decode
```bash
echo "BASE64_STRING" | base64 -d
```

### GCP Token Format
```json
{
  "access_token": "ya29.c...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

### Using Stolen Token
```bash
curl -H "Authorization: Bearer ya29.c..." \
  "https://www.googleapis.com/storage/v1/b?project=PROJECT_ID"
```
