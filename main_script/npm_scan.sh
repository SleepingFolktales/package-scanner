#!/usr/bin/env bash
# =============================================================================
#  npm_scan.sh — npm / TypeScript Package Malicious Code Scanner
#  Covers: postinstall hooks, eval chains, child_process, credential
#  harvesting, network exfiltration, obfuscation, native addons, and more.
#
#  Supply chain precedents this covers:
#    - event-stream (2018)      — hidden payload in dependency
#    - ua-parser-js (2021)      — crypto miner + credential stealer
#    - node-ipc (2022)          — protestware wiping files
#    - node-fetch / colors etc  — protestware / postinstall abuse
# =============================================================================

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; BRED='\033[1;31m'
YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
MAGENTA='\033[0;35m'; WHITE='\033[1;37m'

# ── Counters ──────────────────────────────────────────────────────────────────
CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0; FINDINGS=()

banner() {
cat << 'EOF'
  _   _ ____  __  __   ____   ____    _    _   _
 | \ | |  _ \|  \/  | / ___| / ___|  / \  | \ | |
 |  \| | |_) | |\/| | \___ \| |     / _ \ |  \| |
 | |\  |  __/| |  | |  ___) | |___ / ___ \| |\  |
 |_| \_|_|   |_|  |_| |____/ \____/_/   \_\_| \_|

  npm / TypeScript Package Malicious Code Scanner
  Supply Chain Attack Detection Tool
  ─────────────────────────────────────────────────
EOF
}

log_finding() {
    local severity="$1"; local title="$2"; local detail="$3"
    FINDINGS+=("[$severity] $title | $detail")
    case "$severity" in
        CRITICAL) ((CRITICAL++)); echo -e "  ${BRED}[CRITICAL]${RESET} ${BOLD}$title${RESET}" ;;
        HIGH)     ((HIGH++));     echo -e "  ${RED}[HIGH]${RESET}     $title" ;;
        MEDIUM)   ((MEDIUM++));   echo -e "  ${YELLOW}[MEDIUM]${RESET}   $title" ;;
        LOW)      ((LOW++));      echo -e "  ${CYAN}[LOW]${RESET}      $title" ;;
    esac
    echo -e "             ${MAGENTA}↳${RESET} $detail"
}

check_tool() {
    command -v "$1" &>/dev/null
}

grep_files() {
    local pattern="$1"; local desc="$2"; local sev="$3"
    local matches
    matches=$(grep -rl --include="*.js" --include="*.ts" --include="*.cjs" \
              --include="*.mjs" --include="*.json" -E "$pattern" \
              "$EXTRACT_DIR" 2>/dev/null || true)
    if [[ -n "$matches" ]]; then
        local files; files=$(echo "$matches" | head -3 | xargs -I{} basename {} | tr '\n' ', ' | sed 's/, $//')
        log_finding "$sev" "$desc" "Found in: $files"
        return 0
    fi
    return 1
}

grep_all() {
    # search all file types including binaries
    local pattern="$1"; local desc="$2"; local sev="$3"
    local matches
    matches=$(grep -rl -a "$pattern" "$EXTRACT_DIR" 2>/dev/null || true)
    if [[ -n "$matches" ]]; then
        local files; files=$(echo "$matches" | head -3 | xargs -I{} basename {} | tr '\n' ', ' | sed 's/, $//')
        log_finding "$sev" "$desc" "Found in: $files"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  INPUT COLLECTION
# ─────────────────────────────────────────────────────────────────────────────
clear
banner
echo ""
echo -e "${BOLD}Scans an npm package from the registry without installing it.${RESET}"
echo -e "Downloads the tarball, extracts it, and inspects all JS/TS source files.\n"

echo -e "${CYAN}Package name (e.g. lodash, @types/node):${RESET} \c"; read -r PKG_NAME
echo -e "${CYAN}Version to check (leave blank for latest):${RESET} \c"; read -r PKG_VERSION
echo -e "${CYAN}Operating system [macos/linux/windows]:${RESET} \c"; read -r OS_TYPE
OS_TYPE=$(echo "$OS_TYPE" | tr '[:upper:]' '[:lower:]')

if [[ -n "$PKG_VERSION" ]]; then
    PKG_SPEC="${PKG_NAME}@${PKG_VERSION}"
else
    PKG_SPEC="${PKG_NAME}"
fi

WORK_DIR=$(mktemp -d)
EXTRACT_DIR="$WORK_DIR/extracted"
mkdir -p "$EXTRACT_DIR"
trap 'rm -rf "$WORK_DIR"' EXIT

echo -e "\n${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD} Scanning: ${WHITE}${PKG_SPEC}${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 1 — DOWNLOAD (npm pack — no install, just tarball)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BOLD}[1/9] Downloading package from npm registry (no install)...${RESET}"

if ! check_tool npm; then
    echo -e "${RED}[ERROR]${RESET} 'npm' not found. Please install Node.js first."
    exit 1
fi

cd "$WORK_DIR"
PACK_OUTPUT=$(npm pack "$PKG_SPEC" --ignore-scripts 2>&1) || {
    echo -e "${RED}[ERROR]${RESET} Failed to download '${PKG_SPEC}'. Check name/version."
    echo "$PACK_OUTPUT"
    exit 1
}

TARBALL=$(find "$WORK_DIR" -name "*.tgz" | head -1)
if [[ -z "$TARBALL" ]]; then
    echo -e "${RED}[ERROR]${RESET} No .tgz found after npm pack."
    exit 1
fi

TARBALL_SIZE=$(du -sh "$TARBALL" | cut -f1)
echo -e "  ${GREEN}✓${RESET} Downloaded: $(basename "$TARBALL") ($TARBALL_SIZE)"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 2 — EXTRACT
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[2/9] Extracting package contents...${RESET}"
tar -xzf "$TARBALL" -C "$EXTRACT_DIR" 2>/dev/null
# npm pack always puts contents in a 'package/' subdirectory
PKG_DIR="$EXTRACT_DIR/package"
[[ -d "$PKG_DIR" ]] || PKG_DIR="$EXTRACT_DIR"

FILE_COUNT=$(find "$PKG_DIR" -type f | wc -l | tr -d ' ')
JS_COUNT=$(find "$PKG_DIR" -name "*.js" -o -name "*.ts" -o -name "*.cjs" -o -name "*.mjs" 2>/dev/null | wc -l | tr -d ' ')
echo -e "  ${GREEN}✓${RESET} Extracted $FILE_COUNT files ($JS_COUNT JS/TS source files)"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 3 — package.json LIFECYCLE SCRIPT ANALYSIS
#  The npm equivalent of the Python .pth attack vector.
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[3/9] Analysing package.json lifecycle scripts (primary attack vector)...${RESET}"

PKG_JSON="$PKG_DIR/package.json"
if [[ ! -f "$PKG_JSON" ]]; then
    log_finding "HIGH" "No package.json found in package root" \
        "Cannot verify lifecycle hooks — inspect manually"
else
    # Extract and display scripts block
    if check_tool python3; then
        SCRIPTS=$(python3 -c "
import json, sys
try:
    d = json.load(open('$PKG_JSON'))
    s = d.get('scripts', {})
    hooks = {k: v for k, v in s.items() if k in ['preinstall','install','postinstall','prepare','prepublish','prepublishOnly']}
    if hooks:
        for k, v in hooks.items():
            print(f'{k}|||{v}')
except: pass
" 2>/dev/null)

        if [[ -z "$SCRIPTS" ]]; then
            echo -e "  ${GREEN}✓${RESET} No install lifecycle scripts (preinstall/install/postinstall/prepare)"
        else
            while IFS='|||' read -r hook_name hook_cmd; do
                echo -e "  ${YELLOW}⚠${RESET}  Lifecycle hook found: ${BOLD}${hook_name}${RESET}"
                echo -e "             ${MAGENTA}↳${RESET} Command: $hook_cmd"

                # Classify the hook severity
                if echo "$hook_cmd" | grep -qE "node\s+.*\.js|python|bash|sh\s+-c|curl|wget|exec"; then
                    log_finding "CRITICAL" "install hook runs a script: $hook_name" \
                        "\"$hook_cmd\" — executes at npm install time without any import"
                elif echo "$hook_cmd" | grep -qE "prebuild|node-gyp|bindings|nan"; then
                    log_finding "MEDIUM" "Native build hook: $hook_name" \
                        "\"$hook_cmd\" — compiles native code, review the binding source"
                else
                    log_finding "HIGH" "Lifecycle hook exists: $hook_name" \
                        "\"$hook_cmd\" — runs at install time, verify intent"
                fi
            done <<< "$SCRIPTS"
        fi

        # Also check 'bin' entries — can be auto-executed in some scenarios
        BIN_ENTRIES=$(python3 -c "
import json
try:
    d = json.load(open('$PKG_JSON'))
    b = d.get('bin', {})
    if isinstance(b, str): b = {'bin': b}
    for k, v in b.items(): print(f'{k}={v}')
except: pass
" 2>/dev/null)
        if [[ -n "$BIN_ENTRIES" ]]; then
            echo -e "  ${CYAN}ℹ${RESET}  Binary entry points registered: $BIN_ENTRIES"
        fi
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 4 — OBFUSCATION & EVAL CHAINS
#  JS equivalents of exec(base64.b64decode(...))
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[4/9] Scanning for obfuscation and encoded payload execution...${RESET}"

grep_files "eval\s*\(" \
    "eval() usage detected" "HIGH"

grep_files "new\s+Function\s*\(" \
    "Function() constructor (runtime eval equivalent)" "HIGH"

grep_files "Buffer\.from\s*\(['\"][A-Za-z0-9+/=]{20,}['\"],\s*['\"]base64['\"]" \
    "Buffer.from(...,'base64') — possible encoded payload" "HIGH"

grep_files "eval\s*\(\s*Buffer\.from|eval\s*\(\s*atob\s*\(" \
    "Decoded buffer executed via eval() — classic JS supply chain pattern" "CRITICAL"

grep_files "atob\s*\(|btoa\s*\(" \
    "btoa/atob base64 encode/decode usage" "MEDIUM"

grep_files "\\\\x[0-9a-fA-F]{2}(\\\\x[0-9a-fA-F]{2}){10,}" \
    "Long hex-escape string (obfuscated payload)" "HIGH"

grep_files "String\.fromCharCode\s*\(" \
    "String.fromCharCode() — charcode obfuscation" "MEDIUM"

grep_files "\\[\\]\\s*\[.*\\]\\s*\[.*\\]" \
    "JSFuck-style obfuscation pattern" "HIGH"

grep_files "require\s*\(\s*['\"]_[a-z0-9]{1,4}['\"]|require\s*\(\s*['\"]\.[a-z]{1,5}['\"]" \
    "Suspicious short/hidden module name in require()" "MEDIUM"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 5 — child_process & SHELL EXECUTION
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[5/9] Checking for child_process and shell execution...${RESET}"

grep_files "require\s*\(\s*['\"]child_process['\"]|from\s+['\"]child_process['\"]" \
    "child_process module imported" "HIGH"

grep_files "exec\s*\(|execSync\s*\(|spawn\s*\(|spawnSync\s*\(|execFile\s*\(" \
    "Shell command execution (exec/spawn/execFile)" "HIGH"

grep_files "shelljs|execa\s*\(" \
    "Third-party shell execution library (shelljs/execa)" "MEDIUM"

grep_files "process\.binding\s*\(" \
    "process.binding() — low-level Node.js native access" "HIGH"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 6 — NETWORK EXFILTRATION
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[6/9] Scanning for network exfiltration patterns...${RESET}"

grep_files "require\s*\(\s*['\"]https?['\"]|require\s*\(\s*['\"]node-fetch['\"]|require\s*\(\s*['\"]axios['\"]|require\s*\(\s*['\"]got['\"]" \
    "HTTP client module imported (http/https/axios/got/node-fetch)" "MEDIUM"

grep_files "\.post\s*\(\s*['\"]http|http\.request.*method.*POST|fetch\s*\(['\"]http.*\{.*method.*POST" \
    "HTTP POST to external URL" "HIGH"

grep_files "https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" \
    "Hardcoded IP address URL (suspicious exfiltration target)" "HIGH"

grep_all "pastebin\.com|ngrok\.io|requestbin\.|hookb\.in|webhook\.site|\.onion" \
    "Known exfiltration/anonymisation domain referenced" "CRITICAL"

grep_all "litellm\.cloud|models\.litellm\.cloud" \
    "Reference to litellm.cloud (attacker-controlled domain from litellm attack)" "CRITICAL"

grep_files "dns\.resolve|dns\.lookup" \
    "DNS lookup (can be used for DNS exfiltration channel)" "MEDIUM"

grep_files "WebSocket\s*\(|ws\s*=\s*new|require\s*\(\s*['\"]ws['\"]" \
    "WebSocket usage (persistent outbound channel)" "MEDIUM"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 7 — CREDENTIAL HARVESTING
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[7/9] Scanning for credential harvesting patterns...${RESET}"

grep_files "process\.env\b" \
    "process.env access — environment variable enumeration (API keys, tokens)" "MEDIUM"

grep_files "\.ssh/id_rsa|\.ssh/id_ed25519|\.ssh/authorized_keys|\.ssh/known_hosts" \
    "SSH key file paths referenced" "CRITICAL"

grep_files "\.aws/credentials|AWS_ACCESS_KEY|AWS_SECRET|169\.254\.169\.254" \
    "AWS credential harvesting patterns" "CRITICAL"

grep_files "\.kube/config|KUBERNETES_SERVICE|service.*account.*token" \
    "Kubernetes credential harvesting" "CRITICAL"

grep_files "GOOGLE_APPLICATION_CRED|application_default_credentials|gcloud" \
    "GCP credential harvesting patterns" "HIGH"

grep_files "AZURE_CLIENT_SECRET|AZURE_TENANT|\.azure/" \
    "Azure credential harvesting patterns" "HIGH"

grep_files "\.docker/config\.json|DOCKER_AUTH" \
    "Docker config harvesting" "HIGH"

grep_files "\.npmrc|NPM_TOKEN|NODE_AUTH_TOKEN" \
    "npm token/auth harvesting (can push malicious packages)" "CRITICAL"

grep_files "bash_history|zsh_history|psql_history|mysql_history" \
    "Shell history file access" "MEDIUM"

grep_files "bitcoin|ethereum.*keystore|solana|\.zcash|cardano|metamask" \
    "Cryptocurrency wallet paths referenced" "HIGH"

grep_files "fs\.readFile.*\.ssh|fs\.readFileSync.*\.ssh|readFile.*id_rsa" \
    "Direct filesystem read of SSH key" "CRITICAL"

grep_files "os\.homedir\(\)|process\.env\.HOME|process\.env\.USERPROFILE" \
    "Home directory resolution (precursor to credential file access)" "LOW"

grep_files "github_token|GITHUB_TOKEN|GH_TOKEN|ghp_[A-Za-z0-9]" \
    "GitHub token reference or hardcoded token pattern" "CRITICAL"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 8 — NATIVE ADDONS (.node binaries)
#  .node files are compiled native extensions — completely opaque to source
#  analysis and can do anything at the OS level.
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[8/9] Checking for native addon binaries (.node files)...${RESET}"

NODE_BINARIES=$(find "$PKG_DIR" -name "*.node" 2>/dev/null)
if [[ -z "$NODE_BINARIES" ]]; then
    echo -e "  ${GREEN}✓${RESET} No compiled .node native addons found"
else
    while IFS= read -r node_bin; do
        bin_size=$(du -sh "$node_bin" | cut -f1)
        bin_name=$(basename "$node_bin")
        # Legitimate packages (e.g. bcrypt, sharp) have known build systems
        # Flag unconventional paths or suspiciously small/large sizes
        if echo "$node_bin" | grep -qE "build/Release|prebuilds/|bin/"; then
            log_finding "MEDIUM" "Native addon in standard build path: $bin_name ($bin_size)" \
                "Compiled binary — cannot be source-inspected. Verify package legitimacy."
        else
            log_finding "HIGH" "Native addon in unexpected path: $bin_name ($bin_size)" \
                "$(dirname "$node_bin") — unconventional location for a compiled addon"
        fi
    done <<< "$NODE_BINARIES"
fi

# Also flag if package has no obvious reason for native code
if [[ -n "$(find "$PKG_DIR" -name "*.node" 2>/dev/null)" ]]; then
    if ! grep -qE "node-gyp|node-pre-gyp|prebuild|nan|napi" "$PKG_JSON" 2>/dev/null; then
        log_finding "HIGH" "Native .node binaries present but no build system declared in package.json" \
            "Legitimate native addons declare node-gyp or prebuild as a dependency"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 9 — DEPENDENCY CONFUSION & METADATA CHECKS
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[9/9] Checking package metadata for red flags...${RESET}"

if [[ -f "$PKG_JSON" ]] && check_tool python3; then
    python3 -c "
import json, sys

with open('$PKG_JSON') as f:
    d = json.load(f)

name    = d.get('name','')
version = d.get('version','')
desc    = d.get('description','')
author  = d.get('author','')
repo    = d.get('repository', {})
if isinstance(repo, str): repo_url = repo
else: repo_url = repo.get('url','')

# Flag 1: No repository link — hard to audit
if not repo_url:
    print('NO_REPO')

# Flag 2: No description — typosquatting packages often omit these
if not desc:
    print('NO_DESC')

# Flag 3: Version 0.0.1 / 1.0.0 with no prior history visible
if version in ['0.0.1','1.0.0','0.1.0']:
    print(f'FRESH_VERSION:{version}')

# Flag 4: Name is very close to a popular package (simple check)
popular = ['react','lodash','express','axios','webpack','typescript','next',
           'vue','angular','jquery','moment','chalk','commander','dotenv',
           'eslint','prettier','jest','mocha','nodemon','cors','helmet']
name_clean = name.replace('-','').replace('_','').replace('@','').replace('/','')
for p in popular:
    if name_clean != p and (name_clean.startswith(p) or name_clean.endswith(p)):
        if abs(len(name_clean) - len(p)) <= 3:
            print(f'POSSIBLE_TYPOSQUAT:{name} vs {p}')
            break
" 2>/dev/null | while IFS= read -r flag; do
        case "$flag" in
            NO_REPO)
                log_finding "MEDIUM" "No repository URL in package.json" \
                    "Legitimate packages almost always link to a source repo" ;;
            NO_DESC)
                log_finding "LOW" "No description in package.json" \
                    "Typosquatting packages frequently omit descriptions" ;;
            FRESH_VERSION:*)
                v="${flag#FRESH_VERSION:}"
                log_finding "LOW" "Initial version ($v) — no public history to audit" \
                    "Combined with other findings, this increases risk" ;;
            POSSIBLE_TYPOSQUAT:*)
                names="${flag#POSSIBLE_TYPOSQUAT:}"
                log_finding "HIGH" "Possible typosquatting: $names" \
                    "Name is very similar to a popular package — verify you installed the right one" ;;
        esac
    done
fi

# ─────────────────────────────────────────────────────────────────────────────
#  FINAL REPORT
# ─────────────────────────────────────────────────────────────────────────────
TOTAL=$((CRITICAL + HIGH + MEDIUM + LOW))

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD} SCAN REPORT — ${WHITE}${PKG_SPEC}${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "  ${BRED}CRITICAL${RESET}  $CRITICAL    ${RED}HIGH${RESET}  $HIGH    ${YELLOW}MEDIUM${RESET}  $MEDIUM    ${CYAN}LOW${RESET}  $LOW"
echo ""

if [[ $TOTAL -eq 0 ]]; then
    echo -e "  ${GREEN}✓ No suspicious patterns detected.${RESET}"
    echo -e "  Static analysis only — always review postinstall hooks and"
    echo -e "  any native .node addons manually for production use.\n"
elif [[ $CRITICAL -gt 0 ]]; then
    echo -e "  ${BRED}⛔  DO NOT INSTALL THIS PACKAGE.${RESET}"
    echo -e "  Critical supply chain attack indicators detected."
    echo -e "  If already installed: rotate ALL secrets, API keys, tokens,"
    echo -e "  SSH keys and cloud credentials immediately.\n"
elif [[ $HIGH -gt 0 ]]; then
    echo -e "  ${RED}⚠  HIGH-RISK findings. Do not install without manual review.${RESET}\n"
else
    echo -e "  ${YELLOW}⚠  Low/medium concerns only. Verify before using in production.${RESET}\n"
fi

if [[ ${#FINDINGS[@]} -gt 0 ]]; then
    echo -e "${BOLD}  All Findings:${RESET}"
    for f in "${FINDINGS[@]}"; do
        echo -e "  • $f"
    done
    echo ""
fi

echo -e "${BOLD}  Manual verification steps:${RESET}"
if [[ "$OS_TYPE" == "windows" ]]; then
    echo -e "  1. npm show $PKG_NAME dist-tags"
    echo -e "  2. npm view $PKG_NAME scripts"
    echo -e "  3. Check node_modules\\${PKG_NAME}\\package.json scripts block"
    echo -e "  4. npm install $PKG_SPEC --ignore-scripts  (suppress hooks temporarily)"
else
    echo -e "  1. npm view $PKG_NAME scripts"
    echo -e "  2. npm view $PKG_NAME dist-tags"
    echo -e "  3. cat node_modules/$PKG_NAME/package.json | python3 -m json.tool"
    echo -e "  4. npm install \"$PKG_SPEC\" --ignore-scripts  (suppress hooks temporarily)"
    echo -e "  5. find node_modules/$PKG_NAME -name '*.node'"
fi

echo ""
echo -e "${BOLD}  Useful audit commands:${RESET}"
echo -e "  npm audit                    — check all installed packages"
echo -e "  npx better-npm-audit audit   — extended audit reporting"
echo -e "  npx npm-audit-html           — visual audit report"

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  Scan complete. Temp files cleaned up automatically."
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"