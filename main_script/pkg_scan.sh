#!/usr/bin/env bash
# =============================================================================
#  pkg_scan.sh — Python Package Malicious Code Scanner
#  Inspired by the litellm 1.82.8 supply chain attack (CVE 2026-03-24)
#  Checks for: .pth backdoors, base64 payloads, credential harvesting,
#  exfiltration attempts, obfuscated exec chains, and more.
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
  ____  _  _______ ____   ____    _    _   _
 |  _ \| |/ / ____/ ___| / ___|  / \  | \ | |
 | |_) | ' /|  _| \___ \| |     / _ \ |  \| |
 |  __/| . \| |___ ___) | |___ / ___ \| |\  |
 |_|   |_|\_\_____|____/ \____/_/   \_\_| \_|

  Python Package Malicious Code Scanner
  Supply Chain Attack Detection Tool
  ─────────────────────────────────────────────
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
    if ! command -v "$1" &>/dev/null; then
        echo -e "${YELLOW}[WARN]${RESET} '$1' not found — some checks may be skipped."
        return 1
    fi
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
#  INPUT COLLECTION
# ─────────────────────────────────────────────────────────────────────────────
clear
banner
echo ""
echo -e "${BOLD}This tool inspects a Python package from PyPI for signs of malicious code${RESET}"
echo -e "without installing anything on your system.\n"

echo -e "${CYAN}Package name (e.g. litellm):${RESET} \c"; read -r PKG_NAME
echo -e "${CYAN}Version to check (leave blank for latest):${RESET} \c"; read -r PKG_VERSION
echo -e "${CYAN}Operating system [macos/linux/windows]:${RESET} \c"; read -r OS_TYPE
OS_TYPE=$(echo "$OS_TYPE" | tr '[:upper:]' '[:lower:]')

# Build version specifier
if [[ -n "$PKG_VERSION" ]]; then
    PKG_SPEC="${PKG_NAME}==${PKG_VERSION}"
else
    PKG_SPEC="${PKG_NAME}"
fi

# Work directory (always cleaned up)
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

echo -e "\n${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD} Scanning: ${WHITE}${PKG_SPEC}${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 1 — DOWNLOAD PACKAGE (no install)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BOLD}[1/8] Downloading package from PyPI (no install)...${RESET}"

PIP_CMD="pip"
if [[ "$OS_TYPE" == "macos" ]] || [[ "$OS_TYPE" == "mac" ]]; then
    PIP_CMD="pip3"
elif [[ "$OS_TYPE" == "windows" ]]; then
    PIP_CMD="pip"
fi

if ! $PIP_CMD download "$PKG_SPEC" --no-deps -d "$WORK_DIR" &>/dev/null; then
    echo -e "${RED}[ERROR]${RESET} Failed to download '$PKG_SPEC'. Check the name/version and try again."
    exit 1
fi

WHEEL_FILE=$(find "$WORK_DIR" -name "*.whl" | head -1)
TARGZ_FILE=$(find "$WORK_DIR" -name "*.tar.gz" | head -1)

if [[ -z "$WHEEL_FILE" && -z "$TARGZ_FILE" ]]; then
    echo -e "${RED}[ERROR]${RESET} No .whl or .tar.gz found after download."
    exit 1
fi

echo -e "  ${GREEN}✓${RESET} Downloaded: $(basename "${WHEEL_FILE:-$TARGZ_FILE}")"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 2 — EXTRACT
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[2/8] Extracting package contents...${RESET}"
EXTRACT_DIR="$WORK_DIR/extracted"
mkdir -p "$EXTRACT_DIR"

if [[ -n "$WHEEL_FILE" ]]; then
    if check_tool unzip; then
        unzip -q "$WHEEL_FILE" -d "$EXTRACT_DIR"
    else
        python3 -c "import zipfile; zipfile.ZipFile('$WHEEL_FILE').extractall('$EXTRACT_DIR')"
    fi
fi

if [[ -n "$TARGZ_FILE" ]]; then
    tar -xzf "$TARGZ_FILE" -C "$EXTRACT_DIR" 2>/dev/null || true
fi

FILE_COUNT=$(find "$EXTRACT_DIR" -type f | wc -l | tr -d ' ')
echo -e "  ${GREEN}✓${RESET} Extracted $FILE_COUNT files"

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

grep_check() {
    # Usage: grep_check <pattern> <description> <severity> [file_hint]
    local pattern="$1"; local desc="$2"; local sev="$3"
    local matches
    matches=$(grep -rl --include="*" -E "$pattern" "$EXTRACT_DIR" 2>/dev/null || true)
    if [[ -n "$matches" ]]; then
        local files; files=$(echo "$matches" | head -3 | xargs -I{} basename {} | tr '\n' ', ')
        log_finding "$sev" "$desc" "Found in: $files"
        return 0
    fi
    return 1
}

grep_check_binary() {
    local pattern="$1"; local desc="$2"; local sev="$3"
    local matches
    matches=$(grep -rl -a "$pattern" "$EXTRACT_DIR" 2>/dev/null || true)
    if [[ -n "$matches" ]]; then
        local files; files=$(echo "$matches" | head -3 | xargs -I{} basename {} | tr '\n' ', ')
        log_finding "$sev" "$desc" "Found in: $files"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 3 — .PTH FILE CHECK (primary litellm attack vector)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[3/8] Checking for .pth backdoor files...${RESET}"
PTH_FILES=$(find "$EXTRACT_DIR" -name "*.pth" 2>/dev/null)

if [[ -z "$PTH_FILES" ]]; then
    echo -e "  ${GREEN}✓${RESET} No .pth files found"
else
    while IFS= read -r pth; do
        pth_name=$(basename "$pth")
        pth_size=$(wc -c < "$pth" | tr -d ' ')
        pth_content=$(cat "$pth" 2>/dev/null || true)

        echo -e "  ${YELLOW}⚠${RESET}  Found .pth file: ${BOLD}$pth_name${RESET} (${pth_size} bytes)"

        # Legit .pth files just add paths — they look like:
        #   /some/path/to/lib
        # Malicious ones import or exec code
        if echo "$pth_content" | grep -qE "^import |^exec\(|subprocess|base64|eval\("; then
            log_finding "CRITICAL" ".pth file executes code on Python startup" \
                "$pth_name contains executable statements — auto-runs without any import"
        elif [[ $pth_size -gt 5000 ]]; then
            log_finding "CRITICAL" ".pth file is suspiciously large ($pth_size bytes)" \
                "$pth_name — legitimate .pth files are tiny path lists, not multi-KB blobs"
        elif [[ $pth_size -gt 500 ]]; then
            log_finding "HIGH" ".pth file is larger than expected ($pth_size bytes)" \
                "$pth_name — inspect manually"
        else
            echo -e "  ${GREEN}✓${RESET}  $pth_name looks like a normal path file ($pth_size bytes)"
        fi
    done <<< "$PTH_FILES"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 4 — BASE64 & OBFUSCATION CHECKS
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[4/8] Scanning for obfuscation and encoded payloads...${RESET}"

grep_check "base64\.b64decode\s*\(" \
    "base64.b64decode() used" "MEDIUM"

# Double-encoded: decode result fed straight into exec/eval
grep_check "exec\(base64\.b64decode|eval\(base64\.b64decode" \
    "Encoded payload executed directly via exec(base64.b64decode(...))" "CRITICAL"

grep_check "exec\(.*decode\(|eval\(.*decode\(" \
    "Chained decode→exec pattern detected" "HIGH"

grep_check "__import__\('base64'\)" \
    "Dynamic base64 import (evasion technique)" "HIGH"

grep_check "compile\(.*exec\(|exec\(compile\(" \
    "compile()+exec() chain (bytecode obfuscation)" "HIGH"

grep_check "marshal\.loads|pickle\.loads|shelve\." \
    "Deserialisation of arbitrary data (marshal/pickle)" "MEDIUM"

grep_check "zlib\.decompress.*exec|exec.*zlib\.decompress" \
    "Compressed+executed payload (zlib→exec)" "HIGH"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 5 — SUBPROCESS & NETWORK EXFILTRATION
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[5/8] Checking for subprocess and network activity...${RESET}"

grep_check "subprocess\.(Popen|call|run|check_output)" \
    "subprocess execution found" "HIGH"

grep_check "os\.system\s*\(|os\.popen\s*\(" \
    "os.system()/os.popen() shell execution" "HIGH"

grep_check "curl\s+-s.*-X\s+POST|curl.*--data-binary|curl.*octet-stream" \
    "curl POST with binary data (exfiltration pattern)" "CRITICAL"

grep_check "requests\.(post|put)\s*\(|urllib.*urlopen.*POST" \
    "HTTP POST to external server" "HIGH"

grep_check "socket\.connect\s*\(|socket\.send\s*\(" \
    "Raw socket connection" "HIGH"

grep_check "ftplib|smtplib\.SMTP" \
    "FTP/SMTP usage (data exfiltration channels)" "MEDIUM"

# Check for suspicious hardcoded domains that aren't the official package domain
# Using binary grep to catch encoded strings too
grep_check_binary "litellm\.cloud|models\.litellm\.cloud" \
    "Reference to litellm.cloud (attacker-controlled domain from litellm attack)" "CRITICAL"

grep_check "http[s]?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" \
    "Hardcoded IP address URL (suspicious exfiltration target)" "HIGH"

grep_check "\.onion|pastebin\.com|ngrok\.io|requestbin\." \
    "Known exfiltration/anonymisation domain referenced" "CRITICAL"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 6 — CREDENTIAL HARVESTING PATTERNS
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[6/8] Scanning for credential harvesting patterns...${RESET}"

grep_check "\.ssh/id_rsa|\.ssh/id_ed25519|\.ssh/authorized_keys" \
    "SSH key file paths referenced" "CRITICAL"

grep_check "\.aws/credentials|AWS_ACCESS_KEY|AWS_SECRET|IMDS|169\.254\.169\.254" \
    "AWS credential harvesting patterns" "CRITICAL"

grep_check "\.kube/config|kubernetes/admin\.conf|service.*account.*token" \
    "Kubernetes credential harvesting patterns" "CRITICAL"

grep_check "application_default_credentials|gcloud|GOOGLE_APPLICATION_CRED" \
    "GCP credential harvesting patterns" "HIGH"

grep_check "\.azure/|AZURE_CLIENT_SECRET|AZURE_TENANT" \
    "Azure credential harvesting patterns" "HIGH"

grep_check "\.docker/config\.json|kaniko.*docker" \
    "Docker config harvesting" "HIGH"

grep_check "\.npmrc|vault-token|\.netrc|\.pgpass|\.my\.cnf|\.mongorc" \
    "Package manager / DB credential file access" "HIGH"

grep_check "bash_history|zsh_history|psql_history|mysql_history|rediscli_history" \
    "Shell history file access (leaks past commands/secrets)" "MEDIUM"

grep_check "bitcoin|ethereum.*keystore|solana|cardano|litecoin|\.zcash" \
    "Cryptocurrency wallet paths referenced" "HIGH"

grep_check "printenv|os\.environ\b" \
    "Environment variable enumeration (API keys/tokens)" "MEDIUM"

grep_check "uname -a|ip addr|ip route|hostname|whoami" \
    "System reconnaissance commands" "MEDIUM"

grep_check "/etc/ssl/private|letsencrypt.*\.pem|\.key\b" \
    "SSL/TLS private key file access" "HIGH"

grep_check "terraform\.tfvars|\.gitlab-ci\.yml|Jenkinsfile|\.travis\.yml|\.drone\.yml" \
    "CI/CD secrets file access" "HIGH"

grep_check "slack.*webhook|discord.*webhook|https://hooks\." \
    "Webhook URL harvesting (Slack/Discord)" "MEDIUM"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 7 — ENCRYPTION & STAGING PATTERNS
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[7/8] Checking for encryption/staging (exfil prep)...${RESET}"

grep_check "openssl.*aes-256|openssl.*enc.*-pbkdf2" \
    "openssl AES-256 encryption (data staging before exfil)" "CRITICAL"

grep_check "openssl.*pkeyutl.*encrypt|openssl.*rsa" \
    "RSA public key encryption of collected data" "CRITICAL"

grep_check "tar\s+-czf|tpcp\.tar\.gz" \
    "tar archive creation (staging for exfiltration)" "HIGH"

grep_check "tempfile\.|mkstemp|NamedTemporaryFile" \
    "Temporary file usage (may be used for staging)" "LOW"

grep_check "MIICIjANBgkqhkiG9w0BAQEFAA|BEGIN PUBLIC KEY|BEGIN RSA" \
    "Hardcoded RSA public key (attacker key for encrypting stolen data)" "CRITICAL"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 8 — SETUP.PY / PYPROJECT HOOK ABUSE
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[8/8] Checking install hook abuse and RECORD tampering...${RESET}"

# setup.py with subprocess in install commands
SETUP_PY=$(find "$EXTRACT_DIR" -name "setup.py" | head -1)
if [[ -n "$SETUP_PY" ]]; then
    if grep -qE "subprocess|os\.system|urllib|requests" "$SETUP_PY"; then
        log_finding "HIGH" "setup.py executes network/system calls" \
            "setup.py runs code at install time via cmdclass hooks"
    else
        echo -e "  ${GREEN}✓${RESET} setup.py looks clean"
    fi
fi

# RECORD file: check for unexpected .pth entries
RECORD_FILE=$(find "$EXTRACT_DIR" -name "RECORD" | head -1)
if [[ -n "$RECORD_FILE" ]]; then
    PTH_IN_RECORD=$(grep "\.pth," "$RECORD_FILE" 2>/dev/null || true)
    if [[ -n "$PTH_IN_RECORD" ]]; then
        log_finding "CRITICAL" ".pth file is registered in RECORD (auto-executes on Python start)" \
            "$(echo "$PTH_IN_RECORD" | head -3)"
    fi
    # Unexpectedly large files in RECORD
    while IFS=',' read -r fname sha size; do
        size_clean=$(echo "$size" | tr -d '[:space:]')
        if [[ "$size_clean" =~ ^[0-9]+$ ]] && [[ "$size_clean" -gt 100000 ]]; then
            log_finding "MEDIUM" "Unusually large file in RECORD ($size_clean bytes)" \
                "$fname — verify this file is expected"
        fi
    done < "$RECORD_FILE"
fi

# __init__.py with encoded content
INIT_FILES=$(find "$EXTRACT_DIR" -name "__init__.py")
while IFS= read -r init; do
    if grep -qE "exec\(|eval\(|base64\.b64decode\s*\(" "$init" 2>/dev/null; then
        log_finding "HIGH" "__init__.py contains exec/eval/base64 decode" \
            "$(basename "$(dirname "$init")")/__init__.py runs on import"
    fi
done <<< "$INIT_FILES"

# ─────────────────────────────────────────────────────────────────────────────
#  REPORT
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
    echo -e "  This does not guarantee the package is safe — manual review of"
    echo -e "  any .pth files and setup hooks is always recommended.\n"
elif [[ $CRITICAL -gt 0 ]]; then
    echo -e "  ${BRED}⛔  DO NOT USE THIS PACKAGE.${RESET}"
    echo -e "  Critical indicators of a supply chain attack were detected."
    echo -e "  If installed: rotate ALL secrets, SSH keys, cloud credentials"
    echo -e "  and API tokens immediately.\n"
elif [[ $HIGH -gt 0 ]]; then
    echo -e "  ${RED}⚠  HIGH-RISK findings detected.${RESET}"
    echo -e "  Do not install until findings are manually verified.\n"
else
    echo -e "  ${YELLOW}⚠  Low/medium concerns only — manual review recommended.${RESET}\n"
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
    echo -e "  1. pip show $PKG_NAME"
    echo -e "  2. Check %%APPDATA%%\\Python\\site-packages\\ for .pth files"
    echo -e "  3. pip download \"$PKG_SPEC\" --no-deps -d C:\\Temp\\pkg_check"
else
    echo -e "  1. python3 -m pip show $PKG_NAME"
    echo -e "  2. find \$(python3 -c 'import site; print(site.getsitepackages()[0])') -name '*.pth'"
    echo -e "  3. pip3 download \"$PKG_SPEC\" --no-deps -d /tmp/pkg_check"
fi
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  Scan complete. Temp files cleaned up automatically."
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"