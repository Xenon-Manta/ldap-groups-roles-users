#!/usr/bin/env bash
# ==============================================================================
# user-permissions-report.sh
#
# Produces a recursive permission report for every user defined in rbac.json.
# For each user the report shows:
#   - Identity: uid, display name, tier, expected and actual group memberships
#   - Group validation: pass/fail for each expected group
#   - Filesystem access: effective rwx on every path under /srv/saffell-soft
#     (base_dir from posix_rules.json) and /var/log, tested via sudo -u
#   - ACL snapshot: getfacl output for each managed directory
#
# Usage:
#   sudo ./user-permissions-report.sh [OPTIONS]
#
# Options:
#   --config  PATH   Path to rbac.json        (default: ./rbac.json)
#   --rules   PATH   Path to posix_rules.json  (default: ./posix_rules.json)
#   --path    PATH   Override the audit root   (default: base_dir from rules)
#   --no-acl         Skip getfacl output
#   --help           Show this message
#
# Requirements:
#   jq       (apt install jq)
#   acl      (apt install acl)   — for getfacl; skipped if absent
#   root / sudo access to test other users' permissions
#
# -Rob Saffell
# ==============================================================================

set -uo pipefail

# ------------------------------------------------------------------------------
# Argument parsing
# ------------------------------------------------------------------------------

JSON_FILE="$(pwd)/rbac.json"
RULES_FILE="$(pwd)/posix_rules.json"
OVERRIDE_PATH=""
SKIP_ACL=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)  JSON_FILE="$2";    shift 2 ;;
        --rules)   RULES_FILE="$2";   shift 2 ;;
        --path)    OVERRIDE_PATH="$2"; shift 2 ;;
        --no-acl)  SKIP_ACL=1;        shift   ;;
        --help)
            sed -n '2,/^# =\+$/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1  (use --help for usage)" >&2
            exit 1
            ;;
    esac
done

# ------------------------------------------------------------------------------
# Prerequisite checks
# ------------------------------------------------------------------------------

fail() { echo "ERROR: $*" >&2; exit 1; }

[[ -f "$JSON_FILE" ]]  || fail "rbac.json not found: $JSON_FILE"
[[ -f "$RULES_FILE" ]] || fail "posix_rules.json not found: $RULES_FILE"

command -v jq       >/dev/null 2>&1 || fail "jq is required (apt install jq)"
command -v realpath >/dev/null 2>&1 || fail "realpath is required (coreutils)"

if [[ $EUID -ne 0 ]]; then
    echo "WARNING: Not running as root — sudo -u tests may fail for some users."
    echo "         Run with sudo for accurate results."
    echo
fi

GETFACL_BIN=""
if [[ $SKIP_ACL -eq 0 ]]; then
    if command -v getfacl >/dev/null 2>&1; then
        GETFACL_BIN=$(command -v getfacl)
    else
        echo "WARNING: getfacl not found — ACL snapshots will be skipped (apt install acl)."
        echo
        SKIP_ACL=1
    fi
fi

# ------------------------------------------------------------------------------
# Resolve audit paths from posix_rules.json
# ------------------------------------------------------------------------------

# Read base_dir from posix_rules.json
BASE_DIR=$(jq -r '.base_dir' "$RULES_FILE")
[[ -n "$BASE_DIR" && "$BASE_DIR" != "null" ]] || fail "base_dir not set in posix_rules.json"

# Paths to audit: base_dir subfolders + /var/log (for 3PAO)
# Build the list from posix_rules.json folders and external_acls
mapfile -t AUDIT_PATHS < <(
    # All managed subfolders under base_dir
    jq -r '.folders[].path' "$RULES_FILE" | sed "s|^|${BASE_DIR}/|"
    # External paths (e.g. /var/log)
    jq -r '.external_acls[]? | select(.entry | test("^(group|user):")) | .path' "$RULES_FILE" \
        | sort -u
)

# If caller passed --path, override the list with a recursive walk of that path
if [[ -n "$OVERRIDE_PATH" ]]; then
    OVERRIDE_PATH=$(realpath "$OVERRIDE_PATH")
    [[ -d "$OVERRIDE_PATH" ]] || fail "Override path is not a directory: $OVERRIDE_PATH"
    mapfile -t AUDIT_PATHS < <(find "$OVERRIDE_PATH" -mindepth 0 -print 2>/dev/null)
fi

# ------------------------------------------------------------------------------
# Helper: test effective permissions for a user on a path
# Returns a 3-char string: r/-, w/-, x/-
# Uses sudo -u so the test runs with that user's actual credentials.
# -n (non-interactive) prevents password prompts; if the user has no
# passwordless sudo configured the test returns "???" to flag the gap.
# ------------------------------------------------------------------------------

check_permissions() {
    local user="$1"
    local path="$2"

    # Verify sudo -n works for this user at all
    if ! sudo -n -u "$user" true 2>/dev/null; then
        echo "???"
        return
    fi

    local r="-" w="-" x="-"
    sudo -n -u "$user" test -r "$path" 2>/dev/null && r="r"
    sudo -n -u "$user" test -w "$path" 2>/dev/null && w="w"
    # -x on a directory means traversable; on a file means executable
    sudo -n -u "$user" test -x "$path" 2>/dev/null && x="x"

    echo "${r}${w}${x}"
}

# ------------------------------------------------------------------------------
# Helper: Labeled tiers so ourput makes sense
# ------------------------------------------------------------------------------

tier_label() {
    local raw="$1"
    case "$raw" in
        1)    echo "Tier 1 — Employee" ;;
        2)    echo "Tier 2 — Manager (inherits Employee)" ;;
        3)    echo "Tier 3 — Board (inherits Employee + Manager)" ;;
        flat) echo "Flat — 3PAO (no inheritance)" ;;
        *)    echo "$raw" ;;
    esac
}

# ------------------------------------------------------------------------------
# Report header
# ------------------------------------------------------------------------------

echo "============================================================"
echo " User Permission Report — Saffell-Soft RBAC"
echo "============================================================"
echo "RBAC file   : $JSON_FILE"
echo "Rules file  : $RULES_FILE"
echo "Audit paths : ${#AUDIT_PATHS[@]} managed paths"
echo "Generated   : $(date)"
echo "Host        : $(hostname)"
echo "============================================================"

# ------------------------------------------------------------------------------
# Per-user report begins here - future, output this into a PDF using PyPDF
# ------------------------------------------------------------------------------

while IFS= read -r user; do

    common_name=$(jq -r --arg u "$user" \
        '.users[] | select(.uid == $u) | .common_name // "(no name)"' \
        "$JSON_FILE")

    raw_tier=$(jq -r --arg u "$user" \
        '.users[] | select(.uid == $u) | ._tier // "unknown"' \
        "$JSON_FILE")

    tier=$(tier_label "$raw_tier")

    expected_groups=$(jq -r --arg u "$user" \
        '.users[] | select(.uid == $u) | .groups | join(", ")' \
        "$JSON_FILE")

    echo
    echo "################################################################"
    printf " USER : %s\n" "$user"
    printf " Name : %s\n" "$common_name"
    printf " Tier : %s\n" "$tier"
    echo "################################################################"

    # ------------------------------------------------------------------
    # Account existence check
    # ------------------------------------------------------------------

    if ! getent passwd "$user" >/dev/null 2>&1; then
        echo " STATUS : NOT FOUND — user does not exist on this system"
        echo "          Create with: sudo python3 rbac_sync.py"
        continue
    fi

    actual_groups=$(id -nG "$user" 2>/dev/null | tr ' ' ', ')
    echo " Expected groups : $expected_groups"
    echo " Actual groups   : $actual_groups"

    # ------------------------------------------------------------------
    # Group membership validation
    # ------------------------------------------------------------------

    echo
    echo " Group membership:"

    pass_count=0
    fail_count=0

    while IFS= read -r grp; do
        if id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -Fxq "$grp"; then
            printf "   [PASS] %s\n" "$grp"
            (( pass_count++ )) || true
        else
            printf "   [FAIL] %s  ← user is NOT a member\n" "$grp"
            (( fail_count++ )) || true
        fi
    done < <(jq -r --arg u "$user" \
        '.users[] | select(.uid == $u) | .groups[]' \
        "$JSON_FILE")

    printf "   Summary: %d passed, %d failed\n" "$pass_count" "$fail_count"

    # ------------------------------------------------------------------
    # Sudo rule check - Future, add a specific list of accessible elevated binaries
    # ------------------------------------------------------------------

    echo
    echo " Sudo rules:"
    sudo_rules=$(jq -r --arg u "$user" \
        '.users[] | select(.uid == $u) | .sudo_rules[]?' \
        "$JSON_FILE")

    if [[ -z "$sudo_rules" ]]; then
        echo "   (none defined in rbac.json)"
    else
        while IFS= read -r rule; do
            printf "   %s\n" "$rule"
        done <<< "$sudo_rules"
    fi

    # Check if user is in any privileged system group (should not be for
    # Employee, Board, 3PAO)
    priv_membership=$(id -nG "$user" 2>/dev/null | tr ' ' '\n' | \
        grep -E '^(sudo|wheel|admin)$' || true)
    if [[ -n "$priv_membership" ]]; then
        echo "   [WARN] User is in privileged system group(s): $priv_membership"
        echo "          Run rbac_sync.py to strip these."
    fi

    # ------------------------------------------------------------------
    # Filesystem permission enumeration
    # ------------------------------------------------------------------

    echo
    echo " Filesystem access:"
    printf "   %-5s %-12s %-18s %-18s %s\n" \
        "EFF" "MODE" "OWNER:GROUP" "ACL-MASK" "PATH"
    printf "   %-5s %-12s %-18s %-18s %s\n" \
        "-----" "------------" "------------------" "------------------" "----"

    for path in "${AUDIT_PATHS[@]}"; do

        [[ -e "$path" ]] || continue

        effective=$(check_permissions "$user" "$path")
        mode=$(stat  -c '%A'   "$path" 2>/dev/null || echo "?")
        owner=$(stat -c '%U'   "$path" 2>/dev/null || echo "?")
        grp=$(stat   -c '%G'   "$path" 2>/dev/null || echo "?")

        # Get ACL mask if getfacl available
        acl_mask="-"
        if [[ -n "$GETFACL_BIN" ]]; then
            acl_mask=$("$GETFACL_BIN" --omit-header "$path" 2>/dev/null \
                | grep '^mask::' | cut -d: -f3 || echo "-")
            [[ -z "$acl_mask" ]] && acl_mask="-"
        fi

        # Flag unexpected access
        flag=""
        if [[ "$effective" == "???" ]]; then
            flag="  ← sudo test unavailable"
        elif [[ "$effective" == "rw-" || "$effective" == "rwx" ]]; then
            # Check if this user should have write here per rbac.json tier
            case "$raw_tier" in
                1) # Employee — only own folders are rw
                   if [[ "$path" != *"/employee/"* ]]; then
                       flag="  ← [WARN] write access outside employee scope"
                   fi
                   ;;
                flat) # 3PAO — should never have write anywhere
                   if [[ "$effective" == *"w"* ]]; then
                       flag="  ← [WARN] 3PAO should not have write access"
                   fi
                   ;;
            esac
        fi

        printf "   %-5s %-12s %-18s %-18s %s%s\n" \
            "$effective" \
            "$mode" \
            "${owner}:${grp}" \
            "$acl_mask" \
            "$path" \
            "$flag"

    done

    # ------------------------------------------------------------------
    # ACL snapshot for managed directories
    # ------------------------------------------------------------------

    if [[ $SKIP_ACL -eq 0 ]]; then
        echo
        echo " ACL snapshot (getfacl):"
        for path in "${AUDIT_PATHS[@]}"; do
            [[ -d "$path" ]] || continue
            [[ -e "$path" ]] || continue
            echo
            echo "   --- $path ---"
            "$GETFACL_BIN" --omit-header "$path" 2>/dev/null \
                | sed 's/^/   /' \
                || echo "   (getfacl failed)"
        done
    fi

    echo
    echo " Permission key:"
    echo "   r = read access    w = write access"
    echo "   x = execute/traverse (directories: traverse into)"
    echo "   - = permission denied    ??? = sudo test unavailable for this user"

done < <(jq -r '.users[].uid' "$JSON_FILE")

echo
echo "============================================================"
echo " Report complete"
echo "============================================================"
