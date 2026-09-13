#!/usr/bin/env python3
"""
rbac_fs.py — Filesystem structure and access control provisioner for Saffell-Soft.

Reads posix_rules.json and provisions:
  - Parent directory structure with correct ownership and modes.
  - Shared subfolders with setgid and group ownership.
  - POSIX ACLs via setfacl for cross-group access grants and deny markers.
  - External ACLs on paths outside base_dir (e.g. /var/log for 3PAO read access).
  - Cleanup of stale sudoers drop-in files from previous script versions.

Permission model (from posix_rules.json _tier_model):
  Tier 1 — Employee  : rw on employee/shared, employee/projects
  Tier 2 — Manager   : inherits Tier 1 + rw on manager/shared, manager/reports
  Tier 3 — Board     : inherits Tier 1+2 + rw on board/workspace
  Flat   — 3PAO      : read-only on manager/reports and /var/log only (no inheritance)

All POSIX rules (folder layout, modes, ACL entries) are defined in
posix_rules.json — do not hardcode rules in this script.

Must be run as root.

Usage:
    sudo python3 rbac_fs.py [--rules posix_rules.json] [--dry-run] [--verbose]

Dependencies: Python 3.8+, acl package (setfacl), standard library only.

Open Features for Development:
 1. Add a React UI to manage groups and roles
 2. Encrypt and lock rbac.json / posix_rules.json
 3. Automatically escalate to sudo on run
 4. Add a switch for remote LDAP management using OpenLDAP

-Rob Saffell
"""

import argparse
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log = logging.getLogger("rbac_fs")


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(levelname)-8s %(message)s"))
    log.addHandler(handler)
    log.setLevel(level)


# ---------------------------------------------------------------------------
# Rules loader
# ---------------------------------------------------------------------------

def load_rules(path: str) -> Dict:
    rules_path = Path(path)
    if not rules_path.exists():
        log.error("Rules file not found: %s", path)
        sys.exit(1)
    with rules_path.open(encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as exc:
            log.error("Invalid JSON in %s: %s", path, exc)
            sys.exit(1)


def validate_rules(rules: Dict) -> None:
    """Abort early if required top-level keys are missing."""
    required = ["base_dir", "parent_dirs", "folders", "acls",
                "deny_groups", "sudo_controls"]
    missing = [k for k in required if k not in rules]
    if missing:
        log.error("posix_rules.json is missing required keys: %s", missing)
        sys.exit(1)
    # external_acls is optional — warn if absent so operators know 3PAO
    # /var/log access will not be provisioned.
    if "external_acls" not in rules:
        log.warning(
            "posix_rules.json has no 'external_acls' section — "
            "skipping external path ACLs (e.g. /var/log for 3PAO)."
        )


# ---------------------------------------------------------------------------
# Safe command runner
# ---------------------------------------------------------------------------

def run(cmd: List[str], dry_run: bool = False) -> subprocess.CompletedProcess:
    safe_cmd = " ".join(cmd)
    log.debug("CMD: %s", safe_cmd)
    if dry_run:
        log.info("[dry-run] would run: %s", safe_cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        log.error("Command failed (exit %d): %s", result.returncode, safe_cmd)
        if result.stderr:
            log.error("stderr: %s", result.stderr.strip())
    return result


# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------

def check_root() -> None:
    if os.geteuid() != 0:
        log.error("This script must be run as root (e.g. sudo python3 rbac_fs.py).")
        sys.exit(1)


def check_setfacl_available() -> bool:
    result = subprocess.run(["which", "setfacl"], capture_output=True, text=True)
    return result.returncode == 0


def group_exists(name: str) -> bool:
    result = subprocess.run(
        ["getent", "group", name], capture_output=True, text=True
    )
    return result.returncode == 0


def warn_missing_groups(rules: Dict) -> None:
    """Warn if any group referenced in rules does not exist on the system."""
    referenced = set()
    for folder in rules.get("folders", []):
        referenced.add(folder["group"])
    for parent in rules.get("parent_dirs", []):
        if parent["group"] != "root":
            referenced.add(parent["group"])
    for group in sorted(referenced):
        if not group_exists(group):
            log.warning(
                "Group '%s' does not exist on this system. "
                "Run rbac_sync.py first to create groups and users.",
                group,
            )


# ---------------------------------------------------------------------------
# Folder provisioning
# ---------------------------------------------------------------------------

def provision_base_dir(base_dir: Path, dry_run: bool) -> None:
    if not base_dir.exists():
        log.info("Creating base directory: %s", base_dir)
        if not dry_run:
            base_dir.mkdir(parents=True, exist_ok=True)
    run(["chown", "root:root", str(base_dir)], dry_run)
    run(["chmod", "755", str(base_dir)], dry_run)


def provision_parent_dirs(base_dir: Path, parent_dirs: List[Dict], dry_run: bool) -> None:
    log.info("── Provisioning parent directories ──")
    for entry in parent_dirs:
        path = base_dir / entry["path"]
        owner = entry["owner"]
        group = entry["group"]
        mode = entry["mode"]

        if not path.exists():
            log.info("Creating parent directory: %s", path)
            if not dry_run:
                path.mkdir(parents=True, exist_ok=True)
        else:
            log.debug("Parent directory already exists: %s", path)

        run(["chown", f"{owner}:{group}", str(path)], dry_run)
        log.info("Set ownership %s:%s on %s", owner, group, path)
        run(["chmod", mode, str(path)], dry_run)
        log.info("Set mode %s on %s", mode, path)


def provision_folders(base_dir: Path, folders: List[Dict], dry_run: bool) -> None:
    log.info("── Provisioning shared folders ──")
    for entry in folders:
        path = base_dir / entry["path"]
        owner = entry["owner"]
        group = entry["group"]
        mode = entry["mode"]

        if not path.exists():
            log.info("Creating directory: %s", path)
            if not dry_run:
                path.mkdir(parents=True, exist_ok=True)
        else:
            log.debug("Directory already exists: %s", path)

        run(["chown", f"{owner}:{group}", str(path)], dry_run)
        log.info("Set ownership %s:%s on %s", owner, group, path)
        run(["chmod", mode, str(path)], dry_run)
        log.info("Set mode %s on %s", mode, path)


# ---------------------------------------------------------------------------
# POSIX ACL provisioning
# ---------------------------------------------------------------------------

def provision_acls(base_dir: Path, acls: List[Dict], dry_run: bool) -> None:
    log.info("── Applying POSIX ACLs (base_dir paths) ──")
    for entry in acls:
        # Skip comment/section annotation keys that start with _
        if "entry" not in entry:
            continue
        path = base_dir / entry["path"]
        acl_entry = entry["entry"]

        if not path.exists():
            if not dry_run:
                log.warning("Path does not exist, skipping ACL (%s): %s", acl_entry, path)
                continue
        log.info("setfacl -m %s %s", acl_entry, path)
        run(["setfacl", "-m", acl_entry, str(path)], dry_run)


def provision_external_acls(external_acls: List[Dict], dry_run: bool) -> None:
    """
    Apply ACL entries on paths outside base_dir.

    These paths (e.g. /var/log) are managed by the OS — we only add ACL
    grant entries and never change ownership or mode. This gives 3PAO
    read access to system logs for compliance assessment without touching
    any saffell-soft managed directory.

    Each entry requires 'path' (absolute) and 'entry' (setfacl format).
    """
    log.info("── Applying POSIX ACLs (external paths) ──")
    for entry in external_acls:
        if "entry" not in entry:
            continue
        path = Path(entry["path"])
        acl_entry = entry["entry"]

        if not path.exists():
            log.warning(
                "External path does not exist, skipping ACL (%s): %s",
                acl_entry, path,
            )
            continue

        log.info("setfacl -m %s %s", acl_entry, path)
        run(["setfacl", "-m", acl_entry, str(path)], dry_run)


# ---------------------------------------------------------------------------
# Sudoers stale file cleanup
# ---------------------------------------------------------------------------

def cleanup_stale_sudoers(sudo_controls: Dict, dry_run: bool) -> None:
    """
    Remove stale sudoers drop-in files left by previous script versions
    that used the ineffective !ALL deny approach.

    Sudo access for Employee and Board is enforced by rbac_sync.py removing
    those users from sudo/wheel/admin system groups — not by drop-in files.
    """
    log.info("── Cleaning up stale sudoers drop-ins ──")
    sudoers_dir = Path("/etc/sudoers.d")
    stale_files = sudo_controls.get("stale_sudoers_files", [])

    if not sudoers_dir.exists():
        log.debug("%s does not exist — skipping sudoers cleanup.", sudoers_dir)
        return

    for filename in stale_files:
        path = sudoers_dir / filename
        if path.exists():
            log.info("Removing stale sudoers file: %s", path)
            if not dry_run:
                path.unlink()
        else:
            log.debug("Already clean — stale file not present: %s", path)

    log.info(
        "Sudo controls for Employee and Board are enforced by rbac_sync.py "
        "(strip_privileged_groups removes sudo/wheel/admin membership)."
    )


# ---------------------------------------------------------------------------
# Summary report
# ---------------------------------------------------------------------------

def print_summary(rules: Dict, acl_available: bool) -> None:
    base = rules["base_dir"]
    log.info("")
    log.info("════════════════════════════════════════════════════════")
    log.info("  Saffell-Soft filesystem layout  (rules: posix_rules.json)")
    log.info("════════════════════════════════════════════════════════")
    log.info("  Base: %s", base)

    # Tier model
    tier_model = rules.get("_tier_model", {})
    if tier_model:
        log.info("")
        log.info("  Permission tiers:")
        for tier in tier_model.get("tiers", []):
            inherits = ", ".join(tier["inherits_from"]) or "none"
            log.info("    Tier %s  %-10s  inherits: %-20s  own: %s",
                     tier["tier"], tier["group"], inherits,
                     ", ".join(tier["own_paths"]))
        for flat in tier_model.get("flat_roles", []):
            log.info("    Flat    %-10s  inherits: none  access: %s",
                     flat["group"], flat["access"])

    log.info("")
    log.info("  Parent directories:")
    for p in rules.get("parent_dirs", []):
        log.info("    %-20s  owner=%s:%s  mode=%s",
                 p["path"], p["owner"], p["group"], p["mode"])

    log.info("")
    log.info("  Shared folders:")
    for f in rules.get("folders", []):
        log.info("    %-30s  owner=%s:%s  mode=%s",
                 f["path"], f["owner"], f["group"], f["mode"])

    log.info("")
    acl_count = sum(1 for e in rules.get("acls", []) if "entry" in e)
    ext_count  = sum(1 for e in rules.get("external_acls", []) if "entry" in e)
    log.info("  ACL entries — base_dir: %d  external: %d", acl_count, ext_count)

    if rules.get("external_acls"):
        log.info("")
        log.info("  External ACLs (outside base_dir):")
        for e in rules["external_acls"]:
            if "entry" in e:
                log.info("    setfacl -m %-30s  %s", e["entry"], e["path"])

    log.info("")
    log.info("  Deny groups:")
    for grp, paths in rules.get("deny_groups", {}).items():
        if grp.startswith("_"):
            continue
        log.info("    %-20s  → %s", grp, ", ".join(paths))

    log.info("")
    sc = rules.get("sudo_controls", {})
    log.info("  Sudo controls:")
    log.info("    No-sudo RBAC groups : %s", sc.get("no_sudo_rbac_groups", []))
    log.info("    Enforced by         : rbac_sync.py strip_privileged_groups()")

    log.info("")
    if not acl_available:
        log.warning(
            "  setfacl not found — ACLs were NOT applied. "
            "Install the 'acl' package: sudo apt install acl"
        )
    log.info("════════════════════════════════════════════════════════")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Provision shared folder structure and POSIX access controls "
            "for Saffell-Soft groups, driven by posix_rules.json."
        )
    )
    parser.add_argument(
        "--rules",
        default="posix_rules.json",
        help="Path to the posix_rules.json file (default: posix_rules.json)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be done without making any changes.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug output.",
    )
    args = parser.parse_args()

    setup_logging(args.verbose)

    if args.dry_run:
        log.info("=== DRY RUN MODE — no changes will be made ===")
    else:
        check_root()

    rules = load_rules(args.rules)
    validate_rules(rules)

    base_dir = Path(rules["base_dir"])

    warn_missing_groups(rules)

    acl_available = check_setfacl_available()
    if not acl_available:
        log.warning(
            "setfacl not found. Install the 'acl' package: sudo apt install acl"
        )

    # 1. Base directory
    provision_base_dir(base_dir, args.dry_run)

    # 2. Parent directories (employee/, manager/, board/)
    provision_parent_dirs(base_dir, rules["parent_dirs"], args.dry_run)

    # 3. Shared subfolders
    provision_folders(base_dir, rules["folders"], args.dry_run)

    # 4. POSIX ACLs on base_dir paths
    if acl_available:
        provision_acls(base_dir, rules["acls"], args.dry_run)
    else:
        log.warning("Skipping ACL provisioning — setfacl unavailable.")

    # 5. External ACLs — paths outside base_dir (e.g. /var/log for 3PAO)
    if acl_available:
        external_acls = rules.get("external_acls", [])
        if external_acls:
            provision_external_acls(external_acls, args.dry_run)
        else:
            log.debug("No external_acls defined in rules — skipping.")
    
    # 6. Clean up stale sudoers files from previous script versions
    cleanup_stale_sudoers(rules["sudo_controls"], args.dry_run)

    # 7. Summary
    print_summary(rules, acl_available)

    log.info("Done.")


if __name__ == "__main__":
    main()
