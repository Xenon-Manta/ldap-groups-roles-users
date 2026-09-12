#!/usr/bin/env python3
"""
rbac_fs.py — Filesystem structure and access control provisioner for Saffell-Soft.

Creates and enforces shared folder structures and access controls for the
Employee, Manager, and Board LDAP/local groups defined in rbac.json.

Folder layout
─────────────
/srv/saffell-soft/
├── employee/
│   ├── shared/       Employee rw  |  Manager rw  |  Board r
│   └── projects/     Employee rw  |  Manager rw  |  Board r
├── manager/
│   ├── shared/       Manager rw   |  Board r
│   └── reports/      Manager rw   |  Board r
└── board/
    └── workspace/    Board rw

Access model
────────────
  Employee  — read/write own folders; read manager + board folders: NO access.
              Sudo: safe shell commands + OpenOffice (soffice) only.
  Manager   — read/write employee + manager folders; read board: NO access.
              Sudo: near-full admin (ALL=(ALL) ALL) — already set by rbac_sync.py.
  Board     — read-only on employee + manager folders; read/write board folder.
              Access to board/workspace is granted via direct group membership
              (chmod 2770, group=Board) — no sudo rules required.

Implementation
──────────────
  • POSIX permissions + setgid bit keep new files group-owned.
  • POSIX ACLs (setfacl) layer cross-group read grants.
  • /etc/sudoers.d/rbac_fs_* files enforce per-group command allowlists.

Must be run as root.

Usage:
    sudo python3 rbac_fs.py [--dry-run] [--verbose]

Dependencies: Python 3.8+, acl package (setfacl/getfacl), standard library only.

-Rob Saffell
"""

import argparse
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path("/srv/saffell-soft")

# (path_relative_to_BASE_DIR, owning_group, dir_mode)
# Mode 2770 = setgid + rwxrwx--- (group rw, others none)
# Mode 2750 = setgid + rwxr-x--- (group read-only for non-owners via ACL)
FOLDER_SPEC = [
    # Employee folders — primary group: Employee
    ("employee/shared",    "Employee", 0o2770),
    ("employee/projects",  "Employee", 0o2770),
    # Manager folders — primary group: Manager
    ("manager/shared",     "Manager",  0o2770),
    ("manager/reports",    "Manager",  0o2770),
    # Board folder — primary group: Board
    ("board/workspace",    "Board",    0o2770),
]

# ACL entries to layer on top of POSIX permissions.
# Format: (path_relative_to_BASE_DIR, acl_entry)
# 'default:' entries ensure newly created files/dirs inherit the ACL.
ACL_SPEC = [
    # Manager gets read+write on employee folders (already has rw via Employee
    # group membership in rbac.json, but explicit ACL makes it declarative)
    ("employee/shared",   "group:Manager:rwx"),
    ("employee/shared",   "default:group:Manager:rwx"),
    ("employee/projects", "group:Manager:rwx"),
    ("employee/projects", "default:group:Manager:rwx"),

    # Board gets read-only on employee folders
    ("employee/shared",   "group:Board:r-x"),
    ("employee/shared",   "default:group:Board:r-x"),
    ("employee/projects", "group:Board:r-x"),
    ("employee/projects", "default:group:Board:r-x"),

    # Board gets read-only on manager folders
    ("manager/shared",    "group:Board:r-x"),
    ("manager/shared",    "default:group:Board:r-x"),
    ("manager/reports",   "group:Board:r-x"),
    ("manager/reports",   "default:group:Board:r-x"),
]

# ---------------------------------------------------------------------------
# Sudoers configuration
# ---------------------------------------------------------------------------

SUDOERS_DIR = Path("/etc/sudoers.d")

# Employee: safe shell commands + OpenOffice only. No su, no passwd, no chmod,
# no chown, no package managers, no network tools that bypass controls.
EMPLOYEE_ALLOWED_CMDS = [
    "/bin/ls",
    "/bin/cat",
    "/bin/cp",
    "/bin/mv",
    "/bin/mkdir",
    "/bin/rmdir",
    "/bin/rm",
    "/usr/bin/less",
    "/bin/grep",
    "/usr/bin/find",
    "/bin/nano",
    "/usr/bin/nano",
    "/usr/bin/soffice",          # OpenOffice / LibreOffice
    "/usr/bin/libreoffice",
    "/usr/bin/ooffice",
    "/usr/bin/wc",
    "/usr/bin/sort",
    "/usr/bin/diff",
    "/usr/bin/head",
    "/usr/bin/tail",
    "/usr/bin/file",
    "/usr/bin/stat",
    "/usr/bin/du",
    "/usr/bin/df",
    "/bin/date",
    "/usr/bin/id",
    "/usr/bin/whoami",
    "/usr/bin/pwd",
    "/usr/bin/echo",
]

# Board: read-only on Employee/Manager folders; read+write in Board folders.
# No sudo rules needed — access to board/workspace is granted directly via
# group membership (chmod 2770, group=Board). The OS enforces that Board
# members cannot write to Employee or Manager folders (group ACLs: r-x only).

# Sudoers drop-in filenames (written to /etc/sudoers.d/)
# Board is intentionally absent — their access is purely via group membership.
SUDOERS_FILES = {
    "Employee": "rbac_fs_employee",
}

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
# Safe command runner (mirrors pattern in rbac_sync.py)
# ---------------------------------------------------------------------------

def run(cmd: List[str], dry_run: bool = False, capture: bool = False) -> subprocess.CompletedProcess:
    safe_cmd = " ".join(cmd)
    log.debug("CMD: %s", safe_cmd)
    if dry_run:
        log.info("[dry-run] would run: %s", safe_cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    result = subprocess.run(cmd, capture_output=capture, text=True)
    if result.returncode != 0:
        log.error("Command failed (exit %d): %s", result.returncode, safe_cmd)
        if capture and result.stderr:
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
    """Return True if setfacl is available on this system."""
    result = subprocess.run(
        ["which", "setfacl"], capture_output=True, text=True
    )
    return result.returncode == 0


def group_exists(name: str) -> bool:
    result = subprocess.run(
        ["getent", "group", name], capture_output=True, text=True
    )
    return result.returncode == 0


def warn_missing_groups() -> None:
    for group in ["Employee", "Manager", "Board"]:
        if not group_exists(group):
            log.warning(
                "Group '%s' does not exist on this system. "
                "Run rbac_sync.py first to create groups and users.",
                group,
            )


# ---------------------------------------------------------------------------
# Folder creation and ownership
# ---------------------------------------------------------------------------

def provision_folder(
    rel_path: str,
    group: str,
    mode: int,
    dry_run: bool,
) -> None:
    """Create a folder, set group ownership and permissions."""
    path = BASE_DIR / rel_path

    if not path.exists():
        log.info("Creating directory: %s", path)
        if not dry_run:
            path.mkdir(parents=True, exist_ok=True)
    else:
        log.debug("Directory already exists: %s", path)

    # Owner = root, group = owning group
    log.info("Setting ownership root:%s on %s", group, path)
    run(["chown", f"root:{group}", str(path)], dry_run)

    # Set mode (includes setgid bit).
    # oct() produces '0o2770' — strip the '0o' prefix so chmod sees '2770'.
    octal_str = oct(mode)[2:]
    log.info("Setting mode %s on %s", octal_str, path)
    run(["chmod", octal_str, str(path)], dry_run)


def provision_all_folders(dry_run: bool) -> None:
    log.info("── Provisioning folder structure under %s ──", BASE_DIR)

    # Ensure base dir exists, owned root:root, traversable
    if not BASE_DIR.exists():
        log.info("Creating base directory: %s", BASE_DIR)
        if not dry_run:
            BASE_DIR.mkdir(parents=True, exist_ok=True)
    run(["chown", "root:root", str(BASE_DIR)], dry_run)
    run(["chmod", "755", str(BASE_DIR)], dry_run)

    # Create each group's parent directory (employee/, manager/, board/)
    for parent in ["employee", "manager", "board"]:
        parent_path = BASE_DIR / parent
        if not parent_path.exists():
            log.info("Creating parent directory: %s", parent_path)
            if not dry_run:
                parent_path.mkdir(parents=True, exist_ok=True)
        run(["chown", "root:root", str(parent_path)], dry_run)
        run(["chmod", "755", str(parent_path)], dry_run)

    for rel_path, group, mode in FOLDER_SPEC:
        provision_folder(rel_path, group, mode, dry_run)


# ---------------------------------------------------------------------------
# POSIX ACL provisioning
# ---------------------------------------------------------------------------

def apply_acl(path: Path, acl_entry: str, dry_run: bool) -> None:
    """Apply a single setfacl entry to a path."""
    log.info("setfacl -m %s %s", acl_entry, path)
    run(["setfacl", "-m", acl_entry, str(path)], dry_run)


def provision_all_acls(dry_run: bool) -> None:
    log.info("── Applying POSIX ACLs ──")
    for rel_path, acl_entry in ACL_SPEC:
        path = BASE_DIR / rel_path
        if not path.exists() and not dry_run:
            log.warning("Path does not exist, skipping ACL: %s", path)
            continue
        apply_acl(path, acl_entry, dry_run)


# ---------------------------------------------------------------------------
# Sudoers provisioning
# ---------------------------------------------------------------------------

def _validate_cmd_path(cmd: str) -> bool:
    """Reject paths with shell metacharacters or traversal sequences."""
    return bool(re.match(r"^/[a-zA-Z0-9_/\-\.]+$", cmd)) and ".." not in cmd


def build_sudoers_content(group: str, allowed_cmds: List[str], nopasswd: bool = True) -> str:
    """
    Build the content of a sudoers drop-in for a group.
    Each command is listed on its own line for clarity and easy auditing.
    """
    passwd_flag = "NOPASSWD: " if nopasswd else ""
    lines = [
        "# Managed by rbac_fs.py — do not edit manually",
        f"# Group: {group} — allowed commands",
        "#",
        "# Format: %group ALL=(ALL) NOPASSWD: /path/to/cmd",
        "",
    ]
    for cmd in allowed_cmds:
        if not _validate_cmd_path(cmd):
            log.warning("Skipping invalid command path in sudoers spec: %s", cmd)
            continue
        lines.append(f"%{group} ALL=(ALL) {passwd_flag}{cmd}")
    lines.append("")
    return "\n".join(lines)


def write_sudoers_file(filename: str, content: str, dry_run: bool) -> None:
    path = SUDOERS_DIR / filename
    if dry_run:
        log.info("[dry-run] would write sudoers file %s:\n%s", path, content)
        return
    path.write_text(content)
    path.chmod(0o440)
    log.info("Wrote sudoers file: %s", path)


def provision_sudoers(dry_run: bool) -> None:
    log.info("── Provisioning sudoers rules ──")

    if not SUDOERS_DIR.exists():
        log.error("%s does not exist — cannot write sudoers files.", SUDOERS_DIR)
        return

    # Employee: restricted allowlist
    employee_content = build_sudoers_content(
        group="Employee",
        allowed_cmds=EMPLOYEE_ALLOWED_CMDS,
        nopasswd=True,
    )
    write_sudoers_file(SUDOERS_FILES["Employee"], employee_content, dry_run)

    # Manager: near-full admin — written by rbac_sync.py (ALL=(ALL) ALL).
    # We log a note here for auditability but don't overwrite rbac_sync's file.
    log.info(
        "Manager sudo rules (ALL=(ALL) ALL) are managed by rbac_sync.py — skipping."
    )

    # Board: no sudoers entry. Board members get read/write on board/workspace
    # directly via group membership (chmod 2770, group=Board). Read-only access
    # to employee/manager folders is enforced by POSIX ACLs (r-x entries).


# ---------------------------------------------------------------------------
# Summary report
# ---------------------------------------------------------------------------

def print_summary(acl_available: bool) -> None:
    log.info("")
    log.info("════════════════════════════════════════════")
    log.info("  Saffell-Soft filesystem layout summary")
    log.info("════════════════════════════════════════════")
    log.info("")
    log.info("  /srv/saffell-soft/")
    log.info("  ├── employee/")
    log.info("  │   ├── shared/     Employee:rw  Manager:rw  Board:r")
    log.info("  │   └── projects/   Employee:rw  Manager:rw  Board:r")
    log.info("  ├── manager/")
    log.info("  │   ├── shared/     Manager:rw              Board:r")
    log.info("  │   └── reports/    Manager:rw              Board:r")
    log.info("  └── board/")
    log.info("      └── workspace/  Board:rw")
    log.info("")
    log.info("  Sudoers drop-ins:")
    log.info("    /etc/sudoers.d/rbac_fs_employee  — safe cmds + soffice")
    log.info("    Manager rules managed by rbac_sync.py (ALL=(ALL) ALL)")
    log.info("    Board — no sudoers entry; rw via group membership on board/workspace")
    log.info("")
    if not acl_available:
        log.warning(
            "  setfacl not found — ACLs were NOT applied. "
            "Install the 'acl' package and re-run."
        )
    log.info("════════════════════════════════════════════")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Provision shared folder structure and access controls "
            "for Employee, Manager, and Board groups."
        )
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

    # Check for groups; warn but don't abort — folders can be pre-created
    warn_missing_groups()

    # Check ACL tooling
    acl_available = check_setfacl_available()
    if not acl_available:
        log.warning(
            "setfacl not found. Install the 'acl' package to enable POSIX ACLs: "
            "sudo apt install acl"
        )

    # 1. Create folder structure
    provision_all_folders(args.dry_run)

    # 2. Apply POSIX ACLs (cross-group read access)
    if acl_available:
        provision_all_acls(args.dry_run)
    else:
        log.warning("Skipping ACL provisioning — setfacl unavailable.")

    # 3. Write sudoers allowlists
    provision_sudoers(args.dry_run)

    # 4. Print layout summary
    print_summary(acl_available)

    log.info("Done.")


if __name__ == "__main__":
    main()
