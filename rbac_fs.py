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
  Employee  — read/write own folders (employee/shared, employee/projects).
              NO sudo access — explicit !ALL deny written to /etc/sudoers.d/.
              NO access to manager/ or board/ — parent dirs are mode 0o750
              owned by Manager/Board groups; Employee members are "others"
              and receive --- (no traverse, no list, no read).
  Manager   — read/write employee + manager folders; read board: NO access.
              Sudo: near-full admin (ALL=(ALL) ALL) — already set by rbac_sync.py.
  Board     — read-only on employee + manager folders; read/write board folder.
              NO sudo access — explicit !ALL deny written to /etc/sudoers.d/.
              Access to board/workspace is via direct group membership (chmod 2770).

Implementation
──────────────
  • POSIX permissions + setgid bit keep new files group-owned.
  • POSIX ACLs (setfacl) layer cross-group read grants.
  • /etc/sudoers.d/00_rbac_deny_* hard-deny sudo for Employee and Board.

Must be run as root.

Usage:
    sudo python3 rbac_fs.py [--dry-run] [--verbose]

Dependencies: Python 3.8+, acl package (setfacl/getfacl), standard library only.

-Rob Saffell
"""

import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import List

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path("/srv/saffell-soft")

# (path_relative_to_BASE_DIR, owning_group, dir_mode)
#
# Mode 2770 = setgid + rwxrws---  owning group: full read/write, others: none
# Mode 2750 = setgid + rwxr-s---  owning group: read-only,       others: none
#
# Parent directories (employee/, manager/, board/) use mode 0o710:
#   - root can traverse
#   - owning group can traverse (x bit) but cannot list contents (no r)
#   - others: no access at all
# This prevents Employee members from even traversing into manager/ or board/.
FOLDER_SPEC = [
    # Employee folders — group: Employee, full rw
    ("employee/shared",    "Employee", 0o2770),
    ("employee/projects",  "Employee", 0o2770),
    # Manager folders — group: Manager, full rw; Employee has no entry here
    ("manager/shared",     "Manager",  0o2770),
    ("manager/reports",    "Manager",  0o2770),
    # Board folder — group: Board, full rw; Employee has no entry here
    ("board/workspace",    "Board",    0o2770),
]

# Parent directory modes: (relative_path, owning_group, mode)
# 0o750 = rwxr-x---  owning group can traverse; others blocked entirely.
# Employee is not in the Manager or Board groups, so they are in "others"
# and get --- on manager/ and board/ — no traversal, no listing, no access.
PARENT_SPEC = [
    ("employee", "Employee", 0o750),
    ("manager",  "Manager",  0o750),
    ("board",    "Board",    0o750),
]

# ACL entries to layer on top of POSIX permissions.
# Format: (path_relative_to_BASE_DIR, acl_entry)
# 'default:' entries ensure newly created files/subdirs inherit the ACL.
#
# Employee is NOT granted any ACL entry on manager/ or board/ folders.
# Those parent dirs are owned by their respective groups with mode 0o750,
# so Employee members (who are in "others") get --- and cannot traverse in.
ACL_SPEC = [
    # -----------------------------------------------------------------------
    # Employee folders
    # default:group:Employee:rwx  — new files/dirs created inside inherit
    #                               group-write so all Employee members can
    #                               read and write each other's files.
    # default:mask::rwx           — ensures the ACL mask doesn't strip the
    #                               group write bit that the default entries grant.
    # -----------------------------------------------------------------------
    ("employee/shared",   "group:Employee:rwx"),
    ("employee/shared",   "default:group:Employee:rwx"),
    ("employee/shared",   "default:mask::rwx"),
    ("employee/projects", "group:Employee:rwx"),
    ("employee/projects", "default:group:Employee:rwx"),
    ("employee/projects", "default:mask::rwx"),

    # Manager gets read+write on employee folders via explicit ACL
    ("employee/shared",   "group:Manager:rwx"),
    ("employee/shared",   "default:group:Manager:rwx"),
    ("employee/projects", "group:Manager:rwx"),
    ("employee/projects", "default:group:Manager:rwx"),

    # Board gets read-only on employee folders
    ("employee/shared",   "group:Board:r-x"),
    ("employee/shared",   "default:group:Board:r-x"),
    ("employee/projects", "group:Board:r-x"),
    ("employee/projects", "default:group:Board:r-x"),

    # -----------------------------------------------------------------------
    # Manager folders — default ACL so new files are group-writable
    # -----------------------------------------------------------------------
    ("manager/shared",    "group:Manager:rwx"),
    ("manager/shared",    "default:group:Manager:rwx"),
    ("manager/shared",    "default:mask::rwx"),
    ("manager/reports",   "group:Manager:rwx"),
    ("manager/reports",   "default:group:Manager:rwx"),
    ("manager/reports",   "default:mask::rwx"),

    # Board gets read-only on manager folders
    ("manager/shared",    "group:Board:r-x"),
    ("manager/shared",    "default:group:Board:r-x"),
    ("manager/reports",   "group:Board:r-x"),
    ("manager/reports",   "default:group:Board:r-x"),

    # -----------------------------------------------------------------------
    # Board folder — default ACL so new files are group-writable
    # -----------------------------------------------------------------------
    ("board/workspace",   "group:Board:rwx"),
    ("board/workspace",   "default:group:Board:rwx"),
    ("board/workspace",   "default:mask::rwx"),

    # -----------------------------------------------------------------------
    # Explicit deny for Employee on manager and board subfolders
    # Belt-and-suspenders on top of the parent dir mode 0o750
    # -----------------------------------------------------------------------
    ("manager/shared",    "group:Employee:---"),
    ("manager/shared",    "default:group:Employee:---"),
    ("manager/reports",   "group:Employee:---"),
    ("manager/reports",   "default:group:Employee:---"),
    ("board/workspace",   "group:Employee:---"),
    ("board/workspace",   "default:group:Employee:---"),
]

# ---------------------------------------------------------------------------
# Sudoers hardening — deny sudo for Employee and Board entirely
#
# Neither Employee nor Board should have any sudo access. Writing explicit
# deny drop-ins (using !ALL) to /etc/sudoers.d/ ensures this holds even if
# another rule or package install accidentally grants access later.
#
# sudoers precedence: later files override earlier ones, BUT explicit !ALL
# deny rules in a named drop-in act as a hard block that cannot be
# overridden by earlier wildcard grants in the same parse order.
#
# File naming: prefixed with '00_' so they sort first and establish the
# deny baseline before any other drop-ins are evaluated.
# ---------------------------------------------------------------------------

SUDOERS_DIR = Path("/etc/sudoers.d")

SUDO_DENY_FILES = {
    "Employee": "00_rbac_deny_employee",
    "Board":    "00_rbac_deny_board",
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

    # Create each group's parent directory with restrictive permissions.
    # mode 0o750: owning group can traverse; others (incl. Employee on
    # manager/ and board/) are fully blocked — no listing, no traversal.
    for rel_parent, group, mode in PARENT_SPEC:
        parent_path = BASE_DIR / rel_parent
        if not parent_path.exists():
            log.info("Creating parent directory: %s", parent_path)
            if not dry_run:
                parent_path.mkdir(parents=True, exist_ok=True)
        run(["chown", f"root:{group}", str(parent_path)], dry_run)
        run(["chmod", oct(mode)[2:], str(parent_path)], dry_run)

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
# Sudoers hardening
# ---------------------------------------------------------------------------

def write_sudoers_deny(group: str, filename: str, dry_run: bool) -> None:
    """
    Write a sudoers drop-in that explicitly denies all sudo access for group.
    The '!ALL' operator tells sudo to refuse every command for this group.
    Prefixed '00_' so it sorts and is parsed before any other drop-ins.
    """
    path = SUDOERS_DIR / filename
    content = "\n".join([
        "# Managed by rbac_fs.py — do not edit manually",
        f"# Explicit sudo deny for group: {group}",
        "# This group must not have sudo access of any kind.",
        "",
        f"%{group} ALL=(ALL) !ALL",
        "",
    ])

    if dry_run:
        log.info("[dry-run] would write sudoers deny file %s", path)
        return

    if not SUDOERS_DIR.exists():
        log.error("%s does not exist — cannot write sudoers files.", SUDOERS_DIR)
        return

    path.write_text(content)
    path.chmod(0o440)
    log.info("Wrote sudoers deny file: %s", path)


def remove_stale_employee_allowlist(dry_run: bool) -> None:
    """
    Remove any previously written Employee allowlist drop-in from earlier
    versions of this script so it cannot override the new deny rule.
    """
    stale = SUDOERS_DIR / "rbac_fs_employee"
    if stale.exists():
        log.info("Removing stale Employee sudoers allowlist: %s", stale)
        if not dry_run:
            stale.unlink()


def provision_sudoers(dry_run: bool) -> None:
    log.info("── Provisioning sudoers deny rules for Employee and Board ──")

    # Remove any leftover allowlist file from previous script versions
    remove_stale_employee_allowlist(dry_run)

    # Write hard deny for Employee
    write_sudoers_deny("Employee", SUDO_DENY_FILES["Employee"], dry_run)

    # Write hard deny for Board
    write_sudoers_deny("Board", SUDO_DENY_FILES["Board"], dry_run)

    # Manager: full admin — managed by rbac_sync.py, not touched here.
    log.info("Manager sudo rules (ALL=(ALL) ALL) are managed by rbac_sync.py — skipping.")


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
    log.info("  │   ├── shared/     Employee:rw  Manager:rw  Board:r  (others: no access)")
    log.info("  │   └── projects/   Employee:rw  Manager:rw  Board:r  (others: no access)")
    log.info("  ├── manager/        (mode 750, group=Manager — Employee blocked at dir level)")
    log.info("  │   ├── shared/     Manager:rw              Board:r  (Employee: ---)")
    log.info("  │   └── reports/    Manager:rw              Board:r  (Employee: ---)")
    log.info("  └── board/          (mode 750, group=Board   — Employee blocked at dir level)")
    log.info("      └── workspace/  Board:rw                         (Employee: ---)")
    log.info("")
    log.info("  Sudoers drop-ins:")
    log.info("    /etc/sudoers.d/00_rbac_deny_employee  — !ALL hard deny (no sudo)")
    log.info("    /etc/sudoers.d/00_rbac_deny_board     — !ALL hard deny (no sudo)")
    log.info("    Manager rules managed by rbac_sync.py (ALL=(ALL) ALL)")
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
