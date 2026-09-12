#!/usr/bin/env python3
"""
rbac_sync.py — Local user and group RBAC management for Ubuntu.

Reads rbac.json and ensures the system state matches:
  - Groups are created if missing, updated if attributes differ.
  - Users are created if missing, updated if attributes differ.
  - Group memberships are reconciled to exactly match the spec.
  - Sudo rules for groups and users are written to /etc/sudoers.d/.

Must be run as root.

Usage:
    sudo python3 rbac_sync.py [--config rbac.json] [--dry-run] [--verbose]

Dependencies: Python 3.8+, standard library only (no pip installs required).

Open Features for Development: 
 1. Add a React UI to manage groups and role
 2. Encrypt and lock the rbac.json
 3. Automatically escalate to sudo on run
 4. Add a switch for remote LDAP management using OpenLDAP (including remote auth... etc)

Note: I went back and forth on password set feature and since it wasn't hardly any effort to add it, left it in as optional
-Rob Saffell
"""

import argparse
import json
import logging
import os
import pwd
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Set

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUDOERS_DIR = Path("/etc/sudoers.d")
RBAC_SUDOERS_PREFIX = "rbac_"  # all files we own are prefixed with this
DEFAULT_SHELL = "/bin/bash"
DEFAULT_HOME_BASE = "/home"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log = logging.getLogger("rbac_sync")


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(levelname)-8s %(message)s"))
    log.addHandler(handler)
    log.setLevel(level)


# ---------------------------------------------------------------------------
# Safe command runner
# ---------------------------------------------------------------------------

# Arguments that carry sensitive values and should be redacted in log output.
_REDACT_NEXT = {"--password", "-p"}


def _redact(cmd: List[str]) -> List[str]:
    """Return a copy of cmd with values after sensitive flags replaced by ****."""
    out = []
    redact_next = False
    for token in cmd:
        if redact_next:
            out.append("****")
            redact_next = False
        else:
            out.append(token)
            if token in _REDACT_NEXT:
                redact_next = True
    return out


def run(
    cmd: List[str],
    dry_run: bool = False,
    capture: bool = False,
) -> subprocess.CompletedProcess:
    """
    Run a system command.

    In dry-run mode the command is only logged, never executed.
    Sensitive flag values (e.g. --password) are redacted from log output.
    """
    safe_cmd = " ".join(_redact(cmd))
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
# System state helpers (always re-read from /etc/* to avoid stale caches)
# ---------------------------------------------------------------------------

def _run_getent(database: str, key: str) -> Optional[str]:
    """Query NSS via getent; returns the matching line or None."""
    result = subprocess.run(
        ["getent", database, key],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def group_exists(name: str) -> bool:
    return _run_getent("group", name) is not None


def user_exists(uid: str) -> bool:
    return _run_getent("passwd", uid) is not None


def get_group_gid(name: str) -> Optional[int]:
    line = _run_getent("group", name)
    if line:
        # Format: name:password:gid:members
        parts = line.split(":")
        if len(parts) >= 3:
            try:
                return int(parts[2])
            except ValueError:
                pass
    return None


def get_user_info(uid: str) -> Optional[pwd.struct_passwd]:
    """
    Return a pwd.struct_passwd for uid, read fresh from NSS.
    Uses getent to bypass Python's in-process /etc/passwd cache.
    """
    line = _run_getent("passwd", uid)
    if not line:
        return None
    parts = line.split(":")
    if len(parts) < 7:
        return None
    # Reconstruct as a struct_passwd-compatible object via pwd (parse manually)
    # pwd.struct_passwd fields: pw_name, pw_passwd, pw_uid, pw_gid,
    #                           pw_gecos, pw_dir, pw_shell
    try:
        return pwd.struct_passwd((
            parts[0],           # pw_name
            parts[1],           # pw_passwd
            int(parts[2]),      # pw_uid
            int(parts[3]),      # pw_gid
            parts[4],           # pw_gecos
            parts[5],           # pw_dir
            parts[6],           # pw_shell
        ))
    except (ValueError, IndexError):
        return None


def get_user_supplementary_groups(uid: str) -> Set[str]:
    """
    Return the set of supplementary group names a user currently belongs to.
    Reads from NSS fresh each call so changes made earlier in the same run
    are always reflected.
    """
    groups: Set[str] = set()
    result = subprocess.run(
        ["id", "-Gn", uid],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return groups
    # id -Gn returns all groups including the primary; we want supplementary only.
    # We'll compute primary group name separately and exclude it.
    all_groups = set(result.stdout.strip().split())

    # Determine primary group name from /etc/group
    info = get_user_info(uid)
    if info:
        primary_line = _run_getent("group", str(info.pw_gid))
        if primary_line:
            primary_name = primary_line.split(":")[0]
            all_groups.discard(primary_name)

    return all_groups


def validate_sudoers_rule(rule: str) -> bool:
    """
    Sanity-check a sudoers rule line.
    Rejects strings containing newlines, null bytes, or that don't start
    with a recognisable host/ALL specifier.
    """
    if "\n" in rule or "\0" in rule:
        return False
    if not re.match(r"^[A-Za-z0-9_%/]", rule):
        return False
    return True


# ---------------------------------------------------------------------------
# Sudoers file helpers
# ---------------------------------------------------------------------------

def _safe_name(name: str) -> str:
    """Sanitise a user/group name for use as a filename component."""
    return re.sub(r"[^a-zA-Z0-9_-]", "_", name)


def sudoers_path(name: str, kind: str) -> Path:
    """Return the Path for the sudoers drop-in file we manage for name/kind."""
    return SUDOERS_DIR / f"{RBAC_SUDOERS_PREFIX}{kind}_{_safe_name(name)}"


def write_sudoers_file(path: Path, lines: List[str], dry_run: bool) -> None:
    content = "\n".join(lines) + "\n"
    if dry_run:
        log.info("[dry-run] would write sudoers file %s:\n%s", path, content)
        return
    path.write_text(content)
    path.chmod(0o440)
    log.info("Wrote sudoers file: %s", path)


def remove_sudoers_file(path: Path, dry_run: bool) -> None:
    if path.exists():
        if dry_run:
            log.info("[dry-run] would remove sudoers file %s", path)
            return
        path.unlink()
        log.info("Removed sudoers file: %s", path)


def sync_sudo_rules(
    name: str, kind: str, rules: List[str], dry_run: bool
) -> None:
    """
    Write or remove a /etc/sudoers.d/ drop-in for a user or group.
    kind must be 'user' or 'group'.
    """
    path = sudoers_path(name, kind)

    if not rules:
        remove_sudoers_file(path, dry_run)
        return

    invalid = [r for r in rules if not validate_sudoers_rule(r)]
    if invalid:
        log.error(
            "Invalid sudo rule(s) for %s '%s' — skipping sudoers update: %s",
            kind, name, invalid,
        )
        return

    # Sudoers prefix: %groupname for groups, plain name for users
    subject = f"%{name}" if kind == "group" else name
    lines = [
        "# Managed by rbac_sync.py — do not edit manually",
        f"# {kind}: {name}",
    ]
    for rule in rules:
        lines.append(f"{subject} {rule}")

    new_content = "\n".join(lines) + "\n"
    existing_content = path.read_text() if path.exists() else ""

    if existing_content == new_content:
        log.debug("Sudoers file %s is already up to date.", path)
        return

    write_sudoers_file(path, lines, dry_run)


def prune_orphan_sudoers(
    known_users: Set[str], known_groups: Set[str], dry_run: bool
) -> None:
    """Remove rbac-managed sudoers files for names no longer in rbac.json."""
    if not SUDOERS_DIR.exists():
        return

    for path in SUDOERS_DIR.glob(f"{RBAC_SUDOERS_PREFIX}*"):
        stem = path.name[len(RBAC_SUDOERS_PREFIX):]  # e.g. "user_jdoe" or "group_devs"

        if stem.startswith("user_"):
            safe = stem[len("user_"):]
            # Check whether ANY known user sanitises to this filename stem
            if safe not in {_safe_name(u) for u in known_users}:
                log.info("Pruning orphan sudoers file (user removed from rbac): %s", path)
                remove_sudoers_file(path, dry_run)

        elif stem.startswith("group_"):
            safe = stem[len("group_"):]
            if safe not in {_safe_name(g) for g in known_groups}:
                log.info("Pruning orphan sudoers file (group removed from rbac): %s", path)
                remove_sudoers_file(path, dry_run)


# ---------------------------------------------------------------------------
# Group sync
# Future feature - build hierarchical group system
# Add a UI to graphically displays groups
# ---------------------------------------------------------------------------

def sync_group(group: dict, dry_run: bool) -> None:
    name = group["name"]
    gid = group.get("gid")

    if not group_exists(name):
        log.info("Creating group: %s (gid=%s)", name, gid)
        cmd = ["groupadd"]
        if gid:
            cmd += ["--gid", str(gid)]
        cmd.append(name)
        run(cmd, dry_run)
    else:
        current_gid = get_group_gid(name)
        if gid and current_gid != gid:
            log.info("Updating gid for group '%s': %s -> %d", name, current_gid, gid)
            run(["groupmod", "--gid", str(gid), name], dry_run)
        else:
            log.debug("Group '%s' already exists with correct gid.", name)

    sync_sudo_rules(name, "group", group.get("sudo_rules", []), dry_run)


# ---------------------------------------------------------------------------
# User sync
# ---------------------------------------------------------------------------

def sync_user(user: dict, dry_run: bool) -> None:
    uid = user["uid"]
    cn = user.get("common_name", uid)
    uid_number = user.get("uid_number")
    gid_number = user.get("gid_number")
    home = user.get("home_directory", f"{DEFAULT_HOME_BASE}/{uid}")
    shell = user.get("shell", DEFAULT_SHELL)
    password_hash = user.get("password_hash")
    comment = cn  # stored in the GECOS field

    if not user_exists(uid):
        log.info("Creating user: %s", uid)
        cmd = ["useradd", "--comment", comment]
        if uid_number:
            cmd += ["--uid", str(uid_number)]
        if gid_number:
            cmd += ["--gid", str(gid_number)]
        cmd += ["--home-dir", home, "--create-home", "--shell", shell]
        if password_hash:
            cmd += ["--password", password_hash]
        cmd.append(uid)
        run(cmd, dry_run)
    else:
        info = get_user_info(uid)
        if info is None:
            log.error(
                "Could not read info for existing user '%s' — skipping update.", uid
            )
        else:
            changes: List[str] = []

            if uid_number is not None and info.pw_uid != uid_number:
                changes += ["--uid", str(uid_number)]
            if gid_number is not None and info.pw_gid != gid_number:
                changes += ["--gid", str(gid_number)]
            if info.pw_dir != home:
                changes += ["--home", home, "--move-home"]
            if info.pw_shell != shell:
                changes += ["--shell", shell]
            if info.pw_gecos != comment:
                changes += ["--comment", comment]

            if changes:
                log.info("Updating attributes for user '%s'", uid)
                run(["usermod"] + changes + [uid], dry_run)
            else:
                log.debug("User '%s' attributes already up to date.", uid)

            # NOTE I went back and forth on the pasword feature and opted to put it in
            # If I decide not to use it, nothing happens - but it was no extra
            # effort to add it, so I wanted it
            # Only update the password if a hash is explicitly provided.
            # We compare against the shadow entry; if unreadable we set it
            # to be safe (requires root).
            if password_hash:
                _sync_password(uid, password_hash, dry_run)

    # Reconcile supplementary group memberships
    sync_user_groups(uid, set(user.get("groups", [])), dry_run)

    # Per-user sudo rules
    sync_sudo_rules(uid, "user", user.get("sudo_rules", []), dry_run)


def _sync_password(uid: str, desired_hash: str, dry_run: bool) -> None:
    """Set the user's password only if the shadow hash differs."""
    shadow_line = _run_getent("shadow", uid)
    if shadow_line:
        parts = shadow_line.split(":")
        current_hash = parts[1] if len(parts) > 1 else ""
        if current_hash == desired_hash:
            log.debug("Password hash for '%s' is unchanged — skipping.", uid)
            return
    log.info("Updating password hash for user '%s'", uid)
    run(["usermod", "--password", desired_hash, uid], dry_run)


def sync_user_groups(uid: str, desired_groups: Set[str], dry_run: bool) -> None:
    """
    Reconcile supplementary group membership so it matches desired_groups exactly.
    Groups in desired_groups that the user is not yet in are added.
    Groups the user is in that are not in desired_groups are removed.
    """
    current_groups = get_user_supplementary_groups(uid)

    to_add = desired_groups - current_groups
    to_remove = current_groups - desired_groups

    for g in sorted(to_add):
        if not group_exists(g):
            log.warning(
                "Group '%s' referenced by user '%s' does not exist — skipping.", g, uid
            )
            continue
        log.info("Adding user '%s' to group '%s'", uid, g)
        run(["usermod", "--append", "--groups", g, uid], dry_run)

    for g in sorted(to_remove):
        log.info("Removing user '%s' from group '%s'", uid, g)
        run(["gpasswd", "--delete", uid, g], dry_run)


# Groups that confer sudo/admin access on the local system.
# Users who are not in the Manager group must never be members of these.
PRIVILEGED_SYSTEM_GROUPS = {"sudo", "wheel", "admin"}

# RBAC groups that must never have privileged system group membership.
NO_SUDO_RBAC_GROUPS = {"Employee", "Board"}


def strip_privileged_groups(users: list, dry_run: bool) -> None:
    """
    Forcibly remove Employee-only and Board-only users from any system group
    that grants sudo access (sudo, wheel, admin).

    This is the authoritative sudo block for these roles. sudoers drop-in
    files using !ALL are ineffective because they cannot override a grant
    that comes from group membership in /etc/sudoers or PAM. Removing the
    user from the privileged group at the OS level is the correct control.

    Runs after sync_user() so it overrides any accidental additions.
    """
    for user in users:
        uid = user["uid"]
        user_rbac_groups = set(user.get("groups", []))

        # Only act on users whose RBAC groups are entirely within NO_SUDO_RBAC_GROUPS
        # i.e. they are not a Manager (which legitimately needs sudo).
        if user_rbac_groups - NO_SUDO_RBAC_GROUPS:
            # User has at least one non-restricted RBAC group (e.g. Manager) — skip.
            continue

        current_groups = get_user_supplementary_groups(uid)
        to_strip = current_groups & PRIVILEGED_SYSTEM_GROUPS

        if to_strip:
            for g in sorted(to_strip):
                log.info(
                    "Stripping privileged group '%s' from user '%s' "
                    "(role does not permit sudo access)",
                    g, uid,
                )
                run(["gpasswd", "--delete", uid, g], dry_run)
        else:
            log.debug(
                "User '%s' has no privileged system group membership — OK.", uid
            )


# ---------------------------------------------------------------------------
# Deny group ACL provisioning
#
# deny_employee, deny_manager, deny_board are Linux groups with no functional
# role of their own. Any user added to one of these groups gets an explicit
# setfacl deny (---) on the corresponding folder tree, overriding any
# positive permissions they might otherwise hold.
#
# This gives administrators a clean, auditable way to revoke access for a
# specific user without removing them from their primary role group.
#
# ACL evaluation order: named user > named group > owning group > others.
# A group:deny_X:--- entry will NOT override a user: allow entry for the
# same user. If you need an absolute block, add the user to the deny group
# AND remove any named-user ACL grants for them.
# ---------------------------------------------------------------------------

# Base path — must match BASE_DIR in rbac_fs.py
_FS_BASE = Path("/srv/saffell-soft")

# (deny_group_name, list of folder paths relative to _FS_BASE)
DENY_GROUP_FOLDERS = {
    "deny_employee": [
        "employee/shared",
        "employee/projects",
    ],
    "deny_manager": [
        "manager",             # parent dir — blocks traversal entirely
        "manager/shared",
        "manager/reports",
    ],
    "deny_board": [
        "board/workspace",
    ],
}


def _setfacl_available() -> bool:
    """Return True if setfacl is installed on this system."""
    result = subprocess.run(["which", "setfacl"], capture_output=True, text=True)
    return result.returncode == 0


def provision_deny_acls(dry_run: bool) -> None:
    """
    Apply setfacl group deny entries for deny_employee, deny_manager,
    and deny_board on their respective folder trees.

    Both the directory entry and the default entry are set so that any
    files or subdirectories created inside also inherit the deny.

    Skips gracefully if:
      - setfacl is not installed
      - the target directory does not yet exist (rbac_fs.py must run first)
      - the deny group does not yet exist on the system
    """
    if not _setfacl_available():
        log.warning(
            "setfacl not found — skipping deny ACL provisioning. "
            "Install the 'acl' package: sudo apt install acl"
        )
        return

    log.info("── Provisioning deny group ACLs ──")

    for deny_group, rel_paths in DENY_GROUP_FOLDERS.items():

        if not group_exists(deny_group):
            log.warning(
                "Deny group '%s' does not exist on this system — skipping ACLs. "
                "Ensure rbac_sync.py has created the group first.",
                deny_group,
            )
            continue

        for rel_path in rel_paths:
            target = _FS_BASE / rel_path

            if not target.exists():
                log.warning(
                    "Target path does not exist, skipping deny ACL for '%s': %s  "
                    "(run rbac_fs.py first to create the folder structure)",
                    deny_group, target,
                )
                continue

            for acl_entry in [
                f"group:{deny_group}:---",
                f"default:group:{deny_group}:---",
            ]:
                log.info("setfacl -m %s %s", acl_entry, target)
                run(["setfacl", "-m", acl_entry, str(target)], dry_run)


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------

def validate_config(config: dict) -> List[str]:
    """Return a list of human-readable error strings; empty means valid."""
    errors: List[str] = []
    seen_uids: Set[str] = set()
    seen_group_names: Set[str] = set()
    seen_uid_numbers: Set[int] = set()
    seen_gid_numbers: Set[int] = set()

    group_names = {g["name"] for g in config.get("groups", []) if "name" in g}

    for i, group in enumerate(config.get("groups", [])):
        if "name" not in group:
            errors.append(f"groups[{i}]: missing required field 'name'")
            continue
        name = group["name"]
        if name in seen_group_names:
            errors.append(f"groups[{i}]: duplicate group name '{name}'")
        seen_group_names.add(name)

        gid = group.get("gid")
        if gid is not None:
            if not isinstance(gid, int) or gid < 1:
                errors.append(f"groups[{i}] '{name}': 'gid' must be a positive integer")
            elif gid in seen_gid_numbers:
                errors.append(f"groups[{i}] '{name}': duplicate gid {gid}")
            else:
                seen_gid_numbers.add(gid)

        for j, rule in enumerate(group.get("sudo_rules", [])):
            if not isinstance(rule, str):
                errors.append(f"groups[{i}] '{name}': sudo_rules[{j}] must be a string")

    for i, user in enumerate(config.get("users", [])):
        if "uid" not in user:
            errors.append(f"users[{i}]: missing required field 'uid'")
            continue
        uid = user["uid"]
        if uid in seen_uids:
            errors.append(f"users[{i}]: duplicate uid '{uid}'")
        seen_uids.add(uid)

        uid_number = user.get("uid_number")
        if uid_number is not None:
            if not isinstance(uid_number, int) or uid_number < 1:
                errors.append(
                    f"users[{i}] '{uid}': 'uid_number' must be a positive integer"
                )
            elif uid_number in seen_uid_numbers:
                errors.append(f"users[{i}] '{uid}': duplicate uid_number {uid_number}")
            else:
                seen_uid_numbers.add(uid_number)

        for g in user.get("groups", []):
            if g not in group_names:
                errors.append(
                    f"users[{i}] '{uid}': references undefined group '{g}'"
                )

        for j, rule in enumerate(user.get("sudo_rules", [])):
            if not isinstance(rule, str):
                errors.append(f"users[{i}] '{uid}': sudo_rules[{j}] must be a string")

    return errors


# ---------------------------------------------------------------------------
# Config loader - Additional testing needed here to confirm statefulness
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    config_path = Path(path)
    if not config_path.exists():
        log.error("Config file not found: %s", path)
        sys.exit(1)
    with config_path.open(encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as exc:
            log.error("Invalid JSON in %s: %s", path, exc)
            sys.exit(1)


def check_root() -> None:
    if os.geteuid() != 0:
        log.error("This script must be run as root (e.g. sudo python3 rbac_sync.py).")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sync users and groups from rbac.json to the local Linux system."
    )
    parser.add_argument(
        "--config",
        default="rbac.json",
        help="Path to the rbac.json config file (default: rbac.json)",
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

    config = load_config(args.config)

    errors = validate_config(config)
    if errors:
        log.error("Config validation failed with %d error(s):", len(errors))
        for err in errors:
            log.error("  • %s", err)
        sys.exit(1)

    groups = config.get("groups", [])
    users = config.get("users", [])

    log.info("Syncing %d group(s) and %d user(s)...", len(groups), len(users))

    # 1. Groups first — users need them to exist before being assigned
    for group in groups:
        sync_group(group, args.dry_run)

    # 2. Users
    for user in users:
        sync_user(user, args.dry_run)

    # 3. Strip sudo/wheel/admin group membership from Employee and Board users.
    #    This is the authoritative sudo block — sudoers drop-in !ALL rules
    #    cannot override group-based grants and are not used here.
    strip_privileged_groups(users, args.dry_run)

    # 4. Apply setfacl deny entries for deny_employee, deny_manager, deny_board.
    provision_deny_acls(args.dry_run)

    # 5. Clean up orphaned sudoers files for names removed from rbac.json
    prune_orphan_sudoers(
        known_users={u["uid"] for u in users},
        known_groups={g["name"] for g in groups},
        dry_run=args.dry_run,
    )

    log.info("Done.")


if __name__ == "__main__":
    main()