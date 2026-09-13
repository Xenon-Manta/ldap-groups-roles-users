# Linux Basic RBAC System

A declarative RBAC system for Ubuntu that manages local Linux users, groups, filesystem structure, and POSIX access controls from two JSON configuration files. Run the scripts on any Ubuntu machine to create, update, and fully reconcile users, groups, group memberships, sudo permissions, folder structure, and ACLs.

No third-party dependencies — standard library only.

---

## File Layout

```
ldap-groups-roles-users/
├── rbac.json           # Users, groups, sudo rules, and tier annotations
├── posix_rules.json    # Filesystem layout, ACL entries, deny groups, sudo controls
├── rbac_sync.py        # Syncs users/groups to the OS and applies deny ACLs
└── rbac_fs.py          # Provisions folder structure and POSIX ACLs
```

---

## Requirements

- Python 3.8+
- Ubuntu (or any Debian-based distro)
- `acl` package for POSIX ACL support: `sudo apt install acl`
- System tools: `useradd`, `groupadd`, `usermod`, `gpasswd`, `getent`, `setfacl`
- Must be run as **root** (or via `sudo`)

---

## Open Features / Roadmap

- Add a React UI to manage groups and roles
- Encrypt and lock `rbac.json` / `posix_rules.json`
- Automatically escalate to sudo on run
- Add a switch for remote LDAP management using OpenLDAP (including remote auth)

---

## Quick Start

```bash
# 1. Edit rbac.json to define users and groups
# 2. Edit posix_rules.json if folder structure or ACLs need changing

# 3. Sync users and groups (run first — rbac_fs.py depends on groups existing)
sudo python3 rbac_sync.py --dry-run --verbose
sudo python3 rbac_sync.py

# 4. Provision folder structure and ACLs
sudo python3 rbac_fs.py --dry-run --verbose
sudo python3 rbac_fs.py
```

---

## Permission Model

The system uses a **tiered inheritance model** for the three primary roles, plus one **flat** role with no inheritance.

### Tiers

| Tier | Group | Inherits from | Own folders | Sudo |
|------|-------|---------------|-------------|------|
| 1 | Employee | — | `employee/shared`, `employee/projects` | No |
| 2 | Manager | Employee (T1) | `manager/shared`, `manager/reports` | Yes — `ALL=(ALL) ALL` |
| 3 | Board | Employee (T1) + Manager (T2) | `board/workspace` | No |

> Inheritance is implemented via explicit Linux group membership and POSIX ACL entries — POSIX has no native inheritance mechanism. Each tier holds OS group membership for every tier below it.

### Flat Role

| Role | Inherits | Access |
|------|----------|--------|
| 3PAO | None | Read-only on `manager/reports` and `/var/log` only |

### Full Access Matrix

| Path | Employee | Manager | Board | 3PAO |
|------|----------|---------|-------|------|
| `employee/shared` | `rw` | `rw` (T1 inherited) | `r` (T1 inherited) | — |
| `employee/projects` | `rw` | `rw` (T1 inherited) | `r` (T1 inherited) | — |
| `manager/shared` | `---` | `rw` | `r` (T2 inherited) | — |
| `manager/reports` | `---` | `rw` | `r` (T2 inherited) | `r` |
| `board/workspace` | `---` | `---` | `rw` | — |
| `/var/log` | — | — | — | `r` |

### Sudo Controls

Sudo access is enforced by **removing users from the OS `sudo`/`wheel`/`admin` groups**, not by sudoers drop-in files. The `!ALL` operator in sudoers drop-ins is ineffective against group-based grants and is not used.

| Group | Sudo access |
|-------|-------------|
| Employee | None — stripped from `sudo`, `wheel`, `admin` |
| Manager | Full — `ALL=(ALL) ALL` via `/etc/sudoers.d/` |
| Board | None — stripped from `sudo`, `wheel`, `admin` |
| 3PAO | None — stripped from `sudo`, `wheel`, `admin` |

---

## Folder Structure

All shared folders live under `/srv/saffell-soft/`:

```
/srv/saffell-soft/
├── employee/               root:root       755
│   ├── shared/             root:Employee   2770  (Employee rw, Manager rw, Board r)
│   └── projects/           root:Employee   2770  (Employee rw, Manager rw, Board r)
├── manager/                root:Manager    750   (Board and 3PAO get r-x via ACL)
│   ├── shared/             root:Manager    2770  (Manager rw, Board r)
│   └── reports/            root:Manager    2770  (Manager rw, Board r, 3PAO r)
└── board/                  root:Board      750
    └── workspace/          root:Board      2770  (Board rw)
```

Mode `2770` = setgid + `rwxrws---`. The setgid bit ensures new files and subdirectories inherit the owning group automatically.

---

## Deny Groups

Deny groups provide a clean mechanism to revoke access for a specific user without removing them from their primary role group. Add a user to a deny group, re-run `rbac_sync.py`, and access is blocked.

| Deny group | Blocks access to |
|------------|-----------------|
| `deny_employee` | `employee/`, `employee/shared`, `employee/projects` |
| `deny_manager` | `manager/`, `manager/shared`, `manager/reports` |
| `deny_board` | `board/`, `board/workspace` |
| `deny_3PAO` | `manager/reports` |

### Why named-user ACL entries

POSIX ACL group deny entries (`group:deny_X:---`) cannot override a positive grant from another group the same user belongs to — Linux ORs all matching group ACL entries. Named-user entries (`user:<uid>:---`) are evaluated first in the ACL chain and override all group entries unconditionally. `rbac_sync.py` resolves the current members of each deny group and writes `user:<uid>:---` entries directly on the target paths.

```bash
# Example: block rnovak from employee folders
sudo usermod --append --groups deny_employee rnovak
sudo python3 rbac_sync.py
```

---

## Scripts

### `rbac_sync.py`

Syncs the OS state to match `rbac.json`, then applies deny ACLs from `posix_rules.json`.

```bash
sudo python3 rbac_sync.py [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config PATH` | `rbac.json` | Path to the RBAC config file |
| `--rules PATH` | `posix_rules.json` | Path to the POSIX rules file |
| `--dry-run` | off | Print what would be done without making any changes |
| `--verbose` / `-v` | off | Enable debug-level output |

**What it does (in order):**
1. Creates or updates groups from `rbac.json`
2. Creates or updates users from `rbac.json`
3. Strips `sudo`/`wheel`/`admin` membership from no-sudo users
4. Applies named-user ACL deny entries for all deny group members
5. Prunes orphaned sudoers drop-in files for removed users/groups

### `rbac_fs.py`

Provisions the folder structure and POSIX ACLs from `posix_rules.json`.

```bash
sudo python3 rbac_fs.py [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--rules PATH` | `posix_rules.json` | Path to the POSIX rules file |
| `--dry-run` | off | Print what would be done without making any changes |
| `--verbose` / `-v` | off | Enable debug-level output |

**What it does (in order):**
1. Creates `/srv/saffell-soft/` base directory
2. Creates and sets ownership/mode on parent directories
3. Creates and sets ownership/mode on shared subfolders
4. Applies all POSIX ACL entries from the `acls` section
5. Applies external ACL entries from the `external_acls` section (e.g. `/var/log`)
6. Removes stale sudoers drop-in files from previous script versions

> Run `rbac_sync.py` before `rbac_fs.py` on a fresh system — groups must exist before ACLs referencing them can be applied.

---

## Configuration Files

### `rbac.json`

Defines groups, users, sudo rules, and tier annotations. The `_tier` field on each user is documentation only — access is enforced by group membership and ACLs, not this field.

```jsonc
{
  "groups": [
    {
      "name": "Employee",       // required
      "gid": 3001,              // optional — numeric group ID
      "description": "...",     // optional — informational
      "sudo_rules": []          // optional — written to /etc/sudoers.d/
    }
  ],
  "users": [
    {
      "uid": "tharris",                         // required — login name
      "common_name": "Thomas Harris",           // optional — GECOS field
      "surname": "Harris",                      // optional — informational
      "email": "tharris@saffell-soft.com",      // optional — informational
      "uid_number": 10001,                      // optional — numeric UID
      "gid_number": 3001,                       // optional — primary group GID
      "home_directory": "/home/tharris",        // optional — defaults to /home/<uid>
      "shell": "/bin/bash",                     // optional — defaults to /bin/bash
      "password_hash": "",                      // optional — SHA-512 crypt hash
      "groups": ["Employee", "deny_manager"],   // supplementary group memberships
      "_tier": 1,                               // documentation only
      "sudo_rules": []
    }
  ]
}
```

#### Generating a password hash

```bash
# Python
python3 -c "import crypt; print(crypt.crypt('yourpassword', crypt.mksalt(crypt.METHOD_SHA512)))"

# openssl
openssl passwd -6 'yourpassword'
```

Leave `password_hash` empty to manage passwords separately (e.g. via LDAP or `passwd`).

### `posix_rules.json`

Defines all filesystem and access control rules. Both scripts read this file — edit it to change folder layout, permissions, or ACL entries without touching Python code.

Top-level sections:

| Key | Purpose |
|-----|---------|
| `base_dir` | Root path for all managed folders (`/srv/saffell-soft`) |
| `_tier_model` | Documentation block describing the inheritance hierarchy |
| `parent_dirs` | Top-level directories under `base_dir` with ownership and mode |
| `folders` | Shared subfolders with setgid ownership |
| `acls` | POSIX ACL entries applied to paths under `base_dir` |
| `external_acls` | ACL entries on paths outside `base_dir` (e.g. `/var/log`) |
| `deny_groups` | Maps deny group names to the paths they block |
| `sudo_controls` | Privileged system groups and no-sudo RBAC group lists |

---

## Idempotency

Both scripts are safe to run repeatedly. System state is read before every operation and anything already in the desired state is skipped. Running either script twice in a row with unchanged config files produces no changes.

---

## What the Scripts Do NOT Do

- **Delete users or groups** — users and groups on the system but absent from `rbac.json` are left alone. Remove them manually with `userdel` / `groupdel`.
- **Manage SSH keys** — add key management to `sync_user()` in `rbac_sync.py` if needed.
- **Connect to a remote LDAP server** — these scripts manage the local system. If the machine uses `sssd` or `nss-ldap`, those services handle the LDAP sync separately.
- **Modify `/var/log` ownership or mode** — only ACL grant entries are added; the OS retains full control of system log permissions.
