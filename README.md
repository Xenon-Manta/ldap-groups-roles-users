# rbac_sync

A Python script that manages local Linux users and groups from a declarative `rbac.json` file. Run it on any Ubuntu machine to create, update, and reconcile users, groups, group memberships, and sudo permissions.

No third-party dependencies — standard library only.

---

## Requirements

- Python 3.8+
- Ubuntu (or any Debian-based distro with `useradd`, `groupadd`, `usermod`, `gpasswd`, `getent`)
- Must be run as **root** (or via `sudo`)

---

## Quick Start

```bash
# 1. Edit rbac.json to define your users and groups
# 2. Preview changes without touching the system
sudo python3 rbac_sync.py --dry-run --verbose

# 3. Apply
sudo python3 rbac_sync.py
```

---

## Usage

```
sudo python3 rbac_sync.py [OPTIONS]
```

| Option | Default | Description |
|---|---|---|
| `--config PATH` | `rbac.json` | Path to the RBAC config file |
| `--dry-run` | off | Print what would be done without making any changes |
| `--verbose` / `-v` | off | Enable debug-level output |

Examples:

```bash
# Use a config file in a different location
sudo python3 rbac_sync.py --config /etc/myapp/rbac.json

# See every system call that would run, without executing any
sudo python3 rbac_sync.py --dry-run --verbose
```

---

## rbac.json Schema

```jsonc
{
  "groups": [
    {
      "name": "developers",        // required — group name
      "gid": 2001,                  // optional — numeric group ID
      "description": "Dev team",    // optional — informational only
      "sudo_rules": [               // optional — sudo rules granted to the group
        "ALL=(ALL) NOPASSWD: /usr/bin/docker"
      ]
    }
  ],
  "users": [
    {
      "uid": "jdoe",                          // required — login name
      "common_name": "John Doe",              // optional — GECOS/display name
      "surname": "Doe",                       // optional — informational only
      "email": "jdoe@example.com",            // optional — informational only
      "uid_number": 10001,                    // optional — numeric UID
      "gid_number": 2001,                     // optional — primary group GID
      "home_directory": "/home/jdoe",         // optional — defaults to /home/<uid>
      "shell": "/bin/bash",                   // optional — defaults to /bin/bash
      "password_hash": "$6$salt$hash...",     // optional — pre-hashed password (see below)
      "groups": ["developers"],               // optional — supplementary group memberships
      "sudo_rules": [                         // optional — sudo rules granted to this user
        "ALL=(ALL) NOPASSWD: /usr/bin/apt"
      ]
    }
  ]
}
```

### Generating a password hash

The `password_hash` field accepts a SHA-512 crypt hash (the format stored in `/etc/shadow`). Generate one with:

```bash
python3 -c "import crypt; print(crypt.crypt('yourpassword', crypt.mksalt(crypt.METHOD_SHA512)))"
```

Or using `openssl`:

```bash
openssl passwd -6 'yourpassword'
```

Leave `password_hash` out entirely if you want to manage passwords separately (e.g. via LDAP or `passwd` manually).

---

## What the Script Does

### Groups

| Situation | Action |
|---|---|
| Group does not exist | Creates it with `groupadd` |
| Group exists, gid differs | Updates gid with `groupmod` |
| Group exists, gid matches | No change |

### Users

| Situation | Action |
|---|---|
| User does not exist | Creates with `useradd` including all specified attributes |
| User exists, attributes differ | Updates changed attributes with `usermod` |
| User exists, attributes match | No change |
| Password hash provided and differs from shadow | Updates with `usermod --password` |

### Group Memberships

Memberships are reconciled to exactly match the `groups` list for each user:

- User is missing from a listed group → added via `usermod --append --groups`
- User is in a group not listed → removed via `gpasswd --delete`

### Sudo Rules

Sudo rules are written as drop-in files under `/etc/sudoers.d/`:

- Group rules → `/etc/sudoers.d/rbac_group_<name>`
- User rules → `/etc/sudoers.d/rbac_user_<name>`

Files are created or updated when rules change, and **removed** when a user/group has no rules or is removed from `rbac.json`. Only files with the `rbac_` prefix are ever touched.

Rule format in the file:

```
%developers ALL=(ALL) NOPASSWD: /usr/bin/docker   ← group rule
jdoe        ALL=(ALL) NOPASSWD: /usr/bin/apt       ← user rule
```

---

## Idempotency

The script is safe to run repeatedly. It reads current system state before every operation and skips anything already in the desired state. Running it twice in a row with an unchanged `rbac.json` produces no changes.

---

## What the Script Does NOT Do

- **Delete users or groups** — users and groups present on the system but absent from `rbac.json` are left alone. Remove them manually with `userdel` / `groupdel` if needed.
- **Manage SSH keys** — add key management to the `sync_user` function if required.
- **Connect to a remote LDAP server** — this script manages the local system's users and groups. If the machine uses `sssd` or `nss-ldap`, those services handle the LDAP sync separately.

---

## File Layout

```
ldap-rbac/
├── rbac_sync.py   # the sync script
└── rbac.json      # your RBAC definition (edit this)
```
