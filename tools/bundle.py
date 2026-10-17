"""Per-OS folder files: rhelN/apply.sh, playbook.yml, settings.yml, ansible.cfg, README.md."""

REPO = "YOUR_GITHUB_USER/rhel-cis-benchmark"


def apply_sh(c, bench):
    v, P = c.v, c.p
    return f"""#!/usr/bin/env bash
# =============================================================================
#  Apply the {bench['benchmark']} {bench['version']} to THIS server.
#  https://github.com/{REPO}
#
#  sudo ./apply.sh --check          dry run - shows what would change, changes nothing
#  sudo ./apply.sh                  apply Level 1 Server
#  sudo ./apply.sh --help           all options
# =============================================================================
set -euo pipefail
OS_MAJOR={v}
PFX={P}
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"

usage() {{
  cat <<'EOF'
Usage: sudo ./apply.sh [options]

  --check                 Dry run. Show what would change without changing anything.
  --level 1|2             CIS level (default 1). Level 2 includes Level 1.
  --workstation           Use the Workstation profile (default: Server).
  --skip IDS              Skip controls, comma separated:   --skip 1.1.1.6,5.1.20
  --skip-section IDS      Skip whole sections:              --skip-section 1.1.2,6.3
  --only IDS              Run ONLY these controls:          --only 5.1.20
  -y, --yes               Do not ask for confirmation.
  -h, --help              Show this help.

Permanent settings (SSH allowed groups, password policy, log server ...) go in settings.yml.
The control list with IDs is in CONTROLS.md.
EOF
}}

json_list() {{  # "a,b" -> ["a","b"]
  printf '%s' "$1" | awk -F, '{{printf "["; for (i = 1; i <= NF; i++) printf "%s\\"%s\\"", (i > 1 ? "," : ""), $i; printf "]"}}'
}}

CHECK=() YES="" EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --check|--dry-run) CHECK=(--check --diff) ;;
    --level)           EXTRA+=(-e "${{PFX}}_level=${{2:?--level needs 1 or 2}}"); shift ;;
    --workstation)     EXTRA+=(-e "${{PFX}}_profile=workstation") ;;
    --skip)            EXTRA+=(-e "{{\\"${{PFX}}_skip_rules\\": $(json_list "${{2:?--skip needs IDs}}")}}"); shift ;;
    --skip-section)    EXTRA+=(-e "{{\\"${{PFX}}_skip_sections\\": $(json_list "${{2:?--skip-section needs IDs}}")}}"); shift ;;
    --only)            EXTRA+=(-e "{{\\"${{PFX}}_only_rules\\": $(json_list "${{2:?--only needs IDs}}")}}"); shift ;;
    -y|--yes)          YES=1 ;;
    -h|--help)         usage; exit 0 ;;
    *) echo "Unknown option: $1"; echo; usage; exit 1 ;;
  esac
  shift
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root:  sudo $0 $*"; exit 1
fi

. /etc/os-release
MAJOR="${{VERSION_ID%%.*}}"
if [ "$MAJOR" != "$OS_MAJOR" ]; then
  echo "This folder is for RHEL $OS_MAJOR, but this server runs: $PRETTY_NAME"
  [ -x "$HERE/../rhel$MAJOR/apply.sh" ] && echo "Use: sudo $HERE/../rhel$MAJOR/apply.sh"
  exit 1
fi

if ! command -v ansible-playbook >/dev/null 2>&1; then
  echo ">>> Installing ansible-core (from the AppStream repository)..."
  if ! dnf -y install ansible-core; then
    echo "Could not install ansible-core. Make sure the AppStream repository is enabled"
    echo "(RHEL: the system must be registered with subscription-manager)."
    exit 1
  fi
fi

if [ ${{#CHECK[@]}} -eq 0 ] && [ -z "$YES" ]; then
  cat <<EOF

  You are about to harden this server with the {bench['benchmark']} {bench['version']}.

  * SSH login as root will be DISABLED. Make sure you can log in as a normal user
    that can run sudo before continuing, and keep this session open until you have
    tested a new login.
  * Some settings need a reboot (kernel arguments, SELinux, crypto policy, audit).
  * Tip: run  sudo ./apply.sh --check  first to see every change.

EOF
  read -r -p "Type YES to continue: " answer
  [ "$answer" = "YES" ] || {{ echo "Aborted."; exit 1; }}
fi

cd "$HERE"
export ANSIBLE_CONFIG="$HERE/ansible.cfg"
ansible-playbook -i localhost, -c local playbook.yml "${{CHECK[@]}}" -e "${{PFX}}_report_fetch=false" "${{EXTRA[@]}}"

echo
echo "Done. Compliance report: /root/cis-rhel{v}-report.json"
[ ${{#CHECK[@]}} -eq 0 ] && echo "Reboot when convenient to activate all settings:  sudo reboot"
exit 0
"""


def playbook(c, bench):
    return f"""---
# {bench['benchmark']} {bench['version']}
# Local:   sudo ./apply.sh
# Remote:  ansible-playbook -i "server1,server2," playbook.yml -u admin -b
- name: Apply {bench['benchmark']} {bench['version']}
  hosts: all
  become: true
  gather_facts: true
  vars_files:
    - settings.yml
  roles:
    - cis_rhel{c.v}
"""


def settings(c, bench):
    P = c.p
    rules = {r["id"]: r["title"] for r in bench["rules"]}
    ex_root = next((i for i, t in rules.items() if "PermitRootLogin" in t), "")
    ex_access = next((i for i, t in rules.items() if t == "Ensure sshd access is configured"), "")
    return f"""---
# =============================================================================
#  Your settings for the {bench['benchmark']} {bench['version']}.
#  Edit as needed, then run:  sudo ./apply.sh
#  Every available option (with defaults) is in roles/cis_rhel{c.v}/defaults/main.yml
# =============================================================================

# Level 1 = essential hardening, Level 2 = stricter (includes Level 1)
{P}_level: 1

# server or workstation
{P}_profile: server

# Controls to skip permanently (IDs from CONTROLS.md), e.g. ["1.1.1.6", "{ex_root}"]
{P}_skip_rules: []

# Sections to skip, e.g. ["1.1.2"] (partitions) or ["6"] (logging and auditing)
{P}_skip_sections: []

# --- SSH ---------------------------------------------------------------------
# Control {ex_access}: only these groups may log in over SSH. Recommended: [wheel]
# Left empty by default so nobody is locked out.
{P}_sshd_allowgroups: []
# Control {ex_root}: "no" disables root SSH login (CIS). Change only if you must.
{P}_sshd_permit_root_login: "no"

# --- Firewall ----------------------------------------------------------------
# Services kept open when firewalld is enabled (add http, https, ... as needed)
{P}_firewalld_allowed_services: [ssh]

# --- Services ----------------------------------------------------------------
# "mask" stops and masks unneeded services, "remove" uninstalls their packages
{P}_service_remediation: mask

# --- Passwords ---------------------------------------------------------------
{P}_pwquality_minlen: 14
{P}_pass_max_days: 365

# --- Logging -----------------------------------------------------------------
# Central log server (leave empty if you have none)
{P}_rsyslog_remote_host: ""

# --- Boot loader -------------------------------------------------------------
# Paste the output of  grub2-mkpasswd-pbkdf2  to set a GRUB password
{P}_bootloader_password_hash: ""
"""


ANSIBLE_CFG = """[defaults]
roles_path = ./roles
retry_files_enabled = False
interpreter_python = auto_silent
deprecation_warnings = False
stdout_callback = default
callback_result_format = yaml
display_skipped_hosts = False
forks = 20

[ssh_connection]
pipelining = True
"""


def readme(c, bench, stats):
    v = c.v
    return f"""# CIS Benchmark for RHEL {v} - Ansible hardening

Applies the **{bench['benchmark']} {bench['version']}** ({len(bench['rules'])} controls) to
Red Hat Enterprise Linux {v}, Rocky Linux {v}, AlmaLinux {v} and Oracle Linux {v}.

## Run it on the server

```bash
curl -LO https://github.com/{REPO}/releases/latest/download/cis-rhel{v}.tar.gz
tar xzf cis-rhel{v}.tar.gz
cd rhel{v}
sudo ./apply.sh --check     # 1. dry run - nothing is changed
sudo ./apply.sh             # 2. apply
sudo reboot                 # 3. reboot to activate everything
```

`apply.sh` installs `ansible-core` from AppStream if it is missing.

## Options

| Command | What it does |
|---|---|
| `sudo ./apply.sh --level 2` | Level 2 (stricter) |
| `sudo ./apply.sh --workstation` | Workstation profile |
| `sudo ./apply.sh --skip 1.1.1.6,5.1.20` | Skip controls |
| `sudo ./apply.sh --skip-section 6.3` | Skip a whole section |
| `sudo ./apply.sh --only 5.1.20` | Run only these controls |

Control IDs: [CONTROLS.md](CONTROLS.md). Permanent settings: [settings.yml](settings.yml).

## Many servers at once

```bash
ansible-playbook -i "server1,server2," playbook.yml -u admin -b
```
"""


def write_bundle(c, bench, coverage, write):
    base = f"rhel{c.v}"
    write(f"{base}/apply.sh", apply_sh(c, bench))
    write(f"{base}/playbook.yml", playbook(c, bench))
    write(f"{base}/settings.yml", settings(c, bench))
    write(f"{base}/ansible.cfg", ANSIBLE_CFG)
    write(f"{base}/README.md", readme(c, bench, coverage))
