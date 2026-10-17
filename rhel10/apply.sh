#!/usr/bin/env bash
# =============================================================================
#  Apply the CIS Red Hat Enterprise Linux 10 Benchmark v1.0.1 to THIS server.
#  https://github.com/YOUR_GITHUB_USER/rhel-cis-benchmark
#
#  sudo ./apply.sh --check          dry run - shows what would change, changes nothing
#  sudo ./apply.sh                  apply Level 1 Server
#  sudo ./apply.sh --help           all options
# =============================================================================
set -euo pipefail
OS_MAJOR=10
PFX=rhel10cis
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"

usage() {
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
}

json_list() {  # "a,b" -> ["a","b"]
  printf '%s' "$1" | awk -F, '{printf "["; for (i = 1; i <= NF; i++) printf "%s\"%s\"", (i > 1 ? "," : ""), $i; printf "]"}'
}

CHECK=() YES="" EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --check|--dry-run) CHECK=(--check --diff) ;;
    --level)           EXTRA+=(-e "${PFX}_level=${2:?--level needs 1 or 2}"); shift ;;
    --workstation)     EXTRA+=(-e "${PFX}_profile=workstation") ;;
    --skip)            EXTRA+=(-e "{\"${PFX}_skip_rules\": $(json_list "${2:?--skip needs IDs}")}"); shift ;;
    --skip-section)    EXTRA+=(-e "{\"${PFX}_skip_sections\": $(json_list "${2:?--skip-section needs IDs}")}"); shift ;;
    --only)            EXTRA+=(-e "{\"${PFX}_only_rules\": $(json_list "${2:?--only needs IDs}")}"); shift ;;
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
MAJOR="${VERSION_ID%%.*}"
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

if [ ${#CHECK[@]} -eq 0 ] && [ -z "$YES" ]; then
  cat <<EOF

  You are about to harden this server with the CIS Red Hat Enterprise Linux 10 Benchmark v1.0.1.

  * SSH login as root will be DISABLED. Make sure you can log in as a normal user
    that can run sudo before continuing, and keep this session open until you have
    tested a new login.
  * Some settings need a reboot (kernel arguments, SELinux, crypto policy, audit).
  * Tip: run  sudo ./apply.sh --check  first to see every change.

EOF
  read -r -p "Type YES to continue: " answer
  [ "$answer" = "YES" ] || { echo "Aborted."; exit 1; }
fi

cd "$HERE"
export ANSIBLE_CONFIG="$HERE/ansible.cfg"
ansible-playbook -i localhost, -c local playbook.yml "${CHECK[@]}" -e "${PFX}_report_fetch=false" "${EXTRA[@]}"

echo
echo "Done. Compliance report: /root/cis-rhel10-report.json"
[ ${#CHECK[@]} -eq 0 ] && echo "Reboot when convenient to activate all settings:  sudo reboot"
exit 0
