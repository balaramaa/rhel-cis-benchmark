#!/usr/bin/env bash
# Detects RHEL 8 / 9 / 10 and runs the matching CIS benchmark from rhel8/, rhel9/ or rhel10/.
#   sudo ./apply.sh --check     dry run
#   sudo ./apply.sh             apply
#   sudo ./apply.sh --help      options
set -euo pipefail
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
. /etc/os-release
MAJOR="${VERSION_ID%%.*}"
if [ ! -x "$HERE/rhel$MAJOR/apply.sh" ]; then
  echo "Unsupported OS: $PRETTY_NAME (supported: RHEL / Rocky / Alma / Oracle Linux 8, 9, 10)"
  exit 1
fi
echo ">>> Detected $PRETTY_NAME - using rhel$MAJOR/"
exec "$HERE/rhel$MAJOR/apply.sh" "$@"
