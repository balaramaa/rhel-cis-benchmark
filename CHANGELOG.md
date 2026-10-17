# Changelog

## [1.0.0] - 2026-10-17
### Added
- `cis_rhel8` role - CIS Red Hat Enterprise Linux 8 Benchmark v4.0.0 (322 controls)
- `cis_rhel9` role - CIS Red Hat Enterprise Linux 9 Benchmark v3.0.0 (352 controls)
- `cis_rhel10` role - CIS Red Hat Enterprise Linux 10 Benchmark v1.0.1 (328 controls)
- One self-contained folder per OS (`rhel8/`, `rhel9/`, `rhel10/`) with `apply.sh` - runs on the server, installs ansible-core if needed
- Per-OS download archives attached to every release
- `site.yml` auto-detects the RHEL major version per host (fleet mode)
- No Ansible Galaxy collections required (ansible.builtin only)
- Per-control tags, toggles, skip lists, section skips and allow-lists
- JSON compliance report per host (`/root/cis-rhelN-report.json`, copied to `reports/`)
- Generator (`tools/generate.py`) and PDF metadata extractor (`tools/extract_benchmark.py`)
- CI: generator drift check, yamllint, ansible-lint, shellcheck, `./apply.sh --check` in Rocky 8/9/10 containers
