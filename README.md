# CIS Benchmark for RHEL 8, RHEL 9 and RHEL 10 — Ansible Hardening Playbook

An independent, open-source implementation for applying CIS Benchmark-related hardening settings to Red Hat Enterprise Linux 8, 9 and 10, with intended support for Rocky Linux, AlmaLinux and Oracle Linux of the corresponding major versions.

The project provides an OS-major-version entry script, version-specific configuration, selectable profiles, and control exclusions. The author-reported lab testing below covers RHEL only; it does not establish testing of every compatible distribution or profile.

| Your OS | Referenced CIS Benchmark | Listed controls | Download |
|---|---|---|---|
| RHEL 8 / Rocky 8 / Alma 8 | CIS RHEL 8 Benchmark v4.0.0 | 322 | [cis-rhel8.tar.gz](https://github.com/balaramaa/rhel-cis-benchmark/releases/latest/download/cis-rhel8.tar.gz) |
| RHEL 9 / Rocky 9 / Alma 9 | CIS RHEL 9 Benchmark v3.0.0 | 352 | [cis-rhel9.tar.gz](https://github.com/balaramaa/rhel-cis-benchmark/releases/latest/download/cis-rhel9.tar.gz) |
| RHEL 10 / Rocky 10 / Alma 10 | CIS RHEL 10 Benchmark v1.0.1 | 328 | [cis-rhel10.tar.gz](https://github.com/balaramaa/rhel-cis-benchmark/releases/latest/download/cis-rhel10.tar.gz) |

Each download contains the files for that OS major version. Listed control counts describe the project's control inventory, not an independently verified count of automatically remediated or passed checks.

---

## Quick start

> Test on a disposable or non-production system first. Take a VM snapshot or backup and retain console access. Review settings and exclusions before execution. Root SSH login may be disabled by the selected settings; ensure an appropriate sudo user can log in. There is no automatic rollback.

### RHEL 8

```bash
curl -LO https://github.com/balaramaa/rhel-cis-benchmark/releases/latest/download/cis-rhel8.tar.gz
tar xzf cis-rhel8.tar.gz && cd rhel8
sudo ./apply.sh --check     # preview the planned Ansible changes
sudo ./apply.sh             # apply the selected settings
sudo reboot                 # reboot when appropriate after reviewing changes
```

### RHEL 9

```bash
curl -LO https://github.com/balaramaa/rhel-cis-benchmark/releases/latest/download/cis-rhel9.tar.gz
tar xzf cis-rhel9.tar.gz && cd rhel9
sudo ./apply.sh --check
sudo ./apply.sh
sudo reboot
```

### RHEL 10

```bash
curl -LO https://github.com/balaramaa/rhel-cis-benchmark/releases/latest/download/cis-rhel10.tar.gz
tar xzf cis-rhel10.tar.gz && cd rhel10
sudo ./apply.sh --check
sudo ./apply.sh
sudo reboot
```

### OS-major-version entry script

```bash
git clone https://github.com/balaramaa/rhel-cis-benchmark.git
cd rhel-cis-benchmark
sudo ./apply.sh --check
sudo ./apply.sh
```

The top-level script reads `/etc/os-release`, extracts the major version from `VERSION_ID`, and dispatches to the matching version directory. This dispatch is not a complete distribution-compatibility check. Confirm that your distribution and environment are appropriate before running it.

The version-specific scripts are intended to install `ansible-core` from the standard AppStream repository when needed. Repository access, privileges, package availability, and system-specific prerequisites must be checked in your environment.

---

## Choose what to apply

| You want to… | Command |
|---|---|
| Preview planned changes | `sudo ./apply.sh --check` |
| Level 1 Server (default) | `sudo ./apply.sh` |
| Level 2 (stricter) | `sudo ./apply.sh --level 2` |
| Workstation profile | `sudo ./apply.sh --workstation` |
| Skip some controls | `sudo ./apply.sh --skip 1.1.1.6,5.1.20` |
| Skip a whole section | `sudo ./apply.sh --skip-section 6.3` |
| Apply only some controls | `sudo ./apply.sh --only 5.1.20,5.1.16` |
| No confirmation prompt (automation) | `sudo ./apply.sh -y` |

Control IDs and titles for each version: [rhel8/CONTROLS.md](rhel8/CONTROLS.md) · [rhel9/CONTROLS.md](rhel9/CONTROLS.md) · [rhel10/CONTROLS.md](rhel10/CONTROLS.md).

Control IDs differ between benchmark versions. Always check the control list and implementation for your version before selecting or excluding a control. The examples above illustrate syntax, not a recommended exclusion policy.

### Make exclusions permanent

Edit `settings.yml` in your version's folder, for example `rhel9/settings.yml`:

```yaml
rhel9cis_level: 1
rhel9cis_skip_rules: ["1.1.1.6"]          # example exclusion; review for your environment
rhel9cis_sshd_allowgroups: [wheel]        # example SSH access restriction
rhel9cis_firewalld_allowed_services: [ssh, https]
```

Then run `sudo ./apply.sh` again after reviewing the effects.

---

## Output and validation

- The playbook applies the selected implemented settings, subject to exclusions, existing system state, and execution results.
- The project documents a report at `/root/cis-rhelN-report.json` for applied controls and items requiring attention, such as partitions that must be created at install time.
- Review the execution output, findings, skipped tasks, and configuration changes.

A successful execution or generated report is not by itself proof of full CIS compliance or audit success. Assess the resulting system separately with a suitable scanner and review manual controls and exceptions.

For an OpenSCAP assessment, first check the data stream and available profile identifiers for the installed content:

```bash
sudo dnf install -y openscap-scanner scap-security-guide
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

Use the data stream and profile appropriate to your OS, installed content, and assessment objective. A RHEL 9 path or profile should not be assumed to apply unchanged to RHEL 8 or RHEL 10. Qualys or CIS-CAT assessments likewise require appropriate configuration and interpretation of results.

## Operational precautions and limitations

- Review SSH access settings to avoid losing remote access.
- Review firewall rules and application service requirements.
- Kernel-module restrictions may affect containers, storage, or attached devices.
- Audit settings can affect system availability when storage is exhausted.
- Some changes require rebooting; schedule and validate reboots appropriately.
- Check mode is a preview, not a substitute for testing the complete workflow.
- Controls may require manual action, environment-specific configuration, or documented exceptions.
- Repeated execution should be tested in your environment rather than assumed safe for every workload.
- There is no automatic undo. Maintain a tested recovery procedure.
- This project does not certify SOX compliance, guarantee audit outcomes, or replace organizational security and compliance controls.

---

## Many servers at once (optional)

From a suitable control machine with Ansible installed:

```bash
git clone https://github.com/balaramaa/rhel-cis-benchmark.git && cd rhel-cis-benchmark
cp inventory/hosts.yml.example inventory/hosts.yml     # configure and review your inventory
ansible-playbook site.yml --check --diff               # preview
ansible-playbook site.yml                              # apply after testing
```

Test on a limited, non-production inventory before broader deployment. Do not commit credentials or sensitive inventory data to the public repository.

## Lab testing

The implementation was tested in the author's lab on RHEL 8, RHEL 9, and RHEL 10. The playbook completed without execution errors, and the applied configuration settings were checked.

Qualys was used separately to assess the resulting configurations. Results included passed and skipped checks. Some required configurations were already present before execution; those existing configurations are not attributed to this playbook.

These results describe the tested lab environments, not a guarantee that every control will pass on other systems. Skipped checks are not counted as passed checks.

The following dates and results are reported by the author. OS minor versions, scan scores, and individual check counts are not specified in this summary. This is an author-reported summary, not a published independent test report.

| OS major version | Profile reported | Test date reported | Test summary |
|---|---|---|---|
| RHEL 9 | Level 1 | August 14, 2026 | Error-free execution; settings checked; Qualys assessment included passed and skipped checks |
| RHEL 8 | Level 1 | August 27, 2026 | Error-free execution; settings checked; Qualys assessment included passed and skipped checks |
| RHEL 10 | Level 1 | September 18, 2026 | Error-free execution; settings checked; Qualys assessment included passed and skipped checks |

## Repository layout

- `apply.sh`: OS-major-version entry script.
- `rhel8/`, `rhel9/`, `rhel10/`: version-specific scripts, settings, control lists, playbooks, and roles.
- `site.yml`: fleet-mode playbook.
- `inventory/`: inventory examples.
- `reports/`: report-related files.
- `docs/`: project documentation.
- `tools/`: generation and maintenance utilities.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the project architecture.

## Authorship and sources

This implementation was developed by Balaramakrishna Alti using YAML, Python, and shell scripting. Development referenced Red Hat Ansible documentation and the applicable CIS Benchmark documentation. No code was copied or adapted from other repositories.

My contribution is the software implementation and integration described in this repository, informed by my practical Linux engineering experience. I do not claim authorship of Ansible or the CIS Benchmarks.

## Contributing / maintainers

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

For non-sensitive bugs and requests, [open an issue](https://github.com/balaramaa/rhel-cis-benchmark/issues). Do not include credentials, confidential configurations, internal scan results, or other sensitive information in public issues.

## Disclaimer

Not affiliated with or endorsed by the Center for Internet Security® (CIS). CIS® and CIS Benchmarks™ are trademarks of CIS. Obtain the official benchmarks from [cisecurity.org](https://www.cisecurity.org/cis-benchmarks).

This is an independent implementation. Hardening can affect applications and availability; test before production use and review exceptions and recovery procedures. MIT License, provided without warranty. References to products or organizations do not imply endorsement or certification.
