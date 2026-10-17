# CIS Benchmark for RHEL 8, RHEL 9 and RHEL 10 — Ansible Hardening Playbook

Automatically apply the **CIS Benchmark** to **Red Hat Enterprise Linux 8, 9 and 10**
(also **Rocky Linux, AlmaLinux and Oracle Linux**) with one command. Free, open source, no Ansible experience needed.

| Your OS | CIS Benchmark | Controls | Download |
|---|---|---|---|
| **RHEL 8** / Rocky 8 / Alma 8 | CIS RHEL 8 Benchmark **v4.0.0** | 322 | [cis-rhel8.tar.gz](https://github.com/YOUR_GITHUB_USER/rhel-cis-benchmark/releases/latest/download/cis-rhel8.tar.gz) |
| **RHEL 9** / Rocky 9 / Alma 9 | CIS RHEL 9 Benchmark **v3.0.0** | 352 | [cis-rhel9.tar.gz](https://github.com/YOUR_GITHUB_USER/rhel-cis-benchmark/releases/latest/download/cis-rhel9.tar.gz) |
| **RHEL 10** / Rocky 10 / Alma 10 | CIS RHEL 10 Benchmark **v1.0.1** | 328 | [cis-rhel10.tar.gz](https://github.com/YOUR_GITHUB_USER/rhel-cis-benchmark/releases/latest/download/cis-rhel10.tar.gz) |

Each download contains **only** the settings for that OS version.

---

## Quick start (3 steps, on the server)

> ⚠️ Test on a non-production server first. Make sure you can log in as a **normal user with sudo** —
> root SSH login is disabled by the benchmark.

### RHEL 8

```bash
curl -LO https://github.com/YOUR_GITHUB_USER/rhel-cis-benchmark/releases/latest/download/cis-rhel8.tar.gz
tar xzf cis-rhel8.tar.gz && cd rhel8
sudo ./apply.sh --check     # 1. preview the changes (nothing is changed)
sudo ./apply.sh             # 2. apply the CIS benchmark
sudo reboot                 # 3. reboot to activate everything
```

### RHEL 9

```bash
curl -LO https://github.com/YOUR_GITHUB_USER/rhel-cis-benchmark/releases/latest/download/cis-rhel9.tar.gz
tar xzf cis-rhel9.tar.gz && cd rhel9
sudo ./apply.sh --check
sudo ./apply.sh
sudo reboot
```

### RHEL 10

```bash
curl -LO https://github.com/YOUR_GITHUB_USER/rhel-cis-benchmark/releases/latest/download/cis-rhel10.tar.gz
tar xzf cis-rhel10.tar.gz && cd rhel10
sudo ./apply.sh --check
sudo ./apply.sh
sudo reboot
```

### Don't know your version? Use the auto-detect script

```bash
git clone https://github.com/YOUR_GITHUB_USER/rhel-cis-benchmark.git
cd rhel-cis-benchmark
sudo ./apply.sh --check
sudo ./apply.sh
```

`apply.sh` installs `ansible-core` from the standard AppStream repository if it is not already installed.
Nothing else is required.

---

## Choose what to apply

| You want to… | Command |
|---|---|
| Preview changes only | `sudo ./apply.sh --check` |
| Level 1 Server (default) | `sudo ./apply.sh` |
| Level 2 (stricter) | `sudo ./apply.sh --level 2` |
| Workstation profile | `sudo ./apply.sh --workstation` |
| **Skip** some controls | `sudo ./apply.sh --skip 1.1.1.6,5.1.20` |
| Skip a whole section | `sudo ./apply.sh --skip-section 6.3` |
| Apply **only** some controls | `sudo ./apply.sh --only 5.1.20,5.1.16` |
| No confirmation prompt (automation) | `sudo ./apply.sh -y` |

Control IDs and titles for each version: [rhel8/CONTROLS.md](rhel8/CONTROLS.md) ·
[rhel9/CONTROLS.md](rhel9/CONTROLS.md) · [rhel10/CONTROLS.md](rhel10/CONTROLS.md)

> **Note:** IDs differ between versions. For example, `5.1.20` is *sshd MaxStartups* on RHEL 8,
> *PermitEmptyPasswords* on RHEL 9 and *PermitRootLogin* on RHEL 10. Always check the CONTROLS.md
> file for your version.

### Make exclusions permanent

Edit `settings.yml` in your version's folder, for example `rhel9/settings.yml`:

```yaml
rhel9cis_level: 1
rhel9cis_skip_rules: ["1.1.1.6"]          # keep overlay module for podman
rhel9cis_sshd_allowgroups: [wheel]        # only wheel members may SSH
rhel9cis_firewalld_allowed_services: [ssh, https]
```

Then run `sudo ./apply.sh` again.

---

## What you get after running

- The server is hardened to the selected CIS profile.
- A report at `/root/cis-rhelN-report.json` lists every applied control and anything that needs your
  attention (for example, partitions that must be created at install time).
- The output ends with a short list of findings to review.

To verify independently, scan with OpenSCAP or CIS-CAT before and after:

```bash
sudo dnf install -y openscap-scanner scap-security-guide
sudo oscap xccdf eval --profile cis_server_l1 --report cis-report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml     # use rhel8 / rhel10 as needed
```

---

## Check before you run in production

| Setting | Why it matters | How to keep it |
|---|---|---|
| Root SSH login is disabled | You could be locked out | Log in as a sudo user, or skip PermitRootLogin (RHEL 8: `5.1.22`, RHEL 9: `5.1.21`, RHEL 10: `5.1.20`) |
| firewalld is enabled | Only SSH stays open by default | Add services to `firewalld_allowed_services` in settings.yml |
| `overlay` module disabled (Level 2) | Breaks podman / containers | `--skip 1.1.1.6` |
| USB storage disabled | USB drives stop working | `--skip 1.1.1.10` |
| auditd halts the system when its disk is full (Level 2) | Availability | Set `auditd_disk_full_action: single` |
| Some settings need a reboot | Kernel, SELinux, crypto policy | `sudo reboot` after applying |

---

## Many servers at once (optional)

From any machine with Ansible installed:

```bash
git clone https://github.com/YOUR_GITHUB_USER/rhel-cis-benchmark.git && cd rhel-cis-benchmark
cp inventory/hosts.yml.example inventory/hosts.yml     # list your servers
ansible-playbook site.yml --check --diff               # preview
ansible-playbook site.yml                              # apply - each server gets its own version
```

---

## Repository layout

```
rhel-cis-benchmark/
├── apply.sh          ← auto-detects RHEL 8 / 9 / 10
├── rhel8/            ← everything for RHEL 8   (CIS v4.0.0)
│   ├── apply.sh      ← run this on a RHEL 8 server
│   ├── settings.yml  ← your choices (level, skips, SSH groups …)
│   ├── CONTROLS.md   ← list of all 322 controls
│   ├── playbook.yml
│   └── roles/cis_rhel8/
├── rhel9/            ← everything for RHEL 9   (CIS v3.0.0)
├── rhel10/           ← everything for RHEL 10  (CIS v1.0.1)
├── site.yml          ← optional: many servers from one Ansible machine
└── docs/  tools/     ← documentation and the generator for maintainers
```

---

## FAQ

**Does it work on Rocky Linux / AlmaLinux / Oracle Linux?** Yes, versions 8, 9 and 10.

**Is it safe to run twice?** Yes. Running it again only fixes settings that have drifted.

**Can I undo it?** There is no automatic undo. Take a VM snapshot or backup before applying.

**Does it need internet access?** Only to install `ansible-core` the first time, from your normal RHEL repositories.

**Is this the official CIS tool?** No. It is an independent open-source implementation. See the disclaimer below.

---

## Contributing / maintainers

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Bugs and requests: [open an issue](https://github.com/YOUR_GITHUB_USER/rhel-cis-benchmark/issues).
If this saved you time, please ⭐ the repository.

## Disclaimer

Not affiliated with or endorsed by the Center for Internet Security® (CIS). CIS® and CIS Benchmarks™ are
trademarks of CIS. This project stores only control IDs and titles for reference; get the official benchmarks
from [cisecurity.org](https://www.cisecurity.org/cis-benchmarks). Hardening can affect applications — test before
production use. MIT License, provided without warranty.
