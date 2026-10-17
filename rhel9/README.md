# CIS Benchmark for RHEL 9 - Ansible hardening

Applies the **CIS Red Hat Enterprise Linux 9 Benchmark v3.0.0** (352 controls) to
Red Hat Enterprise Linux 9, Rocky Linux 9, AlmaLinux 9 and Oracle Linux 9.

## Run it on the server

```bash
curl -LO https://github.com/YOUR_GITHUB_USER/rhel-cis-benchmark/releases/latest/download/cis-rhel9.tar.gz
tar xzf cis-rhel9.tar.gz
cd rhel9
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
