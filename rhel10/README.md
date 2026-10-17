# CIS Benchmark for RHEL 10 - Ansible hardening

Applies the **CIS Red Hat Enterprise Linux 10 Benchmark v1.0.1** (328 controls) to
Red Hat Enterprise Linux 10, Rocky Linux 10, AlmaLinux 10 and Oracle Linux 10.

## Run it on the server

```bash
curl -LO https://github.com/YOUR_GITHUB_USER/rhel-cis-benchmark/releases/latest/download/cis-rhel10.tar.gz
tar xzf cis-rhel10.tar.gz
cd rhel10
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
