# Architecture

## Flow of one run

```
sudo ./apply.sh                  (root: detects version → rhelN/apply.sh)
  rhelN/apply.sh                 checks OS version, installs ansible-core, maps options
    ansible-playbook -c local rhelN/playbook.yml  (+ rhelN/settings.yml)
site.yml (fleet mode)            group_by version → each host gets only its own role
role cis_rhelN
  tasks/main.yml
    prelim.yml   (tag: always)
      • assert the host is EL N
      • compute rhelNcis_active_rules from level/profile/skip/only/switches
      • package facts, unit files, groups, UID_MIN, IPv6, authselect, crypto policy
    section_1.yml … section_7.yml
      • one block per control:  when: "'<id>' in rhelNcis_active_rules"
                                tags: [rule_<id>, section_<n>, level…, automated|manual]
    post.yml     (tag: always)
      • flush handlers, write + fetch JSON report, print findings
```

## Why every control is self-contained

Some benchmark settings live in shared files. Each is designed so excluding one control never
changes another:

| Shared thing | Approach |
|---|---|
| sshd | One line per control in `/etc/ssh/sshd_config.d/00-cis-hardening.conf`, included at the top of `sshd_config` (first value wins). `sshd -t` runs before reload. |
| Crypto policy | Each control writes its `.pmod` and appends its module to a fact; a handler runs `update-crypto-policies --set BASE:MOD1:MOD2` once, keeping modules already in use. |
| Audit rules | One file per control in `/etc/audit/rules.d/50-cis-*.rules`. Syscalls are filtered through `ausyscall --dump` so unsupported ones are never written; watches are written only for paths that exist. |
| sysctl | `ansible.posix.sysctl` per key into `/etc/sysctl.d/99-zz-cis-hardening.conf` (sorts last, so it wins). |
| fstab options | `replace` adds one option to one mount line, then remounts. |
| PAM | `authselect` features and per-file config (`faillock.conf`, `pwquality.conf.d/50-cis.conf`, `pwhistory.conf`); module arguments removed from the custom profile templates. |
| sudo | Lines in `/etc/sudoers.d/zz-cis-hardening`, validated with `visudo -cf`. |

## Remediate, audit or manual

| Kind | Behaviour |
|---|---|
| remediate | Changes the system. Shell remediations receive `DRY=1` in check mode and only report. |
| audit | Read-only check; non-compliant items become `audit` findings (e.g. duplicate UIDs). |
| manual | CIS Manual control; evidence (command output) is attached to the report for review. |

## Generator

`tools/generate.py` reads `tools/benchmarks/rhelN.json`, writes the whole `rhelN/` folder and, for every control, asks
`tools/cis_impl.py:implement()` for tasks. Implementations are matched by **title**, because IDs move
between versions while titles mostly stay put; where the benchmarks genuinely differ (for example
"Ensure Wayland is configured" on RHEL 9 versus "Ensure Xwayland is configured" on RHEL 8/10) each title
gets its own implementation. Any title without an implementation falls back to a manual-review task and
is printed as a warning, so a new benchmark release cannot silently lose controls.

## No external dependencies

The roles use only `ansible.builtin` modules, so the `ansible-core` package from RHEL AppStream
(2.14 on RHEL 9, 2.16 on RHEL 8.10 and 10) is enough — no Galaxy collections to install.
