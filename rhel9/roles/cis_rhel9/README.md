# cis_rhel9

Applies the **CIS Red Hat Enterprise Linux 9 Benchmark v3.0.0** to RHEL 9 and binary-compatible rebuilds
(Rocky Linux, AlmaLinux, Oracle Linux).

* 352 controls: 311 remediated, 22 audited, 19 manual (evidence collected)
* Every control is a block tagged `rule_<id>`, `section_<n>`, `level<n>_server` / `level<n>_workstation`
* Every variable is prefixed `rhel9cis_` - see `defaults/main.yml`
* Full control list: [`CONTROLS.md`](../../CONTROLS.md)

This role refuses to run on any other major version.
