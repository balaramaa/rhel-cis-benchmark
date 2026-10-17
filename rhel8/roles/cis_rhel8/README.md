# cis_rhel8

Applies the **CIS Red Hat Enterprise Linux 8 Benchmark v4.0.0** to RHEL 8 and binary-compatible rebuilds
(Rocky Linux, AlmaLinux, Oracle Linux).

* 322 controls: 284 remediated, 21 audited, 17 manual (evidence collected)
* Every control is a block tagged `rule_<id>`, `section_<n>`, `level<n>_server` / `level<n>_workstation`
* Every variable is prefixed `rhel8cis_` - see `defaults/main.yml`
* Full control list: [`CONTROLS.md`](../../CONTROLS.md)

This role refuses to run on any other major version.
