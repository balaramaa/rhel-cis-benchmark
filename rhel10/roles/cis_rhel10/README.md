# cis_rhel10

Applies the **CIS Red Hat Enterprise Linux 10 Benchmark v1.0.1** to RHEL 10 and binary-compatible rebuilds
(Rocky Linux, AlmaLinux, Oracle Linux).

* 328 controls: 289 remediated, 22 audited, 17 manual (evidence collected)
* Every control is a block tagged `rule_<id>`, `section_<n>`, `level<n>_server` / `level<n>_workstation`
* Every variable is prefixed `rhel10cis_` - see `defaults/main.yml`
* Full control list: [`CONTROLS.md`](../../CONTROLS.md)

This role refuses to run on any other major version.
