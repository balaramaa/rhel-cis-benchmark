# Choosing which CIS controls to apply

Control IDs belong to **one** benchmark version. Look them up in `rhel8/CONTROLS.md`,
`rhel9/CONTROLS.md` or `rhel10/CONTROLS.md`.

## On the command line (one run)

```bash
sudo ./apply.sh --skip 1.1.1.6,1.1.1.10        # skip controls
sudo ./apply.sh --skip-section 1.1.2,6.3       # skip sections (any depth: "2", "6.3", "5.3.2.1")
sudo ./apply.sh --only 5.1.20                  # run only these
sudo ./apply.sh --level 2 --workstation        # profile
```

## Permanently (settings.yml)

```yaml
# rhel10/settings.yml
rhel10cis_level: 2
rhel10cis_skip_rules: ["1.1.1.6"]
rhel10cis_skip_sections: ["1.1.2"]
```

Every control also has an on/off switch, listed with its title in
`rhelN/roles/cis_rhelN/defaults/main.yml`. Copy one into settings.yml to change it:

```yaml
rhel10cis_rule_5_1_20: false   # Ensure sshd PermitRootLogin is disabled
```

## With plain Ansible (advanced)

Every control is tagged `rule_<id>`, `section_<n>`, `level1_server`, `level2_server`,
`level1_workstation`, `level2_workstation`, `automated` or `manual`:

```bash
cd rhel9
ansible-playbook -i localhost, -c local playbook.yml --skip-tags rule_1.1.1.6
ansible-playbook -i localhost, -c local playbook.yml --tags section_5
```

## Rules for what runs

A control runs only if it belongs to the chosen profile at or below the chosen level, is not
skipped by ID, section, switch or tag, and (if an `--only` list is given) is on that list.
