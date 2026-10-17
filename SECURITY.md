# Security policy

Please report vulnerabilities privately through GitHub's **Security → Report a vulnerability**
(private advisory) rather than a public issue. Include the role, control ID and RHEL minor version.
You should get a response within 7 days.

This project changes authentication, SSH, firewall, audit and boot settings. Always run with
`--check --diff` first and test on non-production systems.
