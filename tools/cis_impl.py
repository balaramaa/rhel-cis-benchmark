"""Implementations for every CIS recommendation, matched by title.

implement(ctx, rule) returns (tasks, kind) where kind is one of:
  remediate - the role changes the system to comply
  audit     - the role checks and records findings (no safe automatic fix)
  manual    - the benchmark marks it Manual; evidence is collected for review
"""
import re
from cis_lib import (SYSCTL, SERVICES, CLIENTS, FILE_PERMS, AUDIT_TOOLS, SSHD_SIMPLE,
                     SSHD_WEAK, slug, mod_sysfs)

MOUNTS = ["/tmp", "/dev/shm", "/home", "/var", "/var/tmp", "/var/log", "/var/log/audit"]


def implement(c, r):
    t, rid, v = r["title"], r["id"], c.v
    P = c.p
    T = t

    # ---------------------------------------------------------------- 1.1.1
    m = re.match(r"Ensure (\S+) kernel module is not available", t)
    if m:
        mod = m.group(1)
        tasks = [
            {"name": f"{rid} | PATCH | Disable {mod} module in modprobe.d",
             "ansible.builtin.copy": {"dest": f"/etc/modprobe.d/cis-{mod}.conf",
                                      "content": f"# Managed by Ansible - CIS {rid}\ninstall {mod} /bin/false\nblacklist {mod}\n",
                                      "owner": "root", "group": "root", "mode": "0644"}},
            {"name": f"{rid} | AUDIT | Check if {mod} is loaded",
             "ansible.builtin.stat": {"path": f"/sys/module/{mod_sysfs(mod)}"},
             "register": f"{P}_mod_{slug(rid)}"},
            {"name": f"{rid} | PATCH | Unload {mod} if loaded",
             "ansible.builtin.command": f"modprobe -r {mod}",
             "when": f"{P}_mod_{slug(rid)}.stat.exists", "register": f"{P}_modrm_{slug(rid)}",
             "changed_when": f"{P}_modrm_{slug(rid)}.rc == 0", "failed_when": False},
        ]
        if mod == "overlay":
            tasks.insert(0, c.finding(rid, T, "warning",
                                      "['overlay is required by podman/containers - skip this rule on container hosts']",
                                      when="'podman' in ansible_facts.packages or 'containerd.io' in ansible_facts.packages"))
        return tasks, "remediate"

    if t.startswith("Ensure unused filesystems kernel modules"):
        return c.manual(rid, T, "lsmod | awk 'NR>1{print $1}' | sort"), "manual"

    # ------------------------------------------------------- 1.1.2 mounts
    m = re.match(r"Ensure (/\S+) is tmpfs( or a separate partition)?$", t) or \
        re.match(r"Ensure separate partition exists for (/\S+)", t)
    if m:
        mnt = m.group(1)
        return [c.finding(rid, T, "action_required",
                          f"['{mnt} is not a separate mount - repartition or configure a mount (cannot be automated safely)']",
                          when=f"'{mnt}' not in (ansible_facts.mounts | map(attribute='mount') | list)")], "audit"

    m = re.match(r"Ensure (nodev|nosuid|noexec) option set on (/\S+) partition", t)
    if m:
        opt, mnt = m.groups()
        reg = f"{P}_fstab_{slug(rid)}"
        esc = re.escape(mnt)
        tasks = []
        if mnt == "/dev/shm":
            tasks += [
                {"name": f"{rid} | AUDIT | Check for a /dev/shm entry in /etc/fstab",
                 "ansible.builtin.command": "grep -Eq '^\\s*[^#[:space:]]+\\s+/dev/shm\\s' /etc/fstab",
                 "register": f"{reg}_shm", "changed_when": False, "failed_when": f"{reg}_shm.rc > 1",
                 "check_mode": False},
                {"name": f"{rid} | PATCH | Add a /dev/shm tmpfs entry to /etc/fstab",
                 "ansible.builtin.lineinfile": {"path": "/etc/fstab",
                                                "line": "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0"},
                 "when": f"{reg}_shm.rc == 1", "notify": f"{P} remount {mnt}"},
            ]
        tasks += [
            {"name": f"{rid} | AUDIT | Check that {mnt} is an fstab entry",
             "ansible.builtin.command": f"grep -Eq '^\\s*[^#[:space:]]+\\s+{mnt}\\s' /etc/fstab",
             "register": reg, "changed_when": False, "failed_when": f"{reg}.rc > 1", "check_mode": False},
            {"name": f"{rid} | PATCH | Add {opt} to {mnt} in /etc/fstab",
             "ansible.builtin.replace": {
                 "path": "/etc/fstab",
                 "regexp": f"^(\\s*[^#\\s]\\S*\\s+{esc}\\s+\\S+\\s+)(?!(?:\\S*,)?{opt}(?:,|\\s))(\\S+)(.*)$",
                 "replace": f"\\1\\2,{opt}\\3"},
             "when": [f"{reg}.rc == 0", f"'{mnt}' in (ansible_facts.mounts | map(attribute='mount') | list)"],
             "notify": f"{P} remount {mnt}"},
            c.finding(rid, T, "info", f"['{mnt} is not a separate partition in /etc/fstab - option not applicable or set it on the systemd mount unit']",
                      when=f"{reg}.rc != 0 and '{mnt}' != '/dev/shm'"),
        ]
        return tasks, "remediate"

    # ------------------------------------------------------- 1.2 packages
    if t == "Ensure GPG keys are configured":
        return c.manual(rid, T, "rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE}\\t%{SUMMARY}\\n'"), "manual"
    if t == "Ensure gpgcheck is configured":
        return [
            {"name": f"{rid} | PATCH | Enable gpgcheck globally",
             "community.general.ini_file": {"path": "/etc/dnf/dnf.conf", "section": "main",
                                            "option": "gpgcheck", "value": "1", "no_extra_spaces": True}},
            {"name": f"{rid} | AUDIT | Find repo files", "ansible.builtin.find":
                {"paths": "/etc/yum.repos.d", "patterns": "*.repo"}, "register": f"{P}_repos_{slug(rid)}"},
            {"name": f"{rid} | PATCH | Set gpgcheck=1 in every repo file",
             "ansible.builtin.replace": {"path": "{{ item.path }}", "regexp": "^\\s*gpgcheck\\s*=\\s*(0|false|no)\\s*$",
                                         "replace": "gpgcheck=1"},
             "loop": f"{{{{ {P}_repos_{slug(rid)}.files }}}}", "loop_control": {"label": "{{ item.path }}"}},
        ], "remediate"
    if t.startswith("Ensure repo_gpgcheck"):
        return [
            {"name": f"{rid} | PATCH | Enable repo_gpgcheck globally (opt-in)",
             "community.general.ini_file": {"path": "/etc/dnf/dnf.conf", "section": "main",
                                            "option": "repo_gpgcheck", "value": "1", "no_extra_spaces": True},
             "when": f"{P}_enable_repo_gpgcheck | bool"},
            c.finding(rid, T, "action_required",
                      "['repo_gpgcheck not enforced: Red Hat CDN repositories do not sign repodata. Set %s_enable_repo_gpgcheck=true only if all repos support it']" % P,
                      when=f"not {P}_enable_repo_gpgcheck | bool"),
        ], "remediate"
    if t == "Ensure package manager repositories are configured":
        return c.manual(rid, T, "dnf repolist -v 2>/dev/null | grep -E '^(Repo-id|Repo-baseurl)'"), "manual"
    if t == "Ensure weak dependencies are configured":
        return [{"name": f"{rid} | PATCH | Disable weak dependencies",
                 "community.general.ini_file": {"path": "/etc/dnf/dnf.conf", "section": "main",
                                                "option": "install_weak_deps", "value": "0", "no_extra_spaces": True}}], "remediate"
    if t.startswith("Ensure updates, patches"):
        return [
            {"name": f"{rid} | PATCH | Apply all package updates (opt-in)",
             "ansible.builtin.dnf": {"name": "*", "state": "latest"},
             "when": f"{P}_apply_updates | bool"},
        ] + c.manual(rid, T, "dnf -q check-update 2>/dev/null | head -50 || true"), "manual"

    # ------------------------------------------------------------ 1.3 SELinux
    if t == "Ensure SELinux is installed":
        return [c.pkg(rid, ["libselinux"], "present")], "remediate"
    if t == "Ensure SELinux is not disabled in bootloader configuration":
        return [
            *grubby(c, rid, "selinux=0 enforcing=0", remove=True),
            {"name": f"{rid} | PATCH | Remove selinux=0 / enforcing=0 from /etc/default/grub",
             "ansible.builtin.replace": {"path": "/etc/default/grub", "regexp": "\\s*(selinux|enforcing)=0"},
             "notify": f"{P} grub2 mkconfig"},
        ], "remediate"
    if t == "Ensure SELinux policy is configured":
        return [c.lineinfile(rid, "/etc/selinux/config", "^\\s*SELINUXTYPE=", f"SELINUXTYPE={{{{ {P}_selinux_policy }}}}", create=False)], "remediate"
    if t == "Ensure the SELinux mode is not disabled":
        return [
            {"name": f"{rid} | PATCH | Change SELINUX=disabled to permissive (reboot + relabel required)",
             "ansible.builtin.replace": {"path": "/etc/selinux/config",
                                         "regexp": "^(\\s*)SELINUX=disabled\\s*$",
                                         "replace": "\\1SELINUX=permissive"},
             "notify": f"{P} flag reboot"},
        ], "remediate"
    if t == "Ensure the SELinux mode is enforcing":
        return [
            c.lineinfile(rid, "/etc/selinux/config", "^\\s*SELINUX=", "SELINUX=enforcing", create=False),
            {"name": f"{rid} | PATCH | Switch running mode to enforcing",
             "ansible.builtin.command": "setenforce 1",
             "when": "ansible_facts.selinux.status == 'enabled' and ansible_facts.selinux.mode == 'permissive'",
             "changed_when": True},
        ], "remediate"
    if t == "Ensure no unconfined services exist":
        return c.manual(rid, T, "ps -eZ | grep unconfined_service_t || true"), "manual"
    if "mcstrans" in t:
        return [c.pkg(rid, ["mcstrans"], "absent")], "remediate"
    if t == "Ensure SETroubleshoot is not installed":
        return [c.pkg(rid, ["setroubleshoot"], "absent")], "remediate"

    # ------------------------------------------------------------ 1.4 boot
    if t == "Ensure bootloader password is set":
        return [
            {"name": f"{rid} | PATCH | Write GRUB2 PBKDF2 password to user.cfg",
             "ansible.builtin.copy": {"dest": "{{ %s_grub_dir }}/user.cfg" % P,
                                      "content": "GRUB2_PASSWORD={{ %s_bootloader_password_hash }}\n" % P,
                                      "owner": "root", "group": "root", "mode": "0600"},
             "no_log": True,
             "when": f"{P}_bootloader_password_hash | length > 0"},
            c.finding(rid, T, "action_required",
                      f"['Set {P}_bootloader_password_hash (output of grub2-mkpasswd-pbkdf2) to remediate']",
                      when=f"{P}_bootloader_password_hash | length == 0"),
        ], "remediate"
    if t == "Ensure access to bootloader config is configured":
        return c.find_perms(rid, "{{ %s_grub_dir }}" % P, "*", "u-x,go-rwx"), "remediate"
    m = re.match(r"Ensure authentication is required when booting into (rescue|emergency) mode", t)
    if m:
        unit = m.group(1)
        return [
            {"name": f"{rid} | PATCH | Require sulogin for {unit}.service",
             "ansible.builtin.copy": {"dest": f"/etc/systemd/system/{unit}.service.d/00-require-auth.conf",
                                      "content": f"[Service]\nExecStart=\nExecStart=-/usr/lib/systemd/systemd-sulogin-shell {unit}\n",
                                      "owner": "root", "group": "root", "mode": "0644"},
             "notify": f"{P} systemd daemon-reload"},
        ], "remediate"
    if t.startswith("Ensure systemd ability to spawn an interactive boot"):
        return [
            *grubby(c, rid, "systemd.confirm_spawn", remove=True),
            {"name": f"{rid} | PATCH | Remove systemd.confirm_spawn from /etc/default/grub",
             "ansible.builtin.replace": {"path": "/etc/default/grub", "regexp": "\\s*systemd\\.confirm_spawn(=\\S+)?"},
             "notify": f"{P} grub2 mkconfig"},
        ], "remediate"

    # ------------------------------------------------- 1.5 process hardening
    if t == "Ensure core file size is configured":
        return [
            {"name": f"{rid} | PATCH | Comment out hard core limits > 0",
             "ansible.builtin.shell": {"cmd": "grep -lE '^\\s*[^#]+\\s+hard\\s+core\\s+[1-9]' /etc/security/limits.conf /etc/security/limits.d/*.conf 2>/dev/null | "
                                              "while read -r f; do [ \"$DRY\" = 1 ] || sed -ri '/^\\s*[^#]+\\s+hard\\s+core\\s+[1-9]/s/^/# /' \"$f\"; echo CHANGED; done\n",
                                       "executable": "/bin/bash"},
             "environment": {"DRY": "{{ ansible_check_mode | ternary('1', '0') }}"},
             "register": f"{P}_core_{slug(rid)}", "changed_when": f"'CHANGED' in {P}_core_{slug(rid)}.stdout",
             "check_mode": False},
            {"name": f"{rid} | PATCH | Set * hard core 0",
             "ansible.builtin.copy": {"dest": "/etc/security/limits.d/60-cis-core.conf",
                                      "content": "# Managed by Ansible - CIS\n* hard core 0\n",
                                      "owner": "root", "group": "root", "mode": "0644"}},
        ], "remediate"
    m = re.match(r"Ensure ((?:fs|kernel|net)\.[\w.]+) is configured", t)
    if m:
        key = m.group(1)
        val = SYSCTL[key]
        task = {"name": f"{rid} | PATCH | {key} = {val}",
                "ansible.posix.sysctl": {"name": key, "value": str(val), "state": "present",
                                         "sysctl_file": "{{ %s_sysctl_file }}" % P, "sysctl_set": True,
                                         "reload": True}}
        if key.startswith("net.ipv6"):
            task["when"] = f"{P}_ipv6_enabled | bool"
        return [task], "remediate"
    m = re.match(r"Ensure systemd-coredump (ProcessSizeMax|Storage) is configured", t)
    if m:
        opt = m.group(1)
        val = "0" if opt == "ProcessSizeMax" else "none"
        return [{"name": f"{rid} | PATCH | Coredump {opt}={val}",
                 "community.general.ini_file": {"path": "/etc/systemd/coredump.conf.d/60-cis.conf",
                                                "section": "Coredump", "option": opt, "value": val,
                                                "no_extra_spaces": True, "create": True, "mode": "0644"}}], "remediate"

    # ----------------------------------------------------- 1.6 crypto policy
    if t.startswith("Ensure system wide crypto policy is not"):
        return [{"name": f"{rid} | PATCH | Replace LEGACY base policy",
                 "ansible.builtin.set_fact": {f"{P}_crypto_base": "{{ %s_crypto_policy_base }}" % P},
                 "changed_when": f"{P}_crypto_current.split(':')[0] == 'LEGACY'",
                 "notify": f"{P} update crypto policy"}], "remediate"
    crypto = {
        "disables sha1 hash and signature support": ("NO-SHA1", "hash = -SHA1\nsign = -*-SHA1\nsha1_in_certs = 0\n"),
        "macs are configured": ("NO-WEAKMAC", "mac = -*-128*\n"),
        "disables cbc for ssh": ("NO-SSHCBC", "cipher@SSH = -*-CBC\n"),
        "disables chacha20poly1305 for ssh": ("NO-SSHCHACHA20", "cipher@SSH = -CHACHA20-POLY1305\n"),
        "disables EtM for ssh": ("NO-SSHETM", "etm@SSH = DISABLE_ETM\n"),
    }
    for frag, (modname, content) in crypto.items():
        if t == "Ensure system wide crypto policy " + frag:
            tasks = [
                {"name": f"{rid} | PATCH | Create {modname}.pmod",
                 "ansible.builtin.copy": {"dest": f"/etc/crypto-policies/policies/modules/{modname}.pmod",
                                          "content": f"# Managed by Ansible - CIS {rid}\n{content}",
                                          "owner": "root", "group": "root", "mode": "0644"},
                 "notify": f"{P} update crypto policy"},
                {"name": f"{rid} | PATCH | Add {modname} to the policy",
                 "ansible.builtin.set_fact": {f"{P}_crypto_modules": "{{ %s_crypto_modules + ['%s'] }}" % (P, modname)},
                 "changed_when": f"'{modname}' not in {P}_crypto_current.split(':')",
                 "notify": f"{P} update crypto policy"},
            ]
            if modname in ("NO-SSHCHACHA20", "NO-SSHETM"):
                for x in tasks:
                    x["when"] = f"{P}_ssh_terrapin_mitigation | bool"
                tasks.append(c.finding(rid, T, "info",
                                       f"['Skipped: OpenSSH has the Terrapin fix; set {P}_ssh_terrapin_mitigation=true to enforce']",
                                       when=f"not {P}_ssh_terrapin_mitigation | bool"))
            return tasks, "remediate"
    if t == "Ensure system wide crypto policy enables post-quantum algorithms":
        return [
            {"name": f"{rid} | AUDIT | Check PQ subpolicy availability",
             "ansible.builtin.stat": {"path": "/usr/share/crypto-policies/policies/modules/PQ.pmod"},
             "register": f"{P}_pq_{slug(rid)}"},
            {"name": f"{rid} | PATCH | Add PQ to the policy",
             "ansible.builtin.set_fact": {f"{P}_crypto_modules": "{{ %s_crypto_modules + ['PQ'] }}" % P},
             "changed_when": f"'PQ' not in {P}_crypto_current.split(':')",
             "when": f"{P}_pq_{slug(rid)}.stat.exists", "notify": f"{P} update crypto policy"},
        ], "remediate"

    # ------------------------------------------------------------ 1.7 banners
    m = re.match(r"Ensure (/etc/(?:motd|issue|issue\.net)) is configured", t)
    if m:
        path = m.group(1)
        var = {"/etc/motd": "motd", "/etc/issue": "issue", "/etc/issue.net": "issue_net"}[path]
        return [{"name": f"{rid} | PATCH | Write {path}",
                 "ansible.builtin.copy": {"dest": path, "content": "{{ %s_banner_%s }}" % (P, var),
                                          "owner": "root", "group": "root", "mode": "0644"}}], "remediate"

    # ---------------------------------------------------------------- 1.8 GDM
    if t.startswith("Ensure GDM") or t in ("Ensure XDMCP is not enabled", "Ensure Xwayland is configured",
                                           "Ensure Wayland is configured"):
        return gdm(c, r), "remediate"

    # --------------------------------------------------------- 2.1 services
    m = re.match(r"Ensure (.+?) services are not in use", t)
    if m and m.group(1) in SERVICES:
        pkgs, units = SERVICES[m.group(1)]
        return svc_disable(c, rid, pkgs, units, remove_only=(m.group(1) == "X window server")), "remediate"
    if t == "Ensure systemd-journal-remote service is not in use" or t == "Ensure systemd-journal-remote is not in use":
        return svc_disable(c, rid, [], ["systemd-journal-remote.socket", "systemd-journal-remote.service"],
                           mask_only=True), "remediate"
    if t in ("Ensure GNOME Display Manager is removed", "Ensure a graphical user interface is not in use"):
        return [c.pkg(rid, ["gdm"], "absent", "Remove GDM (graphical login)")], "remediate"
    if t == "Ensure Xwayland is not in use":
        return [c.pkg(rid, ["xorg-x11-server-Xwayland"], "absent")], "remediate"
    if t == "Ensure mail transfer agents are configured for local-only mode":
        return [
            {"name": f"{rid} | PATCH | Postfix inet_interfaces = loopback-only",
             "ansible.builtin.lineinfile": {"path": "/etc/postfix/main.cf", "regexp": "^\\s*inet_interfaces\\s*=",
                                            "line": "inet_interfaces = loopback-only"},
             "when": "'postfix' in ansible_facts.packages", "notify": f"{P} restart postfix"},
        ] + c.audit(rid, T, "ss -plntu | grep -P ':(25|465|587)\\b' | grep -Pv '\\h+(127\\.0\\.0\\.1|\\[?::1\\]?):(25|465|587)\\b' || true"), "remediate"
    if t == "Ensure only approved services are listening on a network interface":
        return c.manual(rid, T, "ss -plntu"), "manual"

    # ---------------------------------------------------------- 2.2 clients
    m = re.match(r"Ensure (\w+) client is not installed", t)
    if m:
        return [c.pkg(rid, CLIENTS[m.group(1)], "absent")], "remediate"

    # ------------------------------------------------------------- 2.3 time
    if t == "Ensure time synchronization is in use":
        return [c.pkg(rid, ["chrony"], "present"),
                {"name": f"{rid} | PATCH | Enable chronyd",
                 "ansible.builtin.systemd": {"name": "chronyd", "enabled": True, "state": "started"}}], "remediate"
    if t == "Ensure chrony is configured":
        return c.script(rid, "Add time sources if none are configured", """
if ! grep -Prsq '^\\s*(server|pool)\\s+\\S+' /etc/chrony.conf /etc/chrony.d/ 2>/dev/null; then
  echo CHANGED
  if [ "$DRY" != 1 ]; then
    :
{% for s in P_time_sources %}
    echo '{{ s }}' >> /etc/chrony.conf
{% endfor %}
  fi
fi
""", notify=f"{P} restart chronyd"), "remediate"
    if t == "Ensure chrony is not run as the root user":
        return [{"name": f"{rid} | PATCH | Remove '-u root' from chronyd OPTIONS",
                 "ansible.builtin.replace": {"path": "/etc/sysconfig/chronyd", "regexp": "-u\\s+root\\s*"},
                 "notify": f"{P} restart chronyd"}], "remediate"

    # ------------------------------------------------------------- 2.4 cron
    if t == "Ensure cron daemon is enabled and active":
        return [{"name": f"{rid} | PATCH | Enable crond",
                 "ansible.builtin.systemd": {"name": "crond", "enabled": True, "state": "started"},
                 "when": "'cronie' in ansible_facts.packages"}], "remediate"
    if t == "Ensure access to crontab is configured":
        return [
            {"name": f"{rid} | PATCH | Create /etc/cron.allow",
             "ansible.builtin.file": {"path": "/etc/cron.allow", "state": "touch", "owner": "root",
                                      "group": "root", "mode": "u-x,g-wx,o-rwx",
                                      "modification_time": "preserve", "access_time": "preserve"},
             "when": "'cronie' in ansible_facts.packages"},
        ] + c.perms(rid, [("/etc/cron.deny", ("root", "root", "u-x,g-wx,o-rwx"))]), "remediate"
    if t == "Ensure access to at is configured":
        return [
            {"name": f"{rid} | PATCH | Create /etc/at.allow",
             "ansible.builtin.file": {"path": "/etc/at.allow", "state": "touch", "owner": "root",
                                      "group": "{{ 'daemon' if 'daemon' in %s_groups else 'root' }}" % P,
                                      "mode": "u-x,g-wx,o-rwx",
                                      "modification_time": "preserve", "access_time": "preserve"},
             "when": "'at' in ansible_facts.packages"},
            {"name": f"{rid} | PATCH | Secure /etc/at.deny if present",
             "ansible.builtin.file": {"path": "/etc/at.deny", "owner": "root",
                                      "group": "{{ 'daemon' if 'daemon' in %s_groups else 'root' }}" % P,
                                      "mode": "u-x,g-wx,o-rwx"},
             "when": f"'at' in ansible_facts.packages and {P}_at_deny.stat.exists"},
        ], "remediate"

    # ------------------------------------------------------- 3.1 networking
    if t == "Ensure IPv6 status is identified":
        return c.manual(rid, T, "grep -Pqs '^\\h*0\\b' /sys/module/ipv6/parameters/disable && echo 'IPv6 is enabled' || echo 'IPv6 is not enabled'"), "manual"
    if t == "Ensure wireless interfaces are not available":
        return c.script(rid, "Disable wireless kernel drivers", """
for d in /sys/class/net/*/wireless; do
  [ -d "$d" ] || continue
  mod=$(basename "$(readlink -f "$(dirname "$d")/device/driver/module")")
  [ -n "$mod" ] || continue
  if ! grep -qs "install $mod /bin/false" /etc/modprobe.d/cis-wireless.conf; then
    echo "CHANGED $mod"
    if [ "$DRY" != 1 ]; then
      printf 'install %s /bin/false\\nblacklist %s\\n' "$mod" "$mod" >> /etc/modprobe.d/cis-wireless.conf
      modprobe -r "$mod" 2>/dev/null || true
    fi
  fi
done
"""), "remediate"

    # ------------------------------------------------------------ 4 firewalld
    if t.startswith("Ensure firewalld") or t.startswith("Ensure conflicting firewall utilities"):
        return firewalld(c, r), ("manual" if r["type"] == "manual" else "remediate")

    # --------------------------------------------------------------- 5.1 ssh
    if t.startswith("Ensure sshd ") or "ssh" in t.lower() and t.startswith("Ensure access to"):
        res = ssh(c, r)
        if res:
            return res, "remediate"

    # --------------------------------------------------------------- 5.2 sudo
    if "sudo" in t or "privilege escalation" in t or t == "Ensure users must provide password for escalation" \
            or t == "Ensure access to the su command is restricted":
        res = sudo(c, r)
        if res:
            return res

    # --------------------------------------------------------------- 5.3 PAM
    res = pam(c, r)
    if res:
        return res

    # ---------------------------------------------------- 5.4 accounts
    res = accounts(c, r)
    if res:
        return res

    # ------------------------------------------------------ 6 logging/audit/aide
    res = logging_audit(c, r)
    if res:
        return res

    # ----------------------------------------------- generic file permissions
    m = re.match(r"Ensure access to (/\S+?)/? is configured", t)
    if m:
        path = m.group(1)
        key = path if path in FILE_PERMS else path + "/"
        if key in FILE_PERMS:
            extra = []
            if path == "/etc/security/opasswd":
                extra = [("/etc/security/opasswd.old", FILE_PERMS[key])]
            return c.perms(rid, [(key, FILE_PERMS[key])] + extra), "remediate"

    # ------------------------------------------------------------- 7 system
    res = system_maint(c, r)
    if res:
        return res

    return None, None


def grubby(c, rid, args, remove=False):
    """Idempotent kernel argument change on every installed kernel."""
    P = c.p
    names = " ".join(a.split("=")[0] for a in args.split())
    if remove:
        body = f"""
for a in {names}; do
  if grubby --info=ALL 2>/dev/null | grep '^args=' | grep -Eq "[\\" ]$a(=[^ \\"]*)?[\\" ]"; then
    echo "CHANGED $a"; [ "$DRY" = 1 ] || grubby --update-kernel ALL --remove-args="$a"
  fi
done
"""
    else:
        body = f"""
for a in {args}; do
  if grubby --info=ALL 2>/dev/null | grep '^args=' | grep -vEq "[\\\" ]$a[\\\" ]"; then
    echo "CHANGED $a"; [ "$DRY" = 1 ] || grubby --update-kernel ALL --args="$a"
  fi
done
"""
    return c.script(rid, ("Remove" if remove else "Add") + f" kernel argument(s) {args}", body,
                    notify=f"{P} flag reboot")


# ==========================================================================
# Families
# ==========================================================================

def svc_disable(c, rid, pkgs, units, remove_only=False, mask_only=False):
    P = c.p
    mask = {"name": f"{rid} | PATCH | Stop and mask units",
            "ansible.builtin.systemd": {"name": "{{ item }}", "state": "stopped",
                                                "enabled": False, "masked": True},
            "loop": units, "when": [f"item in {P}_unit_files"]}
    if remove_only:
        return [c.pkg(rid, pkgs, "absent")]
    if mask_only:
        return [mask]
    mask["when"].insert(0, f"{P}_service_remediation == 'mask'")
    return [c.pkg(rid, pkgs, "absent", "Remove packages", when=f"{P}_service_remediation == 'remove'"), mask]


def gdm(c, r):
    P, rid, t = c.p, r["id"], r["title"]
    when_gdm = "'gdm' in ansible_facts.packages"

    def dconf(path, content, label, locks=None, db="local"):
        ts = [
            {"name": f"{rid} | PATCH | dconf profile 'user'",
             "ansible.builtin.copy": {"dest": "/etc/dconf/profile/user",
                                      "content": "user-db:user\nsystem-db:local\n", "mode": "0644",
                                      "force": False}},
            {"name": f"{rid} | PATCH | {label}",
             "ansible.builtin.copy": {"dest": f"/etc/dconf/db/{db}.d/{path}", "content": content,
                                      "owner": "root", "group": "root", "mode": "0644"},
             "notify": f"{P} dconf update"},
        ]
        if locks:
            ts.append({"name": f"{rid} | PATCH | Lock settings",
                       "ansible.builtin.copy": {"dest": f"/etc/dconf/db/{db}.d/locks/{path}",
                                                "content": "\n".join(locks) + "\n", "owner": "root",
                                                "group": "root", "mode": "0644"},
                       "notify": f"{P} dconf update"})
        return ts

    gdm_profile = {"name": f"{rid} | PATCH | dconf profile 'gdm'",
                   "ansible.builtin.copy": {"dest": "/etc/dconf/profile/gdm",
                                            "content": "user-db:user\nsystem-db:gdm\nfile-db:/usr/share/gdm/greeter-dconf-defaults\n",
                                            "mode": "0644"}}
    if t == "Ensure GDM login banner is configured":
        ts = [gdm_profile] + dconf("01-banner-message",
                                    "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text='{{ %s_gdm_banner_text }}'\n" % P,
                                    "Login banner", ["/org/gnome/login-screen/banner-message-enable",
                                                     "/org/gnome/login-screen/banner-message-text"], db="gdm")[1:]
    elif t == "Ensure GDM disable-user-list is configured":
        ts = [gdm_profile] + dconf("00-login-screen", "[org/gnome/login-screen]\ndisable-user-list=true\n",
                                    "Disable user list", ["/org/gnome/login-screen/disable-user-list"], db="gdm")[1:]
    elif t == "Ensure GDM screen lock is configured":
        ts = dconf("00-screensaver",
                   "[org/gnome/desktop/session]\nidle-delay=uint32 {{ %s_gdm_idle_delay }}\n\n[org/gnome/desktop/screensaver]\nlock-delay=uint32 {{ %s_gdm_lock_delay }}\n" % (P, P),
                   "Screen lock", ["/org/gnome/desktop/session/idle-delay", "/org/gnome/desktop/screensaver/lock-delay"])
    elif t == "Ensure GDM automount is configured":
        ts = dconf("00-media-automount", "[org/gnome/desktop/media-handling]\nautomount=false\nautomount-open=false\n",
                   "Disable automount", ["/org/gnome/desktop/media-handling/automount",
                                         "/org/gnome/desktop/media-handling/automount-open"])
    elif t == "Ensure GDM autorun-never is configured":
        ts = dconf("00-media-autorun", "[org/gnome/desktop/media-handling]\nautorun-never=true\n",
                   "Autorun never", ["/org/gnome/desktop/media-handling/autorun-never"])
    elif t == "Ensure XDMCP is not enabled":
        ts = [{"name": f"{rid} | PATCH | Remove Enable=true from [xdmcp]",
               "community.general.ini_file": {"path": "/etc/gdm/custom.conf", "section": "xdmcp",
                                              "option": "Enable", "state": "absent"}}]
    elif t == "Ensure Xwayland is configured":
        ts = [{"name": f"{rid} | PATCH | WaylandEnable=false",
               "community.general.ini_file": {"path": "/etc/gdm/custom.conf", "section": "daemon",
                                              "option": "WaylandEnable", "value": "false", "no_extra_spaces": True}}]
    elif t == "Ensure Wayland is configured":
        ts = [{"name": f"{rid} | PATCH | Remove WaylandEnable=false (use Wayland)",
               "community.general.ini_file": {"path": "/etc/gdm/custom.conf", "section": "daemon",
                                              "option": "WaylandEnable", "state": "absent"}}]
    else:
        return []
    return [{"name": f"{rid} | GDM is installed", "when": when_gdm, "block": ts}]


def firewalld(c, r):
    P, rid, t = c.p, r["id"], r["title"]
    fw_ok = "'firewalld' in ansible_facts.packages"
    if t == "Ensure firewalld is installed":
        return [c.pkg(rid, ["firewalld", "nftables"], "present"),
                {"name": f"{rid} | AUDIT | Refresh package facts", "ansible.builtin.package_facts": {"manager": "auto"}}]
    if t == "Ensure firewalld backend is configured":
        return [c.lineinfile(rid, "/etc/firewalld/firewalld.conf", "^\\s*FirewallBackend=",
                             "FirewallBackend=nftables", notify=f"{P} reload firewalld", create=False,
                             when=fw_ok)]
    if t == "Ensure firewalld.service is configured":
        return [
            *c.script(rid, "Allow management services in the default zone before enabling", """
command -v firewall-cmd >/dev/null || exit 0
if systemctl -q is-active firewalld; then fw="firewall-cmd --permanent"; else fw="firewall-offline-cmd"; fi
for s in {{ P_firewalld_allowed_services | join(' ') }}; do
  $fw --query-service="$s" >/dev/null 2>&1 || { echo "CHANGED $s"; [ "$DRY" = 1 ] || $fw --add-service="$s" >/dev/null; }
done
"""),
            {"name": f"{rid} | PATCH | Enable and start firewalld",
             "ansible.builtin.systemd": {"name": "firewalld", "enabled": True, "state": "started",
                                                 "masked": False}, "when": fw_ok},
        ]
    if t == "Ensure firewalld active zone target is configured":
        return c.script(rid, "Change zones with target ACCEPT", """
command -v firewall-cmd >/dev/null || exit 0
for z in $(firewall-cmd --get-active-zones 2>/dev/null | grep -v '^\\s' ); do
  [ "$z" = trusted ] && continue
  if [ "$(firewall-cmd --permanent --zone="$z" --get-target)" = "ACCEPT" ]; then
    echo "CHANGED $z"
    [ "$DRY" = 1 ] || firewall-cmd --permanent --zone="$z" --set-target={{ P_firewalld_zone_target }}
  fi
done
""", notify=f"{P} reload firewalld")
    if t == "Ensure firewalld logs denied packets":
        return c.script(rid, "Log denied packets", """
command -v firewall-cmd >/dev/null || exit 0
if [ "$(firewall-cmd --get-log-denied)" = "off" ]; then echo CHANGED; [ "$DRY" = 1 ] || firewall-cmd --set-log-denied={{ P_firewalld_log_denied }}; fi
""")
    if t == "Ensure firewalld blocks ICMP timestamp requests and replies":
        return c.script(rid, "Block ICMP timestamp on default-target zones", """
command -v firewall-cmd >/dev/null || exit 0
for z in $(firewall-cmd --get-active-zones 2>/dev/null | grep -v '^\\s'); do
  [ "$(firewall-cmd --permanent --zone="$z" --get-target)" = "default" ] || continue
  for b in timestamp-request timestamp-reply; do
    if ! firewall-cmd --permanent --zone="$z" --query-icmp-block=$b >/dev/null 2>&1; then
      echo "CHANGED $z $b"; [ "$DRY" = 1 ] || firewall-cmd --permanent --zone="$z" --add-icmp-block=$b >/dev/null
    fi
  done
done
""", notify=f"{P} reload firewalld")
    if t == "Ensure conflicting firewall utilities are not in use with firewalld":
        return svc_disable(c, rid, [], ["iptables.service", "ip6tables.service", "nftables.service"], mask_only=True)
    ev = {"loopback traffic": "firewall-cmd --list-all 2>/dev/null",
          "loopback source address traffic": "firewall-cmd --direct --get-all-rules 2>/dev/null; firewall-cmd --list-rich-rules 2>/dev/null",
          "services and ports": "firewall-cmd --list-all-zones 2>/dev/null | grep -E '^\\S|services:|ports:'",
          "default zone": "firewall-cmd --get-default-zone 2>/dev/null"}
    for k, cmd in ev.items():
        if k in t:
            return c.manual(rid, t, cmd)
    return c.manual(rid, t)


def ssh(c, r):
    P, rid, t = c.p, r["id"], r["title"]
    dropin = "/etc/ssh/sshd_config.d/00-cis-hardening.conf"
    notify = f"{P} restart sshd"
    if t == "Ensure access to /etc/ssh/sshd_config is configured":
        return c.perms(rid, [("/etc/ssh/sshd_config", ("root", "root", "u-x,go-rwx"))]) + \
            c.find_perms(rid + "_d", "/etc/ssh/sshd_config.d", "*.conf", "u-x,go-rwx")
    if t == "Ensure access to SSH private host key files is configured":
        return [
            {"name": f"{rid} | AUDIT | Find private host keys", "ansible.builtin.find":
                {"paths": "/etc/ssh", "patterns": "ssh_host_*_key"}, "register": f"{P}_hk_{slug(rid)}"},
            {"name": f"{rid} | PATCH | Secure private host keys",
             "ansible.builtin.file": {"path": "{{ item.path }}", "owner": "root",
                                      "group": "{{ 'ssh_keys' if 'ssh_keys' in %s_groups else 'root' }}" % P,
                                      "mode": "{{ 'u-x,g-wx,o-rwx' if 'ssh_keys' in %s_groups else 'u-x,go-rwx' }}" % P},
             "loop": f"{{{{ {P}_hk_{slug(rid)}.files }}}}", "loop_control": {"label": "{{ item.path }}"}},
        ]
    if t == "Ensure access to SSH public host key files is configured":
        return c.find_perms(rid, "/etc/ssh", "ssh_host_*_key.pub", "u-x,go-wx")
    if t == "Ensure access to /etc/sysconfig/sshd is configured":
        return c.perms(rid, [("/etc/sysconfig/sshd", FILE_PERMS["/etc/sysconfig/sshd"])])
    if t == "Ensure access to /etc/ssh/sshd_config.d/ directory is configured":
        return c.perms(rid, [("/etc/ssh/sshd_config.d", ("root", "root", "0700"))])
    if t == "Ensure sshd crypto_policy is not set":
        return [{"name": f"{rid} | PATCH | Comment out CRYPTO_POLICY in /etc/sysconfig/sshd",
                 "ansible.builtin.replace": {"path": "/etc/sysconfig/sshd", "regexp": "^(\\s*CRYPTO_POLICY\\s*=.*)$",
                                             "replace": "# \\1"}, "notify": notify}]
    for frag, (k, val) in SSHD_SIMPLE.items():
        if t == "Ensure sshd " + frag:
            return [c.lineinfile(rid, dropin, f"^\\s*#?\\s*{k}\\s", f"{k} {c.s(val)}", notify=notify, mode="0600")]
    if t == "Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured":
        return [c.lineinfile(rid, dropin, "^\\s*#?\\s*ClientAliveInterval\\s",
                             "ClientAliveInterval {{ %s_sshd_client_alive_interval }}" % P, notify=notify, mode="0600"),
                c.lineinfile(rid, dropin, "^\\s*#?\\s*ClientAliveCountMax\\s",
                             "ClientAliveCountMax {{ %s_sshd_client_alive_count_max }}" % P, notify=notify, mode="0600")]
    if t == "Ensure sshd access is configured":
        tasks = []
        for k in ("AllowUsers", "AllowGroups", "DenyUsers", "DenyGroups"):
            var = f"{P}_sshd_{k.lower()[:-1] if False else k.lower()}"
            tasks.append(c.lineinfile(rid, dropin, f"^\\s*#?\\s*{k}\\s", f"{k} {{{{ {var} | join(' ') }}}}",
                                      notify=notify, mode="0600", label=f"Set {k}",
                                      when=f"{var} | length > 0"))
        tasks.append(c.finding(rid, t, "action_required",
                               f"['No sshd Allow/Deny list configured. Set {P}_sshd_allowgroups (recommended) - not set automatically to avoid lock-out']",
                               when=" and ".join(f"{P}_sshd_{k} | length == 0" for k in
                                                 ("allowusers", "allowgroups", "denyusers", "denygroups"))))
        return tasks
    for k, (low, var) in SSHD_WEAK.items():
        if t == f"Ensure sshd {k} are configured" or t == f"Ensure sshd {k} is configured":
            reg = f"{P}_sshdt_{slug(rid)}"
            return [
                {"name": f"{rid} | AUDIT | Read effective {k}",
                 "ansible.builtin.shell": f"sshd -T 2>/dev/null | awk '$1==\"{low}\"{{print $2}}'",
                 "register": reg, "changed_when": False, "failed_when": False, "check_mode": False},
                c.lineinfile(rid, dropin, f"^\\s*#?\\s*{k}\\s", f"{k} -{{{{ {c.s(var)} | join(',') }}}}",
                             notify=notify, mode="0600", label=f"Remove weak {k}",
                             when=f"({reg}.stdout.split(',') | intersect({c.s(var)})) | length > 0"),
            ]
    return None


def sudo(c, r):
    P, rid, t = c.p, r["id"], r["title"]
    f = "/etc/sudoers.d/zz-cis-hardening"
    val = "/usr/sbin/visudo -cf %s"

    def d(line, rx):
        return [c.lineinfile(rid, f, rx, line, mode="0440", validate=val)]

    if t == "Ensure sudo is installed":
        return [c.pkg(rid, ["sudo"], "present")], "remediate"
    if t == "Ensure sudo commands use pty":
        return d("Defaults use_pty", "^\\s*Defaults\\s+use_pty") + c.audit(
            rid, t, "grep -rPi '^\\h*Defaults\\h+([^#\\n\\r]+,\\h*)?!use_pty\\b' /etc/sudoers /etc/sudoers.d/ || true"), "remediate"
    if t == "Ensure sudo log file exists":
        return d('Defaults logfile="{{ %s_sudo_logfile }}"' % P, "^\\s*Defaults\\s+logfile="), "remediate"
    if t == "Ensure sudo pwfeedback is configured":
        return d("Defaults !pwfeedback", "^\\s*Defaults\\s+!?pwfeedback"), "remediate"
    if t == "Ensure sudo visiblepw is configured":
        return d("Defaults !visiblepw", "^\\s*Defaults\\s+!?visiblepw"), "remediate"
    if t == "Ensure sudo timestamp_type is configured":
        return d("Defaults timestamp_type=tty", "^\\s*Defaults\\s+timestamp_type="), "remediate"
    if t == "Ensure sudo timestamp_timeout is configured":
        return d("Defaults timestamp_timeout={{ %s_sudo_timestamp_timeout }}" % P, "^\\s*Defaults\\s+timestamp_timeout="), "remediate"
    if t == "Ensure users must provide password for escalation":
        return c.audit(rid, t, "grep -rP '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/ || true",
                       kind="action_required") + [
            {"name": f"{rid} | PATCH | Remove NOPASSWD (opt-in, can break automation accounts)",
             "ansible.builtin.shell": {"cmd": "for f in /etc/sudoers /etc/sudoers.d/*; do grep -q NOPASSWD \"$f\" && sed -ri 's/NOPASSWD:\\s*//g' \"$f\" && visudo -cf \"$f\" && echo CHANGED; done; true",
                                       "executable": "/bin/bash"},
             "register": f"{P}_nopw_{slug(rid)}", "changed_when": f"'CHANGED' in {P}_nopw_{slug(rid)}.stdout",
             "when": f"{P}_sudo_remove_nopasswd | bool and not ansible_check_mode"}], "remediate"
    if t == "Ensure re-authentication for privilege escalation is not disabled globally":
        return c.script(rid, "Remove !authenticate tags", """
for f in /etc/sudoers /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  if grep -Eq '^[^#].*!authenticate' "$f"; then
    echo "CHANGED $f"
    [ "$DRY" = 1 ] || { cp -a "$f" "/root/$(basename "$f").cis-bak"; sed -ri '/^[^#].*!authenticate/s/^/# /' "$f"; visudo -cf "$f" >/dev/null || cp -a "/root/$(basename "$f").cis-bak" "$f"; }
  fi
done
"""), "remediate"
    if t == "Ensure access on sudoers configuration files is configured":
        return c.perms(rid, [("/etc/sudoers", ("root", "root", "u-wx,g-wx,o-rwx"))]) + \
            c.find_perms(rid + "_d", "/etc/sudoers.d", "*", "u-wx,g-wx,o-rwx"), "remediate"
    if t == "Ensure access on the /etc/sudoers.d directory is configured":
        return c.perms(rid, [("/etc/sudoers.d", ("root", "root", "g-w,o-rwx"))]), "remediate"
    if t == "Ensure access to the su command is restricted":
        return [
            {"name": f"{rid} | PATCH | Create empty su group",
             "ansible.builtin.group": {"name": "{{ %s_su_group }}" % P, "state": "present"}},
            {"name": f"{rid} | PATCH | Restrict su with pam_wheel",
             "ansible.builtin.lineinfile": {"path": "/etc/pam.d/su",
                                            "regexp": "^\\s*#?\\s*auth\\s+required\\s+pam_wheel\\.so",
                                            "line": "auth required pam_wheel.so use_uid group={{ %s_su_group }}" % P,
                                            "insertafter": "^\\s*auth\\s+sufficient\\s+pam_rootok\\.so"}},
        ], "remediate"
    return None


def pam(c, r):
    P, rid, t = c.p, r["id"], r["title"]
    prof = "{{ %s_authselect_dir }}" % P
    files = ["system-auth", "password-auth"]
    custom = f"{P}_authselect_is_custom | bool"

    def tmpl_replace(label, rx, rep):
        return {"name": f"{rid} | PATCH | {label}",
                "ansible.builtin.replace": {"path": f"{prof}/{{{{ item }}}}", "regexp": rx, "replace": rep},
                "loop": files, "when": custom, "notify": f"{P} authselect apply"}

    def need_custom():
        return c.finding(rid, t, "action_required",
                         "['PAM is not managed by a custom authselect profile; enable the authselect profile rule first']",
                         when=f"not {custom}")

    def kv(path, key, value, label=None, extra=None):
        ts = [c.lineinfile(rid, path, f"^\\s*#?\\s*{key}\\b", f"{key} = {value}" if value is not None else key,
                           label=label)]
        return ts

    m = re.match(r"Ensure latest version of (pam|authselect|libpwquality) is installed", t)
    if m:
        return [c.pkg(rid, [m.group(1)], "{{ 'latest' if %s_update_pam_packages | bool else 'present' }}" % P)], "remediate"
    if t in ("Ensure active authselect profile includes pam modules", "Ensure PAM is managed by an active authselect profile"):
        return [
            {"name": f"{rid} | PATCH | Create custom authselect profile",
             "ansible.builtin.command": "authselect create-profile {{ %s_authselect_profile }} -b {{ %s_authselect_base }}" % (P, P),
             "args": {"creates": "/etc/authselect/custom/{{ %s_authselect_profile }}" % P},
             "when": f"not {custom} and {P}_authselect_create_custom | bool"},
            {"name": f"{rid} | PATCH | Select the custom profile (keeps current features)",
             "ansible.builtin.command": "authselect select custom/{{ %s_authselect_profile }} {{ %s_authselect_features | join(' ') }} --force" % (P, P),
             "when": f"not {custom} and {P}_authselect_create_custom | bool", "changed_when": True},
            {"name": f"{rid} | PATCH | Refresh authselect facts",
             "ansible.builtin.set_fact": {f"{P}_authselect_dir": "/etc/authselect/custom/{{ %s_authselect_profile }}" % P,
                                          f"{P}_authselect_is_custom": True},
             "when": f"not {custom} and {P}_authselect_create_custom | bool and not ansible_check_mode"},
            need_custom(),
        ], "remediate"
    feat = {"Ensure pam_faillock module is enabled": "with-faillock",
            "Ensure pam_pwhistory module is enabled": "with-pwhistory",
            "Ensure pam_unix does not include nullok": "without-nullok"}
    if t in feat:
        return [{"name": f"{rid} | PATCH | authselect enable-feature {feat[t]}",
                 "ansible.builtin.command": f"authselect enable-feature {feat[t]}",
                 "when": [f"'{feat[t]}' not in {P}_authselect_features",
                          f"{P}_authselect_profile_current | length > 0 or {P}_authselect_is_custom | bool"],
                 "changed_when": True},
                {"name": f"{rid} | PATCH | Track feature", "ansible.builtin.set_fact":
                    {f"{P}_authselect_features": "{{ %s_authselect_features + ['%s'] }}" % (P, feat[t])},
                 "when": f"'{feat[t]}' not in {P}_authselect_features"}], "remediate"
    if t in ("Ensure pam_pwquality module is enabled", "Ensure pam_unix module is enabled"):
        mod = "pam_pwquality" if "pwquality" in t else "pam_unix"
        return c.audit(rid, t, f"for f in system-auth password-auth; do grep -Pq '^\\h*password\\h+\\S+\\h+{mod}\\.so' /etc/pam.d/$f || echo \"{mod} missing from $f\"; done"), "audit"

    # faillock.conf
    fl = "/etc/security/faillock.conf"
    if t == "Ensure password failed attempts lockout is configured":
        return kv(fl, "deny", "{{ %s_faillock_deny }}" % P) + [tmpl_replace("Remove deny= from pam_faillock", "(pam_faillock\\.so.*?)\\s+deny\\s*=\\s*\\S+", "\\1")], "remediate"
    if t == "Ensure password unlock time is configured":
        return kv(fl, "unlock_time", "{{ %s_faillock_unlock_time }}" % P) + [tmpl_replace("Remove unlock_time= from pam_faillock", "(pam_faillock\\.so.*?)\\s+unlock_time\\s*=\\s*\\S+", "\\1")], "remediate"
    if t == "Ensure password failed attempts lockout includes root account":
        return kv(fl, "even_deny_root", None, "even_deny_root") + kv(fl, "root_unlock_time", "{{ %s_faillock_root_unlock_time }}" % P) + \
            [tmpl_replace("Remove root args from pam_faillock", "(pam_faillock\\.so.*?)\\s+(even_deny_root|root_unlock_time\\s*=\\s*\\S+)", "\\1")], "remediate"

    # pwquality
    pq = "/etc/security/pwquality.conf.d/50-cis.conf"
    pqs = {"Ensure password number of changed characters is configured": ("difok", "{{ %s_pwquality_difok }}"),
           "Ensure password length is configured": ("minlen", "{{ %s_pwquality_minlen }}"),
           "Ensure password same consecutive characters is configured": ("maxrepeat", "{{ %s_pwquality_maxrepeat }}"),
           "Ensure password maximum sequential characters is configured": ("maxsequence", "{{ %s_pwquality_maxsequence }}"),
           "Ensure password complexity is configured": ("minclass", "{{ %s_pwquality_minclass }}"),
           "Ensure password dictionary check is enabled": ("dictcheck", "1"),
           "Ensure password quality is enforced for the root user": ("enforce_for_root", None)}
    if t in pqs:
        k, val = pqs[t]
        val = val % P if val and "%s" in val else val
        return [
            {"name": f"{rid} | PATCH | Comment out {k} in pwquality.conf",
             "ansible.builtin.replace": {"path": "/etc/security/pwquality.conf", "regexp": f"^(\\s*{k}\\b.*)$", "replace": "# \\1"}},
        ] + kv(pq, k, val) + [tmpl_replace(f"Remove {k}= from pam_pwquality", f"(pam_pwquality\\.so.*?)\\s+{k}\\s*=\\s*\\S+", "\\1")], \
            ("remediate")

    # pwhistory
    ph = "/etc/security/pwhistory.conf"
    if t == "Ensure password history remember is configured":
        return kv(ph, "remember", "{{ %s_pwhistory_remember }}" % P) + [tmpl_replace("Remove remember= from pam_pwhistory", "(pam_pwhistory\\.so.*?)\\s+remember\\s*=\\s*\\S+", "\\1")], "remediate"
    if t == "Ensure password history is enforced for the root user":
        return kv(ph, "enforce_for_root", None, "enforce_for_root"), "remediate"
    if t == "Ensure pam_pwhistory includes use_authtok":
        return [tmpl_replace("Add use_authtok to pam_pwhistory", "^(\\s*password\\s+\\S+\\s+pam_pwhistory\\.so)((?:(?!use_authtok).)*)$", "\\1\\2 use_authtok"), need_custom()], "remediate"
    if t == "Ensure pam_unix does not include remember":
        return [tmpl_replace("Remove remember= from pam_unix", "(pam_unix\\.so.*?)\\s+remember\\s*=\\s*\\S+", "\\1"), need_custom()], "remediate"
    if t == "Ensure pam_unix includes a strong password hashing algorithm":
        return [tmpl_replace("Use strong hash on pam_unix password line",
                             "^(\\s*password\\s+\\S+\\s+pam_unix\\.so)((?:(?!sha512|yescrypt).)*)$",
                             "\\1 {{ %s_password_hash | lower }}\\2" % P), need_custom()], "remediate"
    if t == "Ensure pam_unix includes use_authtok":
        return [tmpl_replace("Add use_authtok to pam_unix password line",
                             "^(\\s*password\\s+\\S+\\s+pam_unix\\.so)((?:(?!use_authtok).)*)$", "\\1\\2 use_authtok"),
                need_custom()], "remediate"
    return None


def accounts(c, r):
    P, rid, t = c.p, r["id"], r["title"]
    ld = "/etc/login.defs"

    def defs(key, val):
        return c.lineinfile(rid, ld, f"^\\s*#?\\s*{key}\\s", f"{key} {val}", create=False)

    chage = lambda field, opt, cond: c.script(rid, f"Apply {opt} to existing users", f"""
[ "{{{{ P_apply_to_existing_users | bool }}}}" = "True" ] || exit 0
awk -F: '($2 ~ /^\\$.+\\$/) {{ if ({cond}) print $1 }}' /etc/shadow | while read -r u; do
  echo "CHANGED $u"; [ "$DRY" = 1 ] || chage {opt} "$u"
done
""")
    if t == "Ensure password expiration is configured":
        return [defs("PASS_MAX_DAYS", "{{ %s_pass_max_days }}" % P)] + chage(5, "--maxdays {{ P_pass_max_days }}".replace("P_", P + "_"),
                                                                              "$5 > %s || $5 < 1" % ("{{ %s_pass_max_days }}" % P)), "remediate"
    if t == "Ensure minimum password days is configured":
        return [defs("PASS_MIN_DAYS", "{{ %s_pass_min_days }}" % P)] + chage(4, "--mindays {{ %s_pass_min_days }}" % P,
                                                                              "$4 < 1"), "remediate"
    if t == "Ensure password expiration warning days is configured":
        return [defs("PASS_WARN_AGE", "{{ %s_pass_warn_age }}" % P)] + chage(6, "--warndays {{ %s_pass_warn_age }}" % P,
                                                                              "$6 < %s" % ("{{ %s_pass_warn_age }}" % P)), "remediate"
    if t == "Ensure strong password hashing algorithm is configured":
        return [defs("ENCRYPT_METHOD", "{{ %s_password_hash }}" % P)], "remediate"
    if t == "Ensure inactive password lock is configured":
        return [{"name": f"{rid} | PATCH | useradd default INACTIVE",
                 "ansible.builtin.lineinfile": {"path": "/etc/default/useradd", "regexp": "^\\s*#?\\s*INACTIVE=",
                                                "line": "INACTIVE={{ %s_inactive_days }}" % P}}] + \
            chage(7, "--inactive {{ %s_inactive_days }}" % P, "$7 > %s || $7 < 0 || $7 == \"\"" % ("{{ %s_inactive_days }}" % P)), "remediate"
    if t == "Ensure all users last password change date is in the past":
        return c.audit(rid, t, "now=$(( $(date +%s) / 86400 )); awk -F: -v n=\"$now\" '($2 ~ /^\\$/ && $3 > n) {print $1\": last change in future\"}' /etc/shadow"), "audit"
    if t == "Ensure root is the only UID 0 account":
        return c.audit(rid, t, "awk -F: '($3 == 0 && $1 != \"root\") {print $1}' /etc/passwd"), "audit"
    if t == "Ensure root is the only GID 0 account":
        return c.audit(rid, t, "awk -F: '($1 !~ /^(sync|shutdown|halt|operator|root)$/ && $4 == 0) {print $1}' /etc/passwd"), "audit"
    if t == "Ensure group root is the only GID 0 group":
        return c.audit(rid, t, "awk -F: '($3 == 0 && $1 != \"root\") {print $1}' /etc/group"), "audit"
    if t == "Ensure root account access is controlled":
        return c.audit(rid, t, "passwd -S root | awk '$2 !~ /^(P|L|LK|PS)/ {print \"root password status: \"$2}'"), "audit"
    if t == "Ensure root path integrity":
        return c.audit(rid, t, """p=$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)
echo "$p" | grep -q '::' && echo 'Empty directory in PATH (::)'
echo "$p" | grep -Pq ':\\h*$' && echo 'Trailing : in PATH'
for d in $(echo "$p" | tr ':' ' '); do
  if [ -d "$d" ]; then
    [ "$(stat -Lc '%U' "$d")" = root ] || echo "$d not owned by root"
    [ $(( 0$(stat -Lc '%a' "$d") & 022 )) -eq 0 ] || echo "$d is group/world writable"
  else echo "$d is not a directory"; fi
done"""), "audit"
    if t == "Ensure root user umask is configured":
        return [{"name": f"{rid} | PATCH | Comment weak umask in root dotfiles",
                 "ansible.builtin.replace": {"path": "{{ item }}", "regexp": "^(\\s*umask\\s+0?([0-7][0-6][0-6]|[0-7][0-1][0-7]|[0-7][0-7][0-6]))\\s*$",
                                             "replace": "# \\1"},
                 "loop": ["/root/.bash_profile", "/root/.bashrc"], "failed_when": False}], "remediate"
    if t == "Ensure system accounts do not have a valid login shell":
        return c.script(rid, "Set nologin for system accounts", """
uid_min=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
valid="^($(awk -F/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\\//{s,/,\\\\/,g;p}' | paste -s -d '|' -))$"
awk -v pat="$valid" -v m="$uid_min" -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<m || $3==65534) && $NF~pat) {print $1}' /etc/passwd |
while read -r u; do echo "CHANGED $u"; [ "$DRY" = 1 ] || usermod -s "$(command -v nologin)" "$u"; done
"""), "remediate"
    if t == "Ensure accounts without a valid login shell are locked":
        return c.script(rid, "Lock non-root accounts without a valid shell", """
valid="^($(awk -F/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\\//{s,/,\\\\/,g;p}' | paste -s -d '|' -))$"
awk -v pat="$valid" -F: '($1 != "root" && $NF !~ pat) {print $1}' /etc/passwd | while read -r u; do
  passwd -S "$u" | awk '$2 !~ /^L/ {exit 1}' || { echo "CHANGED $u"; [ "$DRY" = 1 ] || usermod -L "$u"; }
done
"""), "remediate"
    if t == "Ensure nologin is not listed in /etc/shells":
        return [{"name": f"{rid} | PATCH | Remove nologin from /etc/shells",
                 "ansible.builtin.lineinfile": {"path": "/etc/shells", "regexp": "^.*/nologin\\s*$", "state": "absent"}}], "remediate"
    if t == "Ensure default user shell timeout is configured":
        return [{"name": f"{rid} | PATCH | Set TMOUT",
                 "ansible.builtin.copy": {"dest": "/etc/profile.d/50-cis-tmout.sh",
                                          "content": "# Managed by Ansible - CIS\nTMOUT={{ %s_shell_timeout }}\nreadonly TMOUT\nexport TMOUT\n" % P,
                                          "owner": "root", "group": "root", "mode": "0644"}}], "remediate"
    if t == "Ensure default user umask is configured in /etc/login.defs":
        return [defs("UMASK", "{{ %s_umask }}" % P)], "remediate"
    if t == "Ensure default user umask is configured":
        tasks = [
            {"name": f"{rid} | PATCH | Comment out weak umask in shell init files",
             "ansible.builtin.shell": {"cmd": "for f in /etc/profile /etc/bashrc /etc/profile.d/*.sh; do [ -f \"$f\" ] || continue; "
                                              "if grep -Pq '^\\s*umask\\s+0?(0[01][0-7]|0[0-7][0-6]|[0-7][0-7][0-6])\\b' \"$f\" && [ \"$f\" != /etc/profile.d/50-cis-umask.sh ]; then "
                                              "echo CHANGED $f; [ \"$DRY\" = 1 ] || sed -ri '/^\\s*umask\\s+0?(0[01][0-7]|0[0-7][0-6]|[0-7][0-7][0-6])\\b/s/^/# /' \"$f\"; fi; done",
                                       "executable": "/bin/bash"},
             "environment": {"DRY": "{{ ansible_check_mode | ternary('1', '0') }}"},
             "register": f"{P}_umask_{slug(rid)}", "changed_when": f"'CHANGED' in {P}_umask_{slug(rid)}.stdout",
             "check_mode": False},
            {"name": f"{rid} | PATCH | Set default umask",
             "ansible.builtin.copy": {"dest": "/etc/profile.d/50-cis-umask.sh",
                                      "content": "# Managed by Ansible - CIS\numask {{ %s_umask }}\n" % P,
                                      "owner": "root", "group": "root", "mode": "0644"}},
        ]
        if c.v != 9:
            tasks.append(defs("UMASK", "{{ %s_umask }}" % P))
        return tasks, "remediate"
    return None


def audit_rule(c, rid, slugname, lines):
    """lines: list of rule strings, may contain {{ }} Jinja."""
    P = c.p
    content = "## Managed by Ansible - CIS %s\n" % rid + "\n".join(lines) + "\n"
    return [{"name": f"{rid} | PATCH | Audit rules {slugname}",
             "ansible.builtin.copy": {"dest": f"/etc/audit/rules.d/50-cis-{slugname}.rules", "content": content,
                                      "owner": "root", "group": "root", "mode": "0640"},
             "notify": f"{P} load audit rules"}]


def sc(c, calls, extra, key, uid=True):
    """syscall rule for both arches, filtered by what ausyscall supports."""
    P = c.p
    out = []
    for arch in ("b64", "b32"):
        lst = "%s" % calls
        expr = "({} | intersect({}_syscalls_{}))".format(lst, P, arch)
        u = " -F auid>={{ %s_uid_min }} -F auid!=unset" % P if uid else ""
        out.append("{%% if %s | length > 0 %%}-a always,exit -F arch=%s -S {{ %s | join(',') }}%s%s -k %s{%% endif %%}"
                   % (expr, arch, expr, extra, u, key))
    return out


def w(c, paths, key, perm="wa"):
    P = c.p
    out = []
    for pth in paths:
        if c.v == 8:
            line = f"-w {pth} -p {perm} -k {key}"
        else:
            kind = "dir" if pth.endswith("/") or pth in ("/etc/sudoers.d", "/etc/NetworkManager", "/etc/pam.d",
                                                          "/etc/selinux", "/usr/share/selinux") else "path"
            line = f"-a always,exit -F arch=b64 -S all -F {kind}={pth} -F perm={perm} -F key={key}"
        out.append("{%% if '%s' in %s_audit_paths %%}%s{%% endif %%}" % (pth, P, line))
    return out


def exe(c, path, key):
    P = c.p
    return "-a always,exit -F path=%s -F perm=x -F auid>={{ %s_uid_min }} -F auid!=unset -k %s" % (path, P, key)


AUDIT_WATCH_PATHS = ["/etc/sudoers", "/etc/sudoers.d", "/etc/localtime", "/etc/issue", "/etc/issue.net",
                     "/etc/hosts", "/etc/hostname", "/etc/sysconfig/network", "/etc/sysconfig/network-scripts/",
                     "/etc/NetworkManager", "/etc/NetworkManager/system-connections/", "/etc/group", "/etc/passwd",
                     "/etc/gshadow", "/etc/shadow", "/etc/security/opasswd", "/etc/nsswitch.conf", "/etc/pam.conf",
                     "/etc/pam.d", "/var/run/utmp", "/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog",
                     "/var/run/faillock", "/etc/selinux", "/usr/share/selinux"]


def logging_audit(c, r):
    P, rid, t = c.p, r["id"], r["title"]
    # ----- AIDE
    if t == "Ensure AIDE is installed":
        return [c.pkg(rid, ["aide"], "present"),
                {"name": f"{rid} | PATCH | Initialise the AIDE database (can take several minutes)",
                 "ansible.builtin.shell": "aide --init && mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz",
                 "args": {"creates": "/var/lib/aide/aide.db.gz"}, "async": 3600, "poll": 15}], "remediate"
    if t == "Ensure filesystem integrity is regularly checked":
        return [
            {"name": f"{rid} | PATCH | aidecheck.service",
             "ansible.builtin.copy": {"dest": "/etc/systemd/system/aidecheck.service", "mode": "0644",
                                      "content": "[Unit]\nDescription=Aide Check\n\n[Service]\nType=simple\nExecStart=/usr/sbin/aide --check\n\n[Install]\nWantedBy=multi-user.target\n"}},
            {"name": f"{rid} | PATCH | aidecheck.timer",
             "ansible.builtin.copy": {"dest": "/etc/systemd/system/aidecheck.timer", "mode": "0644",
                                      "content": "[Unit]\nDescription=Aide check every day at 5AM\n\n[Timer]\nOnCalendar={{ %s_aide_schedule }}\nUnit=aidecheck.service\n\n[Install]\nWantedBy=multi-user.target\n" % P}},
            {"name": f"{rid} | PATCH | Enable aidecheck.timer",
             "ansible.builtin.systemd": {"name": "aidecheck.timer", "enabled": True, "state": "started",
                                                 "daemon_reload": True}, "when": "not ansible_check_mode"},
        ], "remediate"
    if t == "Ensure cryptographic mechanisms are used to protect the integrity of audit tools":
        tools = "\n".join(f"{x} p+i+n+u+g+s+b+acl+xattrs+sha512" for x in AUDIT_TOOLS + ["/sbin/audispd"][:0])
        return [{"name": f"{rid} | PATCH | Protect audit tools in aide.conf",
                 "ansible.builtin.blockinfile": {"path": "/etc/aide.conf", "marker": "# {mark} CIS audit tools",
                                                 "block": "# Audit Tools\n" + tools}}], "remediate"
    if t == "Ensure report_url is configured":
        return [c.lineinfile(rid, "/etc/aide.conf", "^\\s*report_url=syslog:", "report_url=syslog:{{ %s_aide_syslog_facility }}" % P, create=False)], "remediate"

    # ----- journald
    jd = "/etc/systemd/journald.conf.d/60-cis.conf"

    def jopt(opt, val, when=None):
        tk = {"name": f"{rid} | PATCH | journald {opt}={val}",
              "community.general.ini_file": {"path": jd, "section": "Journal", "option": opt, "value": val,
                                             "no_extra_spaces": True, "create": True, "mode": "0644"},
              "notify": f"{P} restart journald"}
        if when:
            tk["when"] = when
        return tk
    if t == "Ensure journald service is active":
        return [{"name": f"{rid} | AUDIT | systemd-journald is active",
                 "ansible.builtin.systemd": {"name": "systemd-journald", "state": "started"}}], "remediate"
    if t == "Ensure journald ForwardToSyslog is disabled":
        return [jopt("ForwardToSyslog", "no", f"{P}_logging_system == 'journald'"),
                c.finding(rid, t, "info", "['Not applicable: rsyslog selected as the logging system']",
                          when=f"{P}_logging_system != 'journald'")], "remediate"
    if t == "Ensure journald is configured to send logs to rsyslog":
        return [jopt("ForwardToSyslog", "yes", f"{P}_logging_system == 'rsyslog'")], "remediate"
    if t == "Ensure journald Compress is configured":
        return [jopt("Compress", "yes")], "remediate"
    if t == "Ensure journald Storage is configured":
        return [jopt("Storage", "persistent")], "remediate"
    if t in ("Ensure journald log file rotation is configured", "Ensure journald log file access is configured"):
        return c.manual(rid, t, "systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^(System|Runtime)(MaxUse|KeepFree|MaxFileSize)|^MaxFileSec' ; ls -l /var/log/journal 2>/dev/null"), "manual"
    if t == "Ensure only one logging system is in use":
        return c.audit(rid, t, "systemctl is-active --quiet rsyslog && systemctl is-active --quiet systemd-journal-upload && echo 'both rsyslog and systemd-journal-upload are active'"), "audit"
    if t == "Ensure systemd-journal-remote is installed":
        return [c.pkg(rid, ["systemd-journal-remote"], "present", when=f"{P}_logging_system == 'journald'")], "remediate"
    if t in ("Ensure systemd-journal-upload authentication is configured",
             "Ensure systemd-journal-remote authentication is configured"):
        return [
            {"name": f"{rid} | PATCH | Configure journal-upload",
             "community.general.ini_file": {"path": "/etc/systemd/journal-upload.conf", "section": "Upload",
                                            "option": "{{ item.k }}", "value": "{{ item.v }}", "no_extra_spaces": True},
             "loop": [{"k": "URL", "v": "{{ %s_journal_upload_url }}" % P},
                      {"k": "ServerKeyFile", "v": "{{ %s_journal_upload_key }}" % P},
                      {"k": "ServerCertificateFile", "v": "{{ %s_journal_upload_cert }}" % P},
                      {"k": "TrustedCertificateFile", "v": "{{ %s_journal_upload_ca }}" % P}],
             "when": f"{P}_logging_system == 'journald' and {P}_journal_upload_url | length > 0"},
            c.finding(rid, t, "action_required", f"['Set {P}_journal_upload_url and certificate paths']",
                      when=f"{P}_logging_system == 'journald' and {P}_journal_upload_url | length == 0"),
        ], "remediate"
    if t == "Ensure systemd-journal-upload is enabled and active":
        return [{"name": f"{rid} | PATCH | Enable systemd-journal-upload",
                 "ansible.builtin.systemd": {"name": "systemd-journal-upload", "enabled": True, "state": "started"},
                 "when": f"{P}_logging_system == 'journald' and {P}_journal_upload_url | length > 0 and not ansible_check_mode"}], "remediate"

    # ----- rsyslog
    rs = f"{P}_logging_system == 'rsyslog'"
    if t == "Ensure rsyslog is installed":
        return [c.pkg(rid, ["rsyslog"], "present", when=rs)], "remediate"
    if t == "Ensure rsyslog service is enabled and active":
        return [{"name": f"{rid} | PATCH | Enable rsyslog",
                 "ansible.builtin.systemd": {"name": "rsyslog", "enabled": True, "state": "started"},
                 "when": rs + " and not ansible_check_mode"}], "remediate"
    if t == "Ensure rsyslog log file creation mode is configured":
        return [c.lineinfile(rid, "/etc/rsyslog.d/60-cis-filecreatemode.conf", "^\\s*\\$FileCreateMode",
                             "$FileCreateMode 0640", notify=f"{P} restart rsyslog", when=rs)], "remediate"
    if t in ("Ensure rsyslog is not configured to receive logs from a remote client",
             "Ensure rsyslog is not configured as a log server"):
        return [{"name": f"{rid} | PATCH | Comment out imtcp/imudp inputs",
                 "ansible.builtin.shell": {"cmd": "grep -lPrs '^\\s*(module\\(load=\"?im(tcp|udp)\"?|input\\(type=\"?im(tcp|udp)\"?|\\$ModLoad\\s+im(tcp|udp)|\\$(InputTCPServerRun|UDPServerRun))' /etc/rsyslog.conf /etc/rsyslog.d/ | "
                                                  "while read -r f; do echo CHANGED $f; [ \"$DRY\" = 1 ] || sed -ri '/^\\s*(module\\(load=\"?im(tcp|udp)\"?|input\\(type=\"?im(tcp|udp)\"?|\\$ModLoad\\s+im(tcp|udp)|\\$(InputTCPServerRun|UDPServerRun))/s/^/# /' \"$f\"; done",
                                           "executable": "/bin/bash"},
                 "environment": {"DRY": "{{ ansible_check_mode | ternary('1', '0') }}"},
                 "register": f"{P}_rsin_{slug(rid)}", "changed_when": f"'CHANGED' in {P}_rsin_{slug(rid)}.stdout",
                 "check_mode": False, "when": f"{rs} and not {P}_rsyslog_is_log_server | bool",
                 "notify": f"{P} restart rsyslog"}], "remediate"
    if t == "Ensure rsyslog is configured to send logs to a remote log host" or t == "Ensure rsyslog network forwarding uses TLS":
        tls = t.endswith("TLS")
        return [
            {"name": f"{rid} | PATCH | Forward logs to {{{{ {P}_rsyslog_remote_host }}}}",
             "ansible.builtin.template": {"src": "rsyslog-remote.conf.j2", "dest": "/etc/rsyslog.d/90-cis-remote.conf",
                                          "owner": "root", "group": "root", "mode": "0640"},
             "when": f"{rs} and {P}_rsyslog_remote_host | length > 0" + (f" and {P}_rsyslog_tls | bool" if tls else ""),
             "notify": f"{P} restart rsyslog"},
            c.finding(rid, t, "action_required", f"['Set {P}_rsyslog_remote_host' + (' and {P}_rsyslog_tls=true' if {tls} else '') + ' to forward logs']",
                      when=f"{rs} and ({P}_rsyslog_remote_host | length == 0" + (f" or not {P}_rsyslog_tls | bool" if tls else "") + ")"),
        ], ("remediate" if tls else "manual")
    if t == "Ensure a rsyslog TLS network stream driver is installed":
        return [c.pkg(rid, ["rsyslog-gnutls"], "present", when=rs)], "remediate"
    if t in ("Ensure rsyslog TLS CA certificate is configured", "Ensure rsyslog TLS client certificate is configured",
             "Ensure rsyslog logging is configured", "Ensure rsyslog logging rules are configured"):
        return c.manual(rid, t, "grep -hPv '^\\s*(#|$)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | head -60"), "manual"
    if t in ("Ensure logrotate is configured", "Ensure rsyslog logrotate is configured"):
        return c.manual(rid, t, "grep -hPv '^\\s*(#|$)' /etc/logrotate.conf; ls /etc/logrotate.d"), "manual"
    if t == "Ensure access to rsyslog configuration files is configured":
        return c.perms(rid, [("/etc/rsyslog.conf", ("root", "root", "u-x,g-wx,o-rwx"))]) + \
            c.find_perms(rid + "_d", "/etc/rsyslog.d", "*.conf", "u-x,g-wx,o-rwx"), "remediate"
    if t == "Ensure access to the /etc/rsyslog.d directory is configured":
        return c.perms(rid, [("/etc/rsyslog.d", ("root", "root", "g-w,o-w"))]), "remediate"
    if t == "Ensure access to the rsyslog work directory is configured":
        return c.perms(rid, [("/var/lib/rsyslog", ("root", "root", "go-rwx"))]), "remediate"
    if t == "Ensure access to all logfiles has been configured":
        return c.script(rid, "Remove excess permissions on /var/log files", """
find -L /var/log -type f \\( -name 'wtmp*' -o -name 'btmp*' -o -name 'lastlog*' \\) -perm /0113 -print 2>/dev/null | while read -r f; do
  echo "CHANGED $f"; [ "$DRY" = 1 ] || chmod ug-x,o-wx "$f"; done
find -L /var/log -type f ! \\( -name 'wtmp*' -o -name 'btmp*' -o -name 'lastlog*' \\) -perm /0137 -print 2>/dev/null | while read -r f; do
  echo "CHANGED $f"; [ "$DRY" = 1 ] || chmod u-x,g-wx,o-rwx "$f"; done
"""), "remediate"

    # ----- auditd
    if t == "Ensure auditd packages are installed":
        return [c.pkg(rid, ["audit", "audit-libs"], "present")], "remediate"
    for frag, arg in (("auditing for processes that start prior to auditd", "audit=1"),
                      ("audit_backlog_limit", "audit_backlog_limit={{ %s_audit_backlog_limit }}" % P)):
        if frag in t:
            key = arg.split("=")[0]
            return [
                *grubby(c, rid, arg),
                {"name": f"{rid} | PATCH | Persist {key} in /etc/default/grub",
                 "ansible.builtin.replace": {"path": "/etc/default/grub",
                                             "regexp": f'^(GRUB_CMDLINE_LINUX="(?:(?!\\b{key}=).)*?)"$',
                                             "replace": f'\\1 {arg}"'},
                 "notify": f"{P} grub2 mkconfig"},
            ], "remediate"
    if t == "Ensure auditd service is enabled and active":
        return [{"name": f"{rid} | PATCH | Enable auditd",
                 "ansible.builtin.systemd": {"name": "auditd", "enabled": True, "state": "started"},
                 "when": "not ansible_check_mode"}], "remediate"

    def ad(opt, val):
        return c.lineinfile(rid, "/etc/audit/auditd.conf", f"^\\s*#?\\s*{opt}\\s*=", f"{opt} = {val}",
                            create=False, mode="0640", notify=f"{P} restart auditd")
    if t == "Ensure audit log storage size is configured":
        return [ad("max_log_file", "{{ %s_auditd_max_log_file }}" % P)], "remediate"
    if t == "Ensure audit logs are not automatically deleted":
        return [ad("max_log_file_action", "keep_logs")], "remediate"
    if t == "Ensure system is disabled when audit logs are full":
        return [ad("disk_full_action", "{{ %s_auditd_disk_full_action }}" % P),
                ad("disk_error_action", "{{ %s_auditd_disk_error_action }}" % P)], "remediate"
    if t == "Ensure system warns when audit logs are low on space":
        return [ad("space_left_action", "{{ %s_auditd_space_left_action }}" % P),
                ad("admin_space_left_action", "{{ %s_auditd_admin_space_left_action }}" % P)], "remediate"

    # ----- audit rules
    um = "{{ %s_uid_min }}" % P
    R = None
    if t in ("Ensure modification of the /etc/sudoers file is collected",
             "Ensure changes to system administration scope (sudoers) is collected"):
        R = ("scope", w(c, ["/etc/sudoers", "/etc/sudoers.d"], "scope"))
    elif t == "Ensure actions as another user are always logged":
        R = ("user-emulation", sc(c, "['execve']", " -C euid!=uid", "user_emulation", uid=False))
        R[1][:] = [x.replace(" -C euid!=uid -k", " -C euid!=uid -F auid!=unset -k") for x in R[1]]
    elif t == "Ensure events that modify the sudo log file are collected":
        R = ("sudo-log", ["-w {{ %s_sudo_logfile }} -p wa -k sudo_log_file" % P] if c.v == 8 else
             ["-a always,exit -F arch=b64 -S all -F path={{ %s_sudo_logfile }} -F perm=wa -F key=sudo_log_file" % P])
    elif t == "Ensure events that modify date and time information are collected":
        R = ("time-change", sc(c, "['adjtimex','settimeofday']", "", "time-change", uid=False) +
             sc(c, "['clock_settime']", " -F a0=0x0", "time-change", uid=False) + w(c, ["/etc/localtime"], "time-change"))
    elif t == "Ensure events that modify sethostname and setdomainname are collected":
        R = ("hostname", sc(c, "['sethostname','setdomainname']", "", "system-locale", uid=False))
    elif t == "Ensure events that modify /etc/issue and /etc/issue.net are collected":
        R = ("issue", w(c, ["/etc/issue", "/etc/issue.net"], "system-locale"))
    elif t == "Ensure events that modify /etc/hosts and /etc/hostname are collected":
        R = ("hosts", w(c, ["/etc/hosts", "/etc/hostname"], "system-locale"))
    elif t.startswith("Ensure events that modify /etc/sysconfig/network and"):
        R = ("network-config", w(c, ["/etc/sysconfig/network", "/etc/NetworkManager/system-connections/"], "system-locale"))
    elif t == "Ensure events that modify /etc/NetworkManager directory are collected":
        R = ("networkmanager", w(c, ["/etc/NetworkManager"], "system-locale"))
    elif t == "Ensure events that modify the system's network environment are collected":
        R = ("system-locale", sc(c, "['sethostname','setdomainname']", "", "system-locale", uid=False) +
             w(c, ["/etc/issue", "/etc/issue.net", "/etc/hosts", "/etc/hostname", "/etc/sysconfig/network",
                   "/etc/sysconfig/network-scripts/", "/etc/NetworkManager"], "system-locale"))
    elif t == "Ensure use of privileged commands are collected":
        return [
            {"name": f"{rid} | AUDIT | Find setuid/setgid programs on local filesystems",
             "ansible.builtin.shell": "for m in $(findmnt -nlk -o TARGET -t ext2,ext3,ext4,xfs,btrfs | grep -Pv '^/(proc|sys)'); do "
                                      "find \"$m\" -xdev -perm /6000 -type f 2>/dev/null; done | sort -u",
             "register": f"{P}_priv_{slug(rid)}", "changed_when": False, "check_mode": False},
            {"name": f"{rid} | PATCH | Audit rules privileged",
             "ansible.builtin.copy": {"dest": "/etc/audit/rules.d/50-cis-privileged.rules", "owner": "root",
                                      "group": "root", "mode": "0640",
                                      "content": "## Managed by Ansible - CIS %s\n{%% for f in %s_priv_%s.stdout_lines %%}\n"
                                                 "-a always,exit -F path={{ f }} -F perm=x -F auid>=%s -F auid!=unset -k privileged\n{%% endfor %%}\n"
                                                 % (rid, P, slug(rid), um)},
             "notify": f"{P} load audit rules"},
        ], "remediate"
    elif t == "Ensure unsuccessful file access attempts are collected":
        R = ("access", sc(c, "['creat','open','openat','truncate','ftruncate']", " -F exit=-EACCES", "access") +
             sc(c, "['creat','open','openat','truncate','ftruncate']", " -F exit=-EPERM", "access"))
    elif t == "Ensure events that modify user/group information are collected":
        R = ("identity", w(c, ["/etc/group", "/etc/passwd", "/etc/gshadow", "/etc/shadow", "/etc/security/opasswd",
                                "/etc/nsswitch.conf", "/etc/pam.conf", "/etc/pam.d"], "identity"))
    elif (m := re.match(r"Ensure events that modify (/etc/\S+)(?: and (/etc/\S+))? (?:information |file )?are collected", t)):
        ps = [x for x in m.groups() if x]
        if ps == ["/etc/pam.conf", "/etc/pam.d/"]:
            ps = ["/etc/pam.conf", "/etc/pam.d"]
        R = ("identity-" + ps[0].split("/")[-1].strip("/").replace(".", "-"), w(c, ps, "identity"))
    elif t == "Ensure discretionary access control permission modification events are collected":
        R = ("perm-mod", sc(c, "['chmod','fchmod','fchmodat']", "", "perm_mod") +
             sc(c, "['chown','fchown','lchown','fchownat']", "", "perm_mod") +
             sc(c, "['setxattr','lsetxattr','fsetxattr','removexattr','lremovexattr','fremovexattr']", "", "perm_mod"))
    elif (m := re.match(r"Ensure discretionary access control permission modification events ([a-z0-9,]+) (?:are )?collected", t)):
        calls = m.group(1).split(",")
        R = ("perm-mod-" + calls[0], sc(c, repr(calls), "", "perm_mod"))
    elif t == "Ensure successful file system mounts are collected":
        R = ("mounts", sc(c, "['mount']", "", "mounts"))
    elif t == "Ensure session initiation information is collected":
        R = ("session", w(c, ["/var/run/utmp", "/var/log/wtmp", "/var/log/btmp"], "session"))
    elif t == "Ensure login and logout events are collected":
        R = ("logins", w(c, ["/var/log/lastlog", "/var/run/faillock"], "logins"))
    elif t == "Ensure file deletion events by users are collected":
        R = ("delete", sc(c, "['rename','unlink','unlinkat','renameat']", "", "delete"))
    elif t == "Ensure unlink file deletion events by users are collected":
        R = ("delete-unlink", sc(c, "['unlink','unlinkat']", "", "delete"))
    elif t == "Ensure rename file deletion events by users are collected":
        R = ("delete-rename", sc(c, "['rename','renameat','renameat2']", "", "delete"))
    elif t == "Ensure events that modify the system's Mandatory Access Controls are collected":
        R = ("mac-policy", w(c, ["/etc/selinux", "/usr/share/selinux"], "MAC-policy"))
    elif (m := re.match(r"Ensure successful and unsuccessful attempts to use the (\w+) command are collected", t)):
        cmd = m.group(1)
        path = {"chcon": "/usr/bin/chcon", "setfacl": "/usr/bin/setfacl", "chacl": "/usr/bin/chacl",
                "usermod": "/usr/sbin/usermod"}[cmd]
        R = (cmd, [exe(c, path, "usermod" if cmd == "usermod" else "perm_chng")])
    elif t == "Ensure kernel module loading unloading and modification is collected":
        if c.v == 8:
            R = ("kernel-modules", sc(c, "['init_module','finit_module','delete_module','create_module','query_module']", "", "kernel_modules")
                 + [exe(c, "/usr/bin/kmod", "kernel_modules")])
        else:
            R = ("kernel-modules-kmod", [exe(c, "/usr/bin/kmod", "kernel_modules")])
    elif (m := re.match(r'Ensure kernel "?([a-z_]+)"?(?: and "([a-z_]+)")? loading unloading and modification is collected', t)):
        calls = [x for x in m.groups() if x]
        R = ("kernel-modules-" + calls[0], sc(c, repr(calls), "", "kernel_modules"))
    elif t == "Ensure the audit configuration is loaded regardless of errors":
        return [{"name": f"{rid} | PATCH | Continue loading rules on error (-c)",
                 "ansible.builtin.copy": {"dest": "/etc/audit/rules.d/01-initialize.rules", "content": "-c\n",
                                          "owner": "root", "group": "root", "mode": "0640"},
                 "notify": f"{P} load audit rules"}], "remediate"
    elif t == "Ensure the audit configuration is immutable":
        return [{"name": f"{rid} | PATCH | Make audit configuration immutable (-e 2)",
                 "ansible.builtin.copy": {"dest": "/etc/audit/rules.d/99-finalize.rules", "content": "-e 2\n",
                                          "owner": "root", "group": "root", "mode": "0640"},
                 "notify": f"{P} load audit rules"}], "remediate"
    elif t == "Ensure the running and on disk configuration is the same":
        return c.audit(rid, t, "augenrules --check 2>&1 | grep -v 'No change' || true",
                       kind=("audit" if r["type"] == "automated" else "manual")), ("audit" if r["type"] == "automated" else "manual")
    if R:
        return audit_rule(c, rid, R[0], R[1]), "remediate"

    # ----- audit file permissions
    logdir = "{{ %s_audit_log_dir }}" % P
    if t == "Ensure the audit log file directory mode is configured":
        return [{"name": f"{rid} | PATCH | Audit log directory mode",
                 "ansible.builtin.file": {"path": logdir, "state": "directory", "mode": "g-w,o-rwx"}}], "remediate"
    m = re.match(r"Ensure audit (log files|configuration files|tools) (mode|owner|group owner) is configured", t)
    if m:
        what, attr = m.groups()
        args = {"mode": None, "owner": None, "group": None}
        if what == "log files":
            vals = {"mode": "u-x,g-wx,o-rwx", "owner": "root", "group owner": "{{ %s_audit_log_group }}" % P}
            reg = f"{P}_alog_{slug(rid)}"
            key = {"mode": "mode", "owner": "owner", "group owner": "group"}[attr]
            return [
                {"name": f"{rid} | AUDIT | Find audit log files", "ansible.builtin.find":
                    {"paths": logdir, "file_type": "file"}, "register": reg},
                {"name": f"{rid} | PATCH | Audit log files {attr}",
                 "ansible.builtin.file": {"path": "{{ item.path }}", key: vals[attr]},
                 "loop": f"{{{{ {reg}.files }}}}", "loop_control": {"label": "{{ item.path }}"}},
            ] + ([c.lineinfile(rid, "/etc/audit/auditd.conf", "^\\s*#?\\s*log_group\\s*=",
                               "log_group = {{ %s_audit_log_group }}" % P, create=False, mode="0640",
                               notify=f"{P} restart auditd")] if attr == "group owner" else []), "remediate"
        if what == "configuration files":
            vals = {"mode": "u-x,g-wx,o-rwx", "owner": "root", "group owner": "root"}
            key = {"mode": "mode", "owner": "owner", "group owner": "group"}[attr]
            reg = f"{P}_aconf_{slug(rid)}"
            return [
                {"name": f"{rid} | AUDIT | Find audit configuration files", "ansible.builtin.find":
                    {"paths": "/etc/audit", "patterns": ["*.conf", "*.rules"], "recurse": True}, "register": reg},
                {"name": f"{rid} | PATCH | Audit configuration files {attr}",
                 "ansible.builtin.file": {"path": "{{ item.path }}", key: vals[attr]},
                 "loop": f"{{{{ {reg}.files }}}}", "loop_control": {"label": "{{ item.path }}"}},
            ], "remediate"
        vals = {"mode": "go-w", "owner": "root", "group owner": "root"}
        key = {"mode": "mode", "owner": "owner", "group owner": "group"}[attr]
        return [{"name": f"{rid} | PATCH | Audit tools {attr}",
                 "ansible.builtin.file": {"path": "{{ item }}", key: vals[attr], "follow": True},
                 "loop": AUDIT_TOOLS, "failed_when": False}], "remediate"
    return None


def system_maint(c, r):
    P, rid, t = c.p, r["id"], r["title"]
    if t == "Ensure world writable files and directories are secured":
        return c.script(rid, "Remove world-write from files / add sticky bit to world-writable dirs", """
for m in $(findmnt -nlk -o TARGET -t ext2,ext3,ext4,xfs,btrfs,vfat); do
  find "$m" -xdev \\( -path /proc -o -path /sys -o -path /run -o -path '/var/lib/containers/*' \\) -prune -o \\
     -type f -perm -0002 -print 2>/dev/null | while read -r f; do echo "CHANGED file $f"; [ "$DRY" = 1 ] || chmod o-w "$f"; done
  find "$m" -xdev \\( -path /proc -o -path /sys -o -path /run \\) -prune -o \\
     -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | while read -r d; do echo "CHANGED dir $d"; [ "$DRY" = 1 ] || chmod a+t "$d"; done
done
"""), "remediate"
    if t == "Ensure no files or directories without an owner and a group exist":
        return c.audit(rid, t, "for m in $(findmnt -nlk -o TARGET -t ext2,ext3,ext4,xfs,btrfs); do find \"$m\" -xdev \\( -path /proc -o -path /sys -o -path /run -o -path '/var/lib/containers/*' \\) -prune -o \\( -nouser -o -nogroup \\) -print 2>/dev/null; done | head -200"), "audit"
    if t == "Ensure SUID and SGID files are reviewed":
        return c.manual(rid, t, "for m in $(findmnt -nlk -o TARGET -t ext2,ext3,ext4,xfs,btrfs); do find \"$m\" -xdev -type f -perm /6000 2>/dev/null; done"), "manual"
    if t == "Ensure accounts in /etc/passwd use shadowed passwords":
        return c.script(rid, "Migrate passwords to /etc/shadow (pwconv)", """
if awk -F: '($2 != "x") {found=1} END {exit !found}' /etc/passwd; then echo CHANGED; [ "$DRY" = 1 ] || pwconv; fi
"""), "remediate"
    if t == "Ensure /etc/shadow password fields are not empty":
        return c.script(rid, "Lock accounts with empty passwords", """
awk -F: '($2 == "") {print $1}' /etc/shadow | while read -r u; do echo "CHANGED $u"; [ "$DRY" = 1 ] || passwd -l "$u"; done
"""), "remediate"
    checks = {
        "Ensure all groups in /etc/passwd exist in /etc/group":
            "for g in $(cut -s -d: -f4 /etc/passwd | sort -u); do grep -q -P \"^.*?:[^:]*:$g:\" /etc/group || echo \"GID $g in /etc/passwd not in /etc/group\"; done",
        "Ensure no duplicate UIDs exist": "cut -f3 -d: /etc/passwd | sort -n | uniq -d | while read -r x; do echo \"Duplicate UID $x: $(awk -F: -v u=$x '$3==u{print $1}' /etc/passwd | xargs)\"; done",
        "Ensure no duplicate GIDs exist": "cut -f3 -d: /etc/group | sort -n | uniq -d | while read -r x; do echo \"Duplicate GID $x\"; done",
        "Ensure no duplicate user names exist": "cut -f1 -d: /etc/passwd | sort | uniq -d",
        "Ensure no duplicate group names exist": "cut -f1 -d: /etc/group | sort | uniq -d",
    }
    if t in checks:
        return c.audit(rid, t, checks[t]), "audit"
    if t == "Ensure local interactive user home directories are configured":
        return c.script(rid, "Fix home directory ownership and mode", """
valid="^($(awk -F/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\\//{s,/,\\\\/,g;p}' | paste -s -d '|' -))$"
awk -v pat="$valid" -F: '$(NF) ~ pat && $1 != "root" {print $1 ":" $(NF-1)}' /etc/passwd | while IFS=: read -r u h; do
  [ -d "$h" ] || { echo "MISSING home $h for $u"; continue; }
  o=$(stat -Lc '%U' "$h"); md=$(stat -Lc '%#a' "$h")
  [ "$o" = "$u" ] || { echo "CHANGED owner $h"; [ "$DRY" = 1 ] || chown "$u" "$h"; }
  [ $(( md & 027 )) -eq 0 ] || { echo "CHANGED mode $h"; [ "$DRY" = 1 ] || chmod g-w,o-rwx "$h"; }
done
"""), "remediate"
    if t == "Ensure local interactive user dot files access is configured":
        return c.script(rid, "Restrict dot file permissions", """
valid="^($(awk -F/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\\//{s,/,\\\\/,g;p}' | paste -s -d '|' -))$"
awk -v pat="$valid" -F: '$(NF) ~ pat {print $1 ":" $(NF-1)}' /etc/passwd | while IFS=: read -r u h; do
  [ -d "$h" ] || continue
  find "$h" -xdev -maxdepth 1 -name '.*' -type f 2>/dev/null | while read -r f; do
    case "$(basename "$f")" in
      .forward|.rhosts) if [ "{{ P_remove_forward_rhosts | bool }}" = "True" ]; then echo "CHANGED remove $f"; [ "$DRY" = 1 ] || rm -f "$f"; else echo "FOUND $f (set P_remove_forward_rhosts=true to delete)"; fi;;
      .netrc|.bash_history) [ $(( $(stat -Lc '%#a' "$f") & 0177 )) -eq 0 ] || { echo "CHANGED $f"; [ "$DRY" = 1 ] || chmod u-x,go-rwx "$f"; };;
      *) [ $(( $(stat -Lc '%#a' "$f") & 0133 )) -eq 0 ] || { echo "CHANGED $f"; [ "$DRY" = 1 ] || chmod u-x,go-wx "$f"; };;
    esac
  done
done
"""), "remediate"
    return None
