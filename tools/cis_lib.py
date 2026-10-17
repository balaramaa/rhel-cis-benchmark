"""Shared helpers and data maps used by generate.py.

Every CIS recommendation is matched by its *title* (not its ID), because the
same ID means different things in different benchmark versions (for example
5.1.20 is MaxStartups on RHEL 8 but PermitRootLogin on RHEL 10).
"""
import re

# --------------------------------------------------------------------------
# Data maps
# --------------------------------------------------------------------------
SYSCTL = {
    "fs.protected_hardlinks": 1, "fs.protected_symlinks": 1, "fs.suid_dumpable": 0,
    "kernel.dmesg_restrict": 1, "kernel.kptr_restrict": 2, "kernel.yama.ptrace_scope": 1,
    "kernel.randomize_va_space": 2,
    "net.ipv4.ip_forward": 0, "net.ipv4.conf.all.forwarding": 0, "net.ipv4.conf.default.forwarding": 0,
    "net.ipv4.conf.all.send_redirects": 0, "net.ipv4.conf.default.send_redirects": 0,
    "net.ipv4.icmp_ignore_bogus_error_responses": 1, "net.ipv4.icmp_echo_ignore_broadcasts": 1,
    "net.ipv4.conf.all.accept_redirects": 0, "net.ipv4.conf.default.accept_redirects": 0,
    "net.ipv4.conf.all.secure_redirects": 0, "net.ipv4.conf.default.secure_redirects": 0,
    "net.ipv4.conf.all.rp_filter": 1, "net.ipv4.conf.default.rp_filter": 1,
    "net.ipv4.conf.all.accept_source_route": 0, "net.ipv4.conf.default.accept_source_route": 0,
    "net.ipv4.conf.all.log_martians": 1, "net.ipv4.conf.default.log_martians": 1,
    "net.ipv4.tcp_syncookies": 1,
    "net.ipv4.conf.all.route_localnet": 0, "net.ipv4.conf.default.route_localnet": 0,
    "net.ipv6.conf.all.forwarding": 0, "net.ipv6.conf.default.forwarding": 0,
    "net.ipv6.conf.all.accept_redirects": 0, "net.ipv6.conf.default.accept_redirects": 0,
    "net.ipv6.conf.all.accept_source_route": 0, "net.ipv6.conf.default.accept_source_route": 0,
    "net.ipv6.conf.all.accept_ra": 0, "net.ipv6.conf.default.accept_ra": 0,
}

# title fragment -> (packages, systemd units)
SERVICES = {
    "autofs": (["autofs"], ["autofs.service"]),
    "avahi daemon": (["avahi"], ["avahi-daemon.socket", "avahi-daemon.service"]),
    "cockpit web": (["cockpit", "cockpit-ws"], ["cockpit.socket", "cockpit.service"]),
    "dhcp server": (["dhcp-server", "kea"], ["dhcpd.service", "dhcpd6.service", "kea-dhcp4.service", "kea-dhcp6.service"]),
    "dns server": (["bind"], ["named.service"]),
    "dnsmasq": (["dnsmasq"], ["dnsmasq.service"]),
    "ftp server": (["vsftpd"], ["vsftpd.service"]),
    "message access server": (["dovecot", "cyrus-imapd"], ["dovecot.socket", "dovecot.service", "cyrus-imapd.service"]),
    "network file system": (["nfs-utils"], ["nfs-server.service"]),
    "nis server": (["ypserv"], ["ypserv.service"]),
    "print server": (["cups"], ["cups.socket", "cups.service"]),
    "rpcbind": (["rpcbind"], ["rpcbind.socket", "rpcbind.service"]),
    "rsync": (["rsync-daemon"], ["rsyncd.socket", "rsyncd.service"]),
    "samba file server": (["samba"], ["smb.service"]),
    "snmp": (["net-snmp"], ["snmpd.service"]),
    "telnet server": (["telnet-server"], ["telnet.socket"]),
    "tftp server": (["tftp-server"], ["tftp.socket", "tftp.service"]),
    "web proxy server": (["squid"], ["squid.service"]),
    "web server": (["httpd", "nginx"], ["httpd.socket", "httpd.service", "nginx.service"]),
    "xinetd": (["xinetd"], ["xinetd.service"]),
    "bluetooth": (["bluez"], ["bluetooth.service"]),
    "X window server": (["xorg-x11-server-common"], []),
}

CLIENTS = {"ftp": ["ftp"], "ldap": ["openldap-clients"], "nis": ["ypbind"],
           "telnet": ["telnet"], "tftp": ["tftp"]}

# path -> (owner, group, mode)
FILE_PERMS = {
    "/etc/motd": ("root", "root", "u-x,go-wx"),
    "/etc/issue": ("root", "root", "u-x,go-wx"),
    "/etc/issue.net": ("root", "root", "u-x,go-wx"),
    "/etc/crontab": ("root", "root", "u-x,go-rwx"),
    "/etc/cron.hourly": ("root", "root", "go-rwx"),
    "/etc/cron.daily": ("root", "root", "go-rwx"),
    "/etc/cron.weekly": ("root", "root", "go-rwx"),
    "/etc/cron.monthly": ("root", "root", "go-rwx"),
    "/etc/cron.yearly": ("root", "root", "go-rwx"),
    "/etc/cron.d": ("root", "root", "go-rwx"),
    "/etc/passwd": ("root", "root", "u-x,go-wx"),
    "/etc/passwd-": ("root", "root", "u-x,go-wx"),
    "/etc/group": ("root", "root", "u-x,go-wx"),
    "/etc/group-": ("root", "root", "u-x,go-wx"),
    "/etc/shadow": ("root", "root", "0000"),
    "/etc/shadow-": ("root", "root", "0000"),
    "/etc/gshadow": ("root", "root", "0000"),
    "/etc/gshadow-": ("root", "root", "0000"),
    "/etc/shells": ("root", "root", "u-x,go-wx"),
    "/etc/security/opasswd": ("root", "root", "u-x,go-rwx"),
    "/etc/sysconfig/sshd": ("root", "root", "u-x,g-wx,o-rwx"),
    "/etc/ssh/sshd_config.d/": ("root", "root", "0700"),
}

AUDIT_TOOLS = ["/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", "/sbin/autrace",
               "/sbin/auditd", "/sbin/augenrules"]

SSHD_SIMPLE = {
    "DisableForwarding is enabled": ("DisableForwarding", "yes"),
    "GSSAPIAuthentication is disabled": ("GSSAPIAuthentication", "no"),
    "HostbasedAuthentication is disabled": ("HostbasedAuthentication", "no"),
    "IgnoreRhosts is enabled": ("IgnoreRhosts", "yes"),
    "LoginGraceTime is configured": ("LoginGraceTime", "{{ P_sshd_login_grace_time }}"),
    "LogLevel is configured": ("LogLevel", "{{ P_sshd_log_level }}"),
    "MaxAuthTries is configured": ("MaxAuthTries", "{{ P_sshd_max_auth_tries }}"),
    "MaxStartups is configured": ("MaxStartups", "{{ P_sshd_max_startups }}"),
    "MaxSessions is configured": ("MaxSessions", "{{ P_sshd_max_sessions }}"),
    "PermitEmptyPasswords is disabled": ("PermitEmptyPasswords", "no"),
    "PermitRootLogin is disabled": ("PermitRootLogin", "{{ P_sshd_permit_root_login }}"),
    "PermitUserEnvironment is disabled": ("PermitUserEnvironment", "no"),
    "UsePAM is enabled": ("UsePAM", "yes"),
    "Banner is configured": ("Banner", "/etc/issue.net"),
}

SSHD_WEAK = {
    "Ciphers": ("ciphers", "P_sshd_weak_ciphers"),
    "KexAlgorithms": ("kexalgorithms", "P_sshd_weak_kex"),
    "MACs": ("macs", "P_sshd_weak_macs"),
}

# --------------------------------------------------------------------------
# Small task builders
# --------------------------------------------------------------------------

def slug(rid):
    return rid.replace(".", "_")


def mod_sysfs(name):
    return name.replace("-", "_")


class Ctx:
    """Per-version build context."""

    def __init__(self, v):
        self.v = int(v)
        self.p = f"rhel{v}cis"
        self.ids_by_title = {}

    def s(self, text):
        """Replace the P_ placeholder with this role's variable prefix."""
        return text.replace("P_", self.p + "_")

    # -- findings -----------------------------------------------------------
    def finding(self, rid, title, kind, detail_expr, when=None):
        task = {
            "name": f"{rid} | Record finding",
            "ansible.builtin.set_fact": {
                f"{self.p}_findings": "{{ %s_findings + [{'id': '%s', 'title': %s, 'type': '%s', 'detail': %s}] }}"
                % (self.p, rid, repr(title), kind, detail_expr)
            },
        }
        if when:
            task["when"] = when
        return task

    def audit(self, rid, title, cmd, kind="audit"):
        """Run a read-only bash check; any stdout lines become a finding."""
        reg = f"{self.p}_chk_{slug(rid)}"
        return [
            {
                "name": f"{rid} | AUDIT | Collect evidence",
                "ansible.builtin.shell": {"cmd": cmd, "executable": "/bin/bash"},
                "register": reg,
                "changed_when": False,
                "failed_when": False,
                "check_mode": False,
            },
            self.finding(rid, title, kind, f"{reg}.stdout_lines[:100]",
                         when=f"{reg}.stdout | trim | length > 0"),
        ]

    def script(self, rid, label, body, notify=None):
        """Run a remediation script that honours check mode.

        The script receives DRY=1 in check mode and must print CHANGED when it
        changed (or, in check mode, would change) something.
        """
        reg = f"{self.p}_fix_{slug(rid)}"
        t = {
            "name": f"{rid} | PATCH | {label}",
            "ansible.builtin.shell": {
                "cmd": "DRY={{ ansible_check_mode | ternary('1', '0') }}\n" + self.s(body),
                "executable": "/bin/bash",
            },
            "register": reg,
            "changed_when": f"'CHANGED' in {reg}.stdout",
            "check_mode": False,
        }
        if notify:
            t["notify"] = notify
        return [t]

    def manual(self, rid, title, evidence=None):
        if evidence:
            return self.audit(rid, title + " (manual review - evidence attached)",
                              evidence + " ; echo 'MANUAL REVIEW REQUIRED'", kind="manual")
        return [self.finding(rid, title, "manual", "['Manual review required - see the CIS benchmark']")]

    def perms(self, rid, paths):
        reg = f"{self.p}_stat_{slug(rid)}"
        specs = [{"path": pth, "owner": o, "group": g, "mode": m} for pth, (o, g, m) in paths]
        return [
            {
                "name": f"{rid} | AUDIT | Stat target paths",
                "ansible.builtin.stat": {"path": "{{ item.path }}"},
                "loop": specs,
                "register": reg,
            },
            {
                "name": f"{rid} | PATCH | Set owner, group and mode",
                "ansible.builtin.file": {
                    "path": "{{ item.item.path }}", "owner": "{{ item.item.owner }}",
                    "group": "{{ item.item.group }}", "mode": "{{ item.item.mode }}",
                },
                "loop": f"{{{{ {reg}.results }}}}",
                "loop_control": {"label": "{{ item.item.path }}"},
                "when": "item.stat.exists",
            },
        ]

    def find_perms(self, rid, paths, patterns, mode, owner="root", group="root",
                   file_type="file", depth=None, hidden=False):
        reg = f"{self.p}_find_{slug(rid)}"
        f = {"paths": paths, "patterns": patterns, "file_type": file_type, "hidden": hidden}
        if depth:
            f["depth"] = depth
            f["recurse"] = True
        t = [
            {"name": f"{rid} | AUDIT | Find files", "ansible.builtin.find": f, "register": reg},
            {
                "name": f"{rid} | PATCH | Set owner, group and mode",
                "ansible.builtin.file": {"path": "{{ item.path }}", "owner": owner,
                                         "group": group, "mode": mode},
                "loop": f"{{{{ {reg}.files }}}}",
                "loop_control": {"label": "{{ item.path }}"},
            },
        ]
        return t

    def lineinfile(self, rid, path, key_regex, line, notify=None, create=True, mode="0644",
                   label=None, validate=None, insertbefore=None, when=None):
        t = {
            "name": f"{rid} | PATCH | {label or line}",
            "ansible.builtin.lineinfile": {
                "path": path, "regexp": key_regex, "line": line, "create": create,
                "owner": "root", "group": "root", "mode": mode,
            },
        }
        if validate:
            t["ansible.builtin.lineinfile"]["validate"] = validate
        if insertbefore:
            t["ansible.builtin.lineinfile"]["insertbefore"] = insertbefore
        if notify:
            t["notify"] = notify
        if when:
            t["when"] = when
        return t

    def pkg(self, rid, names, state, label=None, when=None):
        t = {"name": f"{rid} | PATCH | {label or ('Ensure packages ' + state)}",
             "ansible.builtin.dnf": {"name": names, "state": state}}
        if when:
            t["when"] = when
        return t


def section_of(rid):
    return rid.split(".")[0]


def tags_for(rule):
    tags = [f"rule_{rule['id']}", f"section_{section_of(rule['id'])}", rule["type"]]
    if rule["server"]:
        tags.append(f"level{rule['server']}_server")
    if rule["workstation"]:
        tags.append(f"level{rule['workstation']}_workstation")
    return tags


def title_key(title):
    return re.sub(r"\s+", " ", title).strip()


# --------------------------------------------------------------------------
# Convert collection modules to ansible.builtin equivalents so the roles run
# with nothing but the ansible-core package from RHEL AppStream.
# --------------------------------------------------------------------------
TASK_KEYS = ("when", "loop", "loop_control", "notify", "register", "tags")


def _ini_to_builtin(task):
    a = task["community.general.ini_file"]
    keep = {k: task[k] for k in TASK_KEYS if k in task}
    sec = re.escape(a["section"])
    opt = a["option"]
    opt_rx = opt if "{{" in opt else re.escape(opt)
    if a.get("state") == "absent":
        t = {"name": task["name"],
             "ansible.builtin.lineinfile": {"path": a["path"], "regexp": f"^\\s*{opt_rx}\\s*=", "state": "absent"}}
        t.update(keep)
        return [t]
    mode = a.get("mode", "0644")
    ensure = {"name": task["name"] + " (section)",
              "ansible.builtin.lineinfile": {"path": a["path"], "regexp": f"^\\[{sec}\\]\\s*$",
                                             "line": f"[{a['section']}]", "insertbefore": "BOF",
                                             "firstmatch": True, "create": True, "mode": mode}}
    for k in ("when", "loop", "loop_control"):
        if k in task:
            ensure[k] = task[k]
    t = {"name": task["name"],
         "ansible.builtin.lineinfile": {"path": a["path"], "regexp": f"^\\s*#?\\s*{opt_rx}\\s*=",
                                        "line": f"{opt}={a['value']}", "insertafter": f"^\\[{sec}\\]\\s*$",
                                        "firstmatch": True, "create": True, "mode": mode}}
    t.update(keep)
    return [ensure, t]


def _sysctl_to_builtin(task, prefix):
    a = task["ansible.posix.sysctl"]
    key, val = a["name"], a["value"]
    keep = {k: task[k] for k in TASK_KEYS if k in task}
    flush = ""
    if key.startswith("net.ipv4."):
        flush = " && sysctl -qw net.ipv4.route.flush=1"
    elif key.startswith("net.ipv6."):
        flush = " && sysctl -qw net.ipv6.route.flush=1"
    persist = {"name": task["name"] + " (persistent)",
               "ansible.builtin.lineinfile": {"path": a["sysctl_file"], "regexp": f"^\\s*{re.escape(key)}\\s*=",
                                              "line": f"{key} = {val}", "create": True, "owner": "root",
                                              "group": "root", "mode": "0644"}}
    persist.update({k: v for k, v in keep.items() if k == "when"})
    reg = prefix + "_sysctl_" + re.sub(r"\W", "_", key)
    run = {"name": task["name"] + " (running)",
           "ansible.builtin.shell": {
               "cmd": f"[ \"$(sysctl -n {key} 2>/dev/null)\" = \"{val}\" ] && exit 0\n"
                      f"echo CHANGED\n[ \"{{{{ ansible_check_mode }}}}\" = \"True\" ] || {{ sysctl -qw {key}={val}{flush}; }}",
               "executable": "/bin/bash"},
           "register": reg, "changed_when": f"'CHANGED' in {reg}.stdout", "check_mode": False}
    run.update(keep)
    return [persist, run]


def builtinize(tasks, prefix):
    out = []
    for t in tasks:
        if not isinstance(t, dict):
            out.append(t)
            continue
        if "block" in t:
            t = dict(t)
            t["block"] = builtinize(t["block"], prefix)
            out.append(t)
        elif "community.general.ini_file" in t:
            out.extend(_ini_to_builtin(t))
        elif "ansible.posix.sysctl" in t:
            out.extend(_sysctl_to_builtin(t, prefix))
        else:
            out.extend(_harden(t))
    return out


# Directories that always exist on EL8/9/10 - no need to create them.
_STD_DIRS = {"/etc", "/etc/modprobe.d", "/etc/audit/rules.d", "/etc/profile.d", "/etc/security/limits.d",
             "/etc/crypto-policies/policies/modules", "/etc/systemd/system", "/etc/sudoers.d", "/etc/rsyslog.d",
             "/root", "/etc/security"}
_EDIT_MODULES = ("ansible.builtin.replace", "ansible.builtin.blockinfile", "ansible.builtin.lineinfile")


def _harden(t):
    """Make a task safe when its target file or directory does not exist yet."""
    out = []
    cp = t.get("ansible.builtin.copy")
    if cp and isinstance(cp.get("dest"), str) and "{{" not in cp["dest"]:
        d = cp["dest"].rsplit("/", 1)[0]
        if d not in _STD_DIRS:
            mk = {"name": t["name"] + " (directory)",
                  "ansible.builtin.file": {"path": d, "state": "directory", "owner": "root", "group": "root",
                                           "mode": "0755"}}
            if "when" in t:
                mk["when"] = t["when"]
            out.append(mk)
            # In --check mode the directory above is only simulated, so copy cannot see it.
            t = dict(t)
            reg = t.get("register", "cis_copy_result")
            t["register"] = reg
            t["failed_when"] = (f"{reg} is failed and not (ansible_check_mode and "
                                f"'does not exist' in ({reg}.msg | default('')))")
    for mod in _EDIT_MODULES:
        a = t.get(mod)
        if not a:
            continue
        if mod == "ansible.builtin.lineinfile" and a.get("create"):
            break
        # Editing a file that does not exist (package not installed, or created earlier in a
        # --check run) is "not applicable", not an error.
        t = dict(t)
        reg = t.get("register", "cis_edit_result")
        t["register"] = reg
        t["failed_when"] = f"{reg} is failed and 'does not exist' not in ({reg}.msg | default(''))"
        break
    out.append(t)
    return out
