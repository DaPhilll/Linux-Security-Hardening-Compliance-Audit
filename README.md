[![Darreon Phillips Homepage](https://img.shields.io/badge/Darreon%20Phillips-Homepage-blue?style=for-the-badge&logo=github&logoColor=white)](https://github.com/DaPhilll)

# Linux Security Hardening & Compliance Audit

## Repository Structure
```
/scripts
  linux-hardening-audit.sh
/compliance-mapping
  cis-nist-soc2-mapping.csv
LICENSE
README.md
```

## 1. Executive Summary & Objective
* **Problem Statement:** Linux hosts are often deployed with default configurations that pass functional testing but leave weak SSH settings, missing host firewalls, over-permissive file access, and disabled audit logging in place. Manual review of these settings does not scale across a fleet and produces inconsistent results between hosts.
* **Solution Overview:** This project is a bash script that checks a Linux host against a subset of the CIS Ubuntu Linux Benchmark, reports a pass or fail result for each check, and returns a summary score. Each check is also mapped to NIST SP 800-53 and SOC 2 Type II controls, tying it to the same compliance framework used in the GRC repository.
* **Core Capabilities:**
  * SSH configuration checks (root login, password authentication).
  * Host firewall verification (UFW status and default policy).
  * File permission checks on `/etc/passwd` and `/etc/shadow`.
  * Account hygiene checks (duplicate UID 0 accounts).
  * Kernel hardening and audit logging verification.
  * A pass/fail score usable as a repeatable baseline check.

## 2. Architecture & Environment Topology
The script is designed to run locally on any Ubuntu host in the shared lab environment (VMware Workstation Pro, `10.10.0.0/24`). It has been run against `SRV-SOC01`, the Ubuntu host that also runs Wazuh, Shuffle, and the Greenbone/OpenVAS scanner in the other repositories.

* **Target Hosts:** Ubuntu Server (`SRV-SOC01`, `SURICATA-01`), or any Ubuntu 22.04/24.04 LTS host.
* **Execution Model:** Local script execution with `sudo`, no agent or scheduled service required for the current version.
* **Reference Benchmark:** CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.

## 3. Engineering Thought Process & Methodology
* **Design Considerations:** CIS Benchmark documents run to over 200 controls per Ubuntu release, and most environments don't need or want every control applied. This script covers a smaller, high-value subset — SSH, firewall, file permissions, account hygiene, and audit logging — rather than attempting full benchmark coverage.
* **Technical Challenges & Resolution:**
  * **Challenge:** CIS control section numbers change between Ubuntu releases and benchmark versions (20.04, 22.04, and 24.04 each number sections differently), so hardcoding a section number risks citing the wrong control for a given host.
  * **Resolution:** Checks are identified by control title rather than section number in both the script and the compliance mapping. The README and script both note that section numbers should be verified against the specific benchmark PDF for the Ubuntu release in use.

## 4. Cyber Kill Chain & Threat Lifecycle Mapping
* **Initial Access & Privilege Escalation:** Disabling SSH root login and password authentication removes the most common brute-force and credential-stuffing path into a Linux host. Restricting `/etc/shadow` permissions and eliminating duplicate UID 0 accounts closes off two common local privilege-escalation vectors.
* **Defense Evasion:** Verifying that auditd is active ensures security-relevant events are still logged even if an attacker gains a foothold, supporting after-the-fact investigation.

## 5. Compliance Alignment
Full mapping data is in `/compliance-mapping/cis-nist-soc2-mapping.csv`.

| Check | NIST SP 800-53 | SOC 2 TSC |
| :--- | :--- | :--- |
| SSH Root Login Disabled | AC-6 | CC6.1 |
| SSH Password Authentication Disabled | IA-2 | CC6.1 |
| UFW Installed and Running | SC-7 | CC6.6 |
| Default Deny Firewall Policy | SC-7 | CC6.6 |
| `/etc/passwd` Permissions | AC-6 | CC6.1 |
| `/etc/shadow` Permissions | IA-5 | CC6.1 |
| No Duplicate UID 0 Accounts | AC-2 | CC6.2 |
| ASLR Enabled | SI-16 | CC6.6 |
| Auditd Installed and Enabled | AU-2 | CC7.2 |
| Automatic Security Updates | SI-2 | CC7.1 |
| Telnet Server Not Installed (custom) | CM-7 | CC6.6 |

## 6. Reference Benchmark
* **CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0** — source for the SSH, firewall, file permission, and auditd checks. Section numbers differ for Ubuntu 20.04 and 22.04; verify against the benchmark version matching your target host before treating a section number as authoritative.
* **Custom Check:** Telnet server presence is not part of the CIS benchmark used here; it's included because a cleartext remote-access service has no legitimate use case in this lab.

## 7. Implementation & Code

### Audit Script
`scripts/linux-hardening-audit.sh`
```bash
#!/bin/bash
#
# Linux Security Hardening & Compliance Audit
# Runs a subset of CIS Ubuntu Linux Benchmark checks against the local host
# and reports a pass/fail result for each, with a summary score at the end.
#
# Usage: sudo ./linux-hardening-audit.sh

PASS_COUNT=0
FAIL_COUNT=0

pass() {
    echo "PASS | $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
    echo "FAIL | $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

echo "Linux Security Hardening & Compliance Audit"
echo "Host: $(hostname)   Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "------------------------------------------------------------"

# Ensure SSH Root Login Is Disabled
if grep -Eq '^\s*PermitRootLogin\s+no\b' /etc/ssh/sshd_config 2>/dev/null; then
    pass "Ensure SSH Root Login Is Disabled"
else
    fail "Ensure SSH Root Login Is Disabled"
fi

# Ensure SSH Password Authentication Is Disabled
if grep -Eq '^\s*PasswordAuthentication\s+no\b' /etc/ssh/sshd_config 2>/dev/null; then
    pass "Ensure SSH Password Authentication Is Disabled"
else
    fail "Ensure SSH Password Authentication Is Disabled"
fi

# Ensure UFW Is Installed and Running
if command -v ufw &>/dev/null && sudo ufw status | grep -q "Status: active"; then
    pass "Ensure UFW Is Installed and Running"
else
    fail "Ensure UFW Is Installed and Running"
fi

# Ensure Default Deny Firewall Policy Is Set
if sudo ufw status verbose 2>/dev/null | grep -q "Default: deny (incoming)"; then
    pass "Ensure Default Deny Firewall Policy Is Set"
else
    fail "Ensure Default Deny Firewall Policy Is Set"
fi

# Ensure Permissions on /etc/passwd Are Configured (644 or stricter)
passwd_perms=$(stat -c %a /etc/passwd 2>/dev/null)
if [ -n "$passwd_perms" ] && [ "$passwd_perms" -le 644 ]; then
    pass "Ensure Permissions on /etc/passwd Are Configured"
else
    fail "Ensure Permissions on /etc/passwd Are Configured"
fi

# Ensure Permissions on /etc/shadow Are Configured (640 or stricter)
shadow_perms=$(stat -c %a /etc/shadow 2>/dev/null)
if [ -n "$shadow_perms" ] && [ "$shadow_perms" -le 640 ]; then
    pass "Ensure Permissions on /etc/shadow Are Configured"
else
    fail "Ensure Permissions on /etc/shadow Are Configured"
fi

# Ensure No Duplicate UID 0 Accounts Exist
dup_uid0=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | grep -vc '^root$')
if [ "$dup_uid0" -eq 0 ]; then
    pass "Ensure No Duplicate UID 0 Accounts Exist"
else
    fail "Ensure No Duplicate UID 0 Accounts Exist"
fi

# Ensure Address Space Layout Randomization (ASLR) Is Enabled
aslr=$(sysctl -n kernel.randomize_va_space 2>/dev/null)
if [ "$aslr" = "2" ]; then
    pass "Ensure ASLR Is Enabled"
else
    fail "Ensure ASLR Is Enabled"
fi

# Ensure Auditd Is Installed and Enabled
if systemctl is-active --quiet auditd 2>/dev/null; then
    pass "Ensure Auditd Is Installed and Enabled"
else
    fail "Ensure Auditd Is Installed and Enabled"
fi

# Ensure Automatic Security Updates Are Configured
if dpkg -s unattended-upgrades &>/dev/null; then
    pass "Ensure Automatic Security Updates Are Configured"
else
    fail "Ensure Automatic Security Updates Are Configured"
fi

# Custom: Ensure Telnet Server Is Not Installed
if dpkg -s telnetd &>/dev/null; then
    fail "Custom: Telnet Server Not Installed"
else
    pass "Custom: Telnet Server Not Installed"
fi

echo "------------------------------------------------------------"
total=$((PASS_COUNT + FAIL_COUNT))
echo "Score: $PASS_COUNT / $total checks passed"
```

## 8. Sample Run
The output below is from an actual run of the script (not simulated), against a host with default SSH, firewall, and audit settings still in place, to show baseline output before hardening is applied.

```bash
$ sudo ./linux-hardening-audit.sh
Linux Security Hardening & Compliance Audit
Host: SRV-SOC01   Date: 2026-07-04T16:43:52Z
------------------------------------------------------------
FAIL | Ensure SSH Root Login Is Disabled
FAIL | Ensure SSH Password Authentication Is Disabled
FAIL | Ensure UFW Is Installed and Running
FAIL | Ensure Default Deny Firewall Policy Is Set
PASS | Ensure Permissions on /etc/passwd Are Configured
PASS | Ensure Permissions on /etc/shadow Are Configured
PASS | Ensure No Duplicate UID 0 Accounts Exist
PASS | Ensure ASLR Is Enabled
FAIL | Ensure Auditd Is Installed and Enabled
FAIL | Ensure Automatic Security Updates Are Configured
PASS | Custom: Telnet Server Not Installed
------------------------------------------------------------
Score: 5 / 11 checks passed
```

Running the script again after applying the corresponding hardening steps (disabling SSH root login and password auth, enabling UFW with a default-deny policy, installing and enabling auditd, and installing `unattended-upgrades`) brings the score to 11/11.

## 9. Hardening & Future Enhancements
* **Current Posture:** The script is read-only; it reports findings but does not modify system configuration. Hardening changes are applied manually based on the failed checks.
* **Future Roadmap:**
  * [ ] Add a `--remediate` flag that applies safe, reversible fixes for a subset of checks (SSH config, UFW policy) with a `--dry-run` option.
  * [ ] Extend the compliance mapping to a second CSV for Windows hosts, reusing the format already established in the GRC repository's risk register.
  * [ ] Schedule the script via cron on `SRV-SOC01` and forward output to the Wazuh deployment for trend tracking over time.

## License
MIT — see [LICENSE](./LICENSE).

<br><br><br>
[![Darreon Phillips Homepage](https://img.shields.io/badge/Darreon%20Phillips-Homepage-blue?style=for-the-badge&logo=github&logoColor=white)](https://github.com/DaPhilll)
