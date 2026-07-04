#!/bin/bash
#
# Linux Security Hardening & Compliance Audit
# Runs a subset of CIS Ubuntu Linux Benchmark checks against the local host
# and reports a pass/fail result for each, with a summary score at the end.
#
# Reference: CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0
# Section numbers vary between Ubuntu releases and CIS benchmark versions,
# so checks below are identified by control title rather than section number.
# Verify exact section numbers against the benchmark PDF for your Ubuntu release.
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
