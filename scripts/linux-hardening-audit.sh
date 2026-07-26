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

skip() {
    echo "SKIP | $1"
}

# Compare a file mode against the maximum permitted mode.
# Modes are octal, so a numeric comparison is wrong: 466 is numerically less
# than 644 but grants group and other write. This masks off the permitted bits
# and requires the remainder to be zero.
mode_within() {
    local actual=$1 max=$2
    [ -n "$actual" ] || return 1
    (( (8#$actual & ~8#$max) == 0 ))
}

if [ "$(id -u)" -ne 0 ]; then
    echo "This script reads root-owned files and must be run with sudo." >&2
    exit 1
fi

echo "Linux Security Hardening & Compliance Audit"
echo "Host: $(hostname)   Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "------------------------------------------------------------"

# SSH checks read the effective configuration via 'sshd -T' rather than grepping
# /etc/ssh/sshd_config directly. Ubuntu 22.04 and later include
# /etc/ssh/sshd_config.d/*.conf, and the installer-generated 50-cloud-init.conf
# can set PasswordAuthentication yes, overriding the main file. Grepping only
# the main file reports a pass while password auth is actually enabled
# (Ubuntu bug LP#2088207).
if command -v sshd &>/dev/null; then
    SSHD_EFFECTIVE=$(sshd -T 2>/dev/null)
elif [ -x /usr/sbin/sshd ]; then
    SSHD_EFFECTIVE=$(/usr/sbin/sshd -T 2>/dev/null)
else
    SSHD_EFFECTIVE=""
fi

if [ -z "$SSHD_EFFECTIVE" ]; then
    skip "Ensure SSH Root Login Is Disabled (sshd not installed or config unreadable)"
    skip "Ensure SSH Password Authentication Is Disabled (sshd not installed or config unreadable)"
else
    # Ensure SSH Root Login Is Disabled
    if echo "$SSHD_EFFECTIVE" | grep -qi '^permitrootlogin no$'; then
        pass "Ensure SSH Root Login Is Disabled"
    else
        fail "Ensure SSH Root Login Is Disabled"
    fi

    # Ensure SSH Password Authentication Is Disabled
    if echo "$SSHD_EFFECTIVE" | grep -qi '^passwordauthentication no$'; then
        pass "Ensure SSH Password Authentication Is Disabled"
    else
        fail "Ensure SSH Password Authentication Is Disabled"
    fi
fi

# Ensure UFW Is Installed and Running
if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    pass "Ensure UFW Is Installed and Running"
else
    fail "Ensure UFW Is Installed and Running"
fi

# Ensure Default Deny Firewall Policy Is Set
if command -v ufw &>/dev/null && ufw status verbose 2>/dev/null | grep -q "Default: deny (incoming)"; then
    pass "Ensure Default Deny Firewall Policy Is Set"
else
    fail "Ensure Default Deny Firewall Policy Is Set"
fi

# Ensure Permissions on /etc/passwd Are Configured (644 or stricter)
if mode_within "$(stat -c %a /etc/passwd 2>/dev/null)" 644; then
    pass "Ensure Permissions on /etc/passwd Are Configured"
else
    fail "Ensure Permissions on /etc/passwd Are Configured"
fi

# Ensure Permissions on /etc/shadow Are Configured (640 or stricter)
if mode_within "$(stat -c %a /etc/shadow 2>/dev/null)" 640; then
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

# Ensure Address Space Layout Randomization (ASLR) Is Enabled.
# Checks the running value and that it is persisted, since a runtime-only
# setting reverts on reboot.
aslr_runtime=$(sysctl -n kernel.randomize_va_space 2>/dev/null)
aslr_persisted=$(grep -Rhs '^\s*kernel.randomize_va_space\s*=\s*2' \
    /etc/sysctl.conf /etc/sysctl.d/ 2>/dev/null | head -n1)
if [ "$aslr_runtime" = "2" ] && [ -n "$aslr_persisted" ]; then
    pass "Ensure ASLR Is Enabled"
elif [ "$aslr_runtime" = "2" ]; then
    fail "Ensure ASLR Is Enabled (active now but not persisted in sysctl config)"
else
    fail "Ensure ASLR Is Enabled"
fi

# Ensure Auditd Is Installed and Enabled
if systemctl is-enabled --quiet auditd 2>/dev/null && systemctl is-active --quiet auditd 2>/dev/null; then
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
