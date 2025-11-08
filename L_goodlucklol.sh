#!/bin/bash

# Script for Initial Evidence Collection on Linux for CCDC
# Adapted from Windows PowerShell version
# Incorporates scanning for suspicious elements and interactive remediation options
# Run as root for full access (sudo ./script.sh)

# Configuration
hostname=$(hostname)
timestamp=$(date +%Y%m%d_%H%M%S)
evidenceDir="/tmp/InitialEvidence_${timestamp}"
logfile="${evidenceDir}/00_scan_log_${timestamp}.log"
remediation_log="${evidenceDir}/00_remediation_log_${timestamp}.log"

# Services required for scoring or basic functionality (adjust based on competition packet)
scored_svcs="sshd vsftpd mysqld httpd apache2 wazuh docker"

# System users to exclude from 'extras' check (adjust for distro)
system_excludes="root daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody systemd-network systemd-resolve systemd-timesync systemd-coredump messagebus _apt colord whoopsie systemd-journal-remote"

# Users listed in the packet for your team's network (adjust based on competition packet)
packet_users="drwho martymcfly arthurdent sambeckett loki riphunter theflash tonystark drstrange bartallen merlin terminator mrpeabody jamescole docbrown professorparadox"

# Suspicious process names
suspicious_names="nc ncat netcat powercat mimikatz psexec procdump cobalt meterpreter empire powershell cmd miner crypto backdoor reverse shell pty"

# Create evidence directory
mkdir -p "$evidenceDir"
echo "INITIAL EVIDENCE COLLECTION" | tee -a "$logfile"
echo "Machine: $hostname" | tee -a "$logfile"
echo "Time: $(date)" | tee -a "$logfile"
echo "" | tee -a "$logfile"
echo "Evidence will be saved to: $evidenceDir" | tee -a "$logfile"

function pause_for_screenshot {
    local message=$1
    echo -e "\n[SCREENSHOT] $message" | tee -a "$logfile"
    echo "Press Enter when screenshot is taken..."
    read -r
}

# All Users
echo -e "\n=== 👥 ALL USERS ===" | tee -a "$logfile"
all_users=$(getent passwd | cut -d: -f1,3,4,6,7 | sort)
echo "$all_users" | tee "$evidenceDir/01_local_users.txt"
echo "$all_users" | tee -a "$logfile"

# Enabled Users (users with valid shells and not locked)
echo -e "\nEnabled Users:" | tee -a "$logfile"
enabled_users=$(getent passwd | awk -F: '{ if ($7 !~ /nologin|false/ && $7 != "") print $1 }' | sort)
for user in $enabled_users; do
    if [[ $user == *"admin"* ]]; then
        echo "$user" | tee -a "$logfile"
    else
        echo "$user" | tee -a "$logfile"
    fi
done
pause_for_screenshot "Take screenshot of ALL USERS above"

# Sudoers / Admins (users in sudo or wheel group)
echo -e "\nCurrent Administrators (sudo/wheel group members):" | tee -a "$logfile"
admins=""
if getent group sudo >/dev/null; then
    admins=$(getent group sudo | cut -d: -f4 | tr ',' '\n')
elif getent group wheel >/dev/null; then
    admins=$(getent group wheel | cut -d: -f4 | tr ',' '\n')
fi
echo "$admins" | tee "$evidenceDir/02_administrators.txt"
echo "$admins" | tee -a "$logfile"
pause_for_screenshot "Take screenshot of ADMINISTRATORS"

# All Groups
echo -e "\n=== 👥 LOCAL GROUPS ===" | tee -a "$logfile"
groups=$(getent group | cut -d: -f1,3 | sort)
echo "$groups" | tee "$evidenceDir/03_local_groups.txt"
echo "$groups" | tee -a "$logfile"

# Important Groups
important_groups="sudo wheel adm admin root docker"
for group in $important_groups; do
    if getent group "$group" >/dev/null; then
        members=$(getent group "$group" | cut -d: -f4 | tr ',' '\n')
        if [[ -n $members ]]; then
            echo -e "\n$group members:" | tee -a "$logfile"
            echo "$members" | tee -a "$logfile"
            echo "$members" | tee "$evidenceDir/03_group_${group}_members.txt"
        fi
    fi
done

# Extra Users (not in packet or system excludes)
echo -e "\nWARNING: Extra Users (Potential Malicious/New Accounts):" | tee -a "$logfile"
expected_regex=$(echo $packet_users $system_excludes | sed 's/ /|/g')
extra_users=$(getent passwd | cut -d: -f1 | grep -vE "^($expected_regex)$" | grep -vE "(^$|#)")
echo "$extra_users" | tee -a "$logfile"

# Processes
echo -e "\n=== 🚨 ALL PROCESSES (ps aux) ===" | tee -a "$logfile"
processes=$(ps aux --sort=-%cpu | head -n 50)  # Top 50 for brevity
echo "$processes" | tee "$evidenceDir/04_all_processes.txt"
echo "Top CPU/MEM Processes:" | tee -a "$logfile"
echo "$processes" | tee -a "$logfile"

# Suspicious Processes
echo -e "\nPotentially suspicious processes:" | tee -a "$logfile"
found_suspicious=false
suspicious_procs=$(ps aux | grep -E "($(echo $suspicious_names | tr ' ' '|'))" | grep -v grep)
if [[ -n $suspicious_procs ]]; then
    echo "$suspicious_procs" | tee -a "$logfile"
    found_suspicious=true
fi
if $found_suspicious; then
    pause_for_screenshot "Take screenshot of SUSPICIOUS PROCESSES"
fi

# Network Connections
echo -e "\n=== 📡 ESTABLISHED CONNECTIONS (ss -tup) ===" | tee -a "$logfile"
if command -v ss >/dev/null; then
    connections=$(ss -tup | grep ESTAB)
else
    connections=$(netstat -tup | grep ESTAB)
fi
echo "$connections" | tee "$evidenceDir/05_network_connections.txt"
echo "$connections" | tee -a "$logfile"

# Suspicious External Connections (non-local IPs)
suspicious_connections=""
while read -r conn; do
    remote=$(echo "$conn" | awk '{print $5}' | cut -d: -f1)
    if [[ ! $remote =~ ^(127\.|10\.|192\.168\.|172\.16\.|172\.20\.|::1) ]]; then
        suspicious_connections+="$conn\n"
        echo "EXTERNAL: $conn" | tee -a "$logfile"
    fi
done <<< "$connections"
if [[ -n $suspicious_connections ]]; then
    pause_for_screenshot "Take screenshot of EXTERNAL CONNECTIONS"
fi

# Listening Ports
echo -e "\n=== 📡 LISTENING PORTS (ss -tuln) ===" | tee -a "$logfile"
if command -v ss >/dev/null; then
    listening=$(ss -tuln)
else
    listening=$(netstat -tuln)
fi
echo "$listening" | tee "$evidenceDir/11_listening_ports.txt"
echo "$listening" | tee -a "$logfile"

# Non-Scored Ports (exclude common scored ones)
echo -e "\nWARNING: Non-Scored Ports (review these!):" | tee -a "$logfile"
echo "$listening" | awk 'NR>1 {split($5, a, ":"); port = a[length(a)]; if (port !~ /^(22|21|3306|80|443|55000)$/ && port >= 1024) print $0}' | tee -a "$logfile"

# Scheduled Tasks / Cron Jobs
echo -e "\n=== 🕰️ CUSTOM SCHEDULED TASKS / CRON JOBS ===" | tee -a "$logfile"
crons=""
crons+="$(crontab -l 2>/dev/null || echo 'No user crontab')\n"
crons+="System Crontab:\n$(cat /etc/crontab 2>/dev/null)\n"
crons+="Cron.d:\n$(ls -la /etc/cron.d/ 2>/dev/null)\n"
echo "$crons" | tee "$evidenceDir/06_scheduled_tasks.txt"
echo "$crons" | tee -a "$logfile"
found_tasks=false
if [[ -n $(echo "$crons" | grep -v "No user crontab") ]]; then
    found_tasks=true
fi
if $found_tasks; then
    pause_for_screenshot "Take screenshot of SCHEDULED TASKS"
fi

# Systemd Timers (additional scheduled)
echo -e "\nSystemd Timers:" | tee -a "$logfile"
timers=$(systemctl list-timers --all --no-pager 2>/dev/null)
echo "$timers" | tee -a "$logfile"
echo "$timers" | tee "$evidenceDir/06_systemd_timers.txt"

# Startup Programs / Enabled Services
echo -e "\n=== 🚀 STARTUP PROGRAMS / ENABLED SERVICES ===" | tee -a "$logfile"
startup=$(systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null)
echo "$startup" | tee "$evidenceDir/07_startup_programs.txt"
echo "$startup" | tee -a "$logfile"
if [[ -n $startup ]]; then
    pause_for_screenshot "Take screenshot of STARTUP PROGRAMS"
fi

# Persistence via Run Keys equivalents (e.g., /etc/rc.local, .bashrc, etc.)
echo -e "\n=== 🔑 PERSISTENCE CHECKS (rc.local, profiles, etc.) ===" | tee -a "$logfile"
run_keys=""
run_keys+="/etc/rc.local:\n$(cat /etc/rc.local 2>/dev/null)\n"
run_keys+="/etc/profile:\n$(cat /etc/profile 2>/dev/null | grep -E 'alias|export|source|sh|bash')\n"
run_keys+="User .bashrc files:\n"
for home in /home/* /root; do
    if [[ -f $home/.bashrc ]]; then
        run_keys+="$home/.bashrc:\n$(grep -E 'alias|export|source|sh|bash' $home/.bashrc)\n"
    fi
done
echo "$run_keys" | tee "$evidenceDir/08_persistence_checks.txt"
echo "$run_keys" | tee -a "$logfile"
found_run_keys=false
if [[ -n $run_keys ]]; then
    found_run_keys=true
fi
if $found_run_keys; then
    pause_for_screenshot "Take screenshot of PERSISTENCE CHECKS"
fi

# Services
echo -e "\n=== 💡 CUSTOM RUNNING SERVICES ===" | tee -a "$logfile"
services=$(systemctl list-units --type=service --state=running --no-pager | grep -vE "systemd|dbus|NetworkManager|avahi|bluetooth|polkit|rtkit|udisks|upower|wpa_supplicant|gdm|gnome|colord|accounts|geoclue|packagekit|switcheroo|ModemManager|thermald|acpid|whoopsie|bolt|fwupd|rsyslog|rsync|unattended|snap|apparmor|irqbalance|kerneloops|apport|plymouth|speech|speech-dispatcher|speech-dispatcher-audio|alsa|pulse|gvfs|atd|cron|anacron|logrotate|rsyslog|unattended-upgrades")
echo "$services" | tee "$evidenceDir/09_custom_services.txt"
echo "$services" | tee -a "$logfile"
all_services=$(systemctl list-units --type=service --no-pager)
echo "$all_services" | tee "$evidenceDir/09_all_services.txt"

# Firewall
echo -e "\n=== 🛡️ FIREWALL STATUS ===" | tee -a "$logfile"
if command -v ufw >/dev/null; then
    firewall=$(ufw status verbose)
elif command -v firewall-cmd >/dev/null; then
    firewall=$(firewall-cmd --list-all)
else
    firewall=$(iptables -L -v -n)
fi
echo "$firewall" | tee "$evidenceDir/10_firewall_profiles.txt"
echo "$firewall" | tee -a "$logfile"
pause_for_screenshot "Take screenshot of FIREWALL STATUS"

# Recent Logons / Auth Logs
echo -e "\n=== 🔑 RECENT LOGONS (last 20) ===" | tee -a "$logfile"
logons=$(last -20)
echo "$logons" | tee "$evidenceDir/12_recent_logons.txt"
echo "$logons" | tee -a "$logfile"

# Failed Logons
echo -e "\nFailed Logons (grep auth.log or journalctl):" | tee -a "$logfile"
if [[ -f /var/log/auth.log ]]; then
    failed_logons=$(grep -i "failed password" /var/log/auth.log | tail -20)
elif command -v journalctl >/dev/null; then
    failed_logons=$(journalctl -u ssh -u systemd-logind --since "1 day ago" | grep -i "failed\|invalid" | tail -20)
fi
echo "$failed_logons" | tee "$evidenceDir/12_failed_logons.txt"
echo "$failed_logons" | tee -a "$logfile"
if [[ -n $failed_logons ]]; then
    pause_for_screenshot "Take screenshot showing FAILED LOGON count"
fi

# New Users (from logs)
echo -e "\nNew Users Created (grep auth.log or journalctl):" | tee -a "$logfile"
if [[ -f /var/log/auth.log ]]; then
    new_users=$(grep -i "new user" /var/log/auth.log | tail -10)
elif command -v journalctl >/dev/null; then
    new_users=$(journalctl --since "1 day ago" | grep -i "created user" | tail -10)
fi
echo "$new_users" | tee "$evidenceDir/12_new_users.txt"
echo "$new_users" | tee -a "$logfile"

# Web Files (if web server present)
if [[ -d /var/www ]]; then
    echo -e "\n=== 🌐 WEB FILES (/var/www) ===" | tee -a "$logfile"
    web_files=$(find /var/www -type f -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort -r | head -50)
    echo "$web_files" | tee "$evidenceDir/13_web_files.txt"
    echo "Web files found: $(echo "$web_files" | wc -l)" | tee -a "$logfile"

    # Suspicious recent web files
    suspicious_web=$(find /var/www -type f \( -name "*.php" -o -name "*.asp" -o -name "*.jsp" -o -name "*.aspx" \) -mtime -1)
    if [[ -n $suspicious_web ]]; then
        echo -e "\nRecent web files (potential webshells):" | tee -a "$logfile"
        echo "$suspicious_web" | tee -a "$logfile"
        pause_for_screenshot "Take screenshot of SUSPICIOUS WEB FILES"
    fi
fi

# SMB Shares (if samba running)
smb_service=$(systemctl status smb 2>/dev/null || systemctl status smbd 2>/dev/null)
if [[ -n $smb_service ]]; then
    echo -e "\n=== 📂 SMB SHARES ===" | tee -a "$logfile"
    shares=$(smbstatus -S 2>/dev/null || cat /etc/samba/smb.conf | grep -E "^\[" | grep -v global)
    echo "$shares" | tee "$evidenceDir/14_smb_shares.txt"
    echo "$shares" | tee -a "$logfile"
    pause_for_screenshot "Take screenshot of SMB SHARES"
fi

# AD Info (if joined to domain, assumes sssd or winbind)
if command -v wbinfo >/dev/null || command -v getent >/dev/null; then
    echo -e "\n=== 🏰 ACTIVE DIRECTORY INFO ===" | tee -a "$logfile"
    ad_users=$(getent passwd | grep '@' | cut -d: -f1)  # Domain users
    echo "$ad_users" | tee "$evidenceDir/15_ad_users.txt"
    ad_groups=$(getent group | grep '@')
    echo "$ad_groups" | tee "$evidenceDir/15_ad_groups.txt"
    echo "AD information collected" | tee -a "$logfile"
fi

# Summary
echo "EVIDENCE COLLECTION COMPLETE" | tee -a "$logfile"
summary="
INITIAL EVIDENCE COLLECTION SUMMARY
Machine: $hostname
Collection Time: $(date)
Evidence Location: $evidenceDir
FINDINGS:
- Enabled Users: $(echo "$enabled_users" | wc -l)
- Administrators: $(echo "$admins" | wc -l)
- Running Processes: $(ps aux | wc -l)
- Established Connections: $(echo "$connections" | wc -l)
- External Connections: $(echo -e "$suspicious_connections" | wc -l)
- Custom Scheduled Tasks: $(echo "$crons" | grep -c '^')
- Startup Programs: $(echo "$startup" | grep -c service)
- Failed Logons: $(echo "$failed_logons" | wc -l)
RED FLAGS TO INVESTIGATE:
$(if [[ $(echo -e "$suspicious_connections" | wc -l) -gt 0 ]]; then echo "External network connections found!"; fi)
$(if [[ $(echo "$failed_logons" | wc -l) -gt 5 ]]; then echo "Multiple failed logon attempts!"; fi)
$(if [[ -n $new_users ]]; then echo "New user accounts were created!"; fi)
$(if $found_suspicious; then echo "Suspicious processes detected!"; fi)
"
echo "$summary" | tee "$evidenceDir/00_SUMMARY.txt"
echo "$summary" | tee -a "$logfile"

# Quick console filter for warnings
cat "$logfile" | grep -E "WARNING|ERROR|Suspicious|EXTERNAL|RED FLAGS"

# Interactive Remediation Section
echo -e "\n=== 🛠️ INTERACTIVE REMEDIATION ==="
echo "$(date): Starting interactive remediation" | tee -a "$remediation_log"

# Kill Suspicious Processes
echo -e "\n=== PROCESS REMEDIATION ===" | tee -a "$remediation_log"
for susp in $suspicious_names; do
    pids=$(pgrep -f "$susp")
    if [[ -n $pids ]]; then
        echo "Found suspicious process '$susp' (PIDs: $pids). Kill? (y/n)"
        read -r confirm
        if [[ $confirm == "y" ]]; then
            kill -9 $pids
            echo "$(date): Killed suspicious process '$susp' PIDs $pids" | tee -a "$remediation_log"
        fi
    fi
done

# Disable Unknown Services
echo -e "\n=== SERVICE REMEDIATION ===" | tee -a "$remediation_log"
unknown_svcs=$(systemctl list-units --type=service --state=running --no-pager | awk '{print $1}' | grep .service | grep -vE "($(echo $scored_svcs | tr ' ' '|'))")
for svc in $unknown_svcs; do
    if systemctl is-active --quiet "$svc"; then
        if ! echo "$scored_svcs" | grep -q "$svc"; then
            echo "Unknown service '$svc' active. Stop/disable? (y/n)"
            read -r confirm
            if [[ $confirm == "y" ]]; then
                systemctl stop "$svc"
                systemctl disable "$svc"
                echo "$(date): Stopped/disabled unknown service '$svc'" | tee -a "$remediation_log"
            fi
        else
            echo "Service '$svc' is a SCORED SERVICE. Skipping."
        fi
    fi
done

# Close Non-Scored Ports
echo -e "\n=== FIREWALL REMEDIATION ===" | tee -a "$remediation_log"
non_scored_ports=$(echo "$listening" | awk 'NR>1 {split($5, a, ":"); port = a[length(a)]; if (port !~ /^(22|21|3306|80|443|55000)$/ && port >= 1024) print port}' | sort -u)
for port in $non_scored_ports; do
    echo "Block port $port? (y/n)"
    read -r confirm
    if [[ $confirm == "y" ]]; then
        if command -v ufw >/dev/null; then
            ufw deny "$port"
            echo "$(date): UFW denied port $port" | tee -a "$remediation_log"
        elif command -v iptables >/dev/null; then
            iptables -A INPUT -p tcp --dport "$port" -j DROP
            echo "$(date): iptables dropped TCP port $port" | tee -a "$remediation_log"
        fi
    fi
done

# Cron Job Clean-up
echo -e "\n=== CRON REMEDIATION (Interactive Targeted Removal) ===" | tee -a "$remediation_log"
crontab -l > /dev/null 2>&1
if [[ $? -eq 0 ]]; then
    echo "User crontab found. Remove a specific malicious job? (y/n)"
    read -r confirm
    if [[ $confirm == "y" ]]; then
        echo "Enter the UNIQUE PHRASE/SIGNATURE of the malicious cron job (e.g., /tmp/backdoor_script.sh):"
        read -r malicious_phrase
        if [[ -n $malicious_phrase ]]; then
            crontab -l > /tmp/current_crontab.txt
            sed "/$malicious_phrase/d" /tmp/current_crontab.txt > /tmp/clean_crontab.txt
            if ! cmp -s /tmp/current_crontab.txt /tmp/clean_crontab.txt; then
                crontab /tmp/clean_crontab.txt
                echo "$(date): Removed cron job with phrase '$malicious_phrase'." | tee -a "$remediation_log"
            else
                echo "$(date): Phrase '$malicious_phrase' not found. No changes." | tee -a "$remediation_log"
            fi
            rm /tmp/current_crontab.txt /tmp/clean_crontab.txt
        fi
    fi
else
    echo "No user crontab found. Skipping." | tee -a "$remediation_log"
fi

echo -e "\n$(date): Remediation complete. Rerun the scan if needed." | tee -a "$remediation_log"
echo "** Evidence saved to: $evidenceDir **"
echo "Press Enter to exit..."
read -r
