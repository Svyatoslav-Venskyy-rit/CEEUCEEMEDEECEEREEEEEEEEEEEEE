#!/bin/bash
# Configuration
LOGFILE="/var/log/ccdc_password_reset_$(date +%F_%H%M%S).log"  # Timestamped log file
PROTECTED_USER="whiteteam blackteam grayteam grayteam dd-dog datadog"  # User to skip (protected)
# Target users: Merged from both scripts (comp users only, excluding system/standard ones)
TARGET_USERS="root drwho martymcfly arthurdent sambeckett loki riphunter theflash tonystark drstrange bartallen merlin terminator mrpeabody jamescole docbrown professorparadox"

echo "$(date): Starting single-password reset for target users." | tee -a $LOGFILE

# Prompt for the single password to set for all users
read -s -p "Enter the new password for all target users: " NEW_PASSWORD
echo  # Newline after input
if [ -z "$NEW_PASSWORD" ]; then
    echo "ERROR: No password provided. Aborting." | tee -a $LOGFILE
    exit 1
fi

# Confirm password (optional but recommended for safety)
read -s -p "Confirm the new password: " CONFIRM_PASSWORD
echo
if [ "$NEW_PASSWORD" != "$CONFIRM_PASSWORD" ]; then
    echo "ERROR: Passwords do not match. Aborting." | tee -a $LOGFILE
    exit 1
fi

for user in $TARGET_USERS; do
    # Skip protected user
    if [ "$user" == "$PROTECTED_USER" ]; then
        echo "$(date): SKIP: Protected account $PROTECTED_USER is EXCLUDED." | tee -a $LOGFILE
        continue
    fi

    # Check if user exists
    if id "$user" >/dev/null 2>&1; then
        # Log old hash for auditing
        OLD_HASH=$(grep "^$user:" /etc/shadow 2>/dev/null | cut -d: -f2)
        if [ -z "$OLD_HASH" ]; then
            OLD_HASH="N/A (User not in shadow file)"
        fi

        # Change password
        echo "$user:$NEW_PASSWORD" | chpasswd

        echo "$(date): SUCCESS: Reset password for $user (Old hash: $OLD_HASH)" | tee -a $LOGFILE
        echo "Reset password for user: $user"
    else
        echo "$(date): SKIP: User $user not found on system." | tee -a $LOGFILE
    fi
done

echo "$(date): Password reset complete. Log saved to $LOGFILE. **Remember to securely manage the new password!**" | tee -a $LOGFILE

# Usage: Save as reset_passwords.sh, then: chmod +x reset_passwords.sh && sudo ./reset_passwords.sh
