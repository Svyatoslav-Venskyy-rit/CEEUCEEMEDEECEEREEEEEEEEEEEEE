<#
  CCDC Password Reset Script (INTERACTIVE)
  - This script is designed for CCDC to secure both Local and Domain accounts.
  - It uses a single password set within the script (edit $NewPassword).
  - IMPORTANT: It now prompts for Y/N confirmation before changing the password for *each* enabled, non-excluded account.
  - It handles accounts in three ways: EXCLUDED, TARGETED, and CATCH-ALL.
  - Generates a detailed report. MUST be run as Administrator/Domain Admin.
#>

# =========================================================
# === EDIT THIS LINE FOR THE NEW PASSWORD (CRITICAL!) ===
# =========================================================
$NewPassword = '1234567890ABC!@#' 

# ------------------------------------
# --- LISTS FOR LOGIC CONTROL ---
# ------------------------------------

# A. EXCLUSION LIST: Accounts containing these names (case-insensitive) are NEVER touched (e.g., scoring engines)
$exclusionPatterns = @(
    'datadog', 'dd-dog',
    'whiteteam', 'blackteam', 'grayteam' # Add any other scoring/comp/team accounts here
)

# B. TARGET LIST: These are the specific accounts you want to ensure are changed.
$targetSpecificUsers = @(
    'fathertime', 'chronos', 'aion', 'kairos', 'merlin', 'terminator', 'mrpeabody', 'jamescole',
    'docbrown', 'professorparadox', 'drwho', 'martymcfly', 'arthurdent', 'sambeckett', 'loki',
    'riphunter', 'theflash', 'tonystark', 'drstrange', 'bartallen'
)

# Build regex to match any exclusion substring
$exclusionRegex = ($exclusionPatterns | ForEach-Object { [regex]::Escape($_) }) -join '|'


# Output file with timestamp
$timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$outCsv = ".\ccdc_password_reset_report_$timestamp.csv"

# Initialize report array and secure password string
$report = @()
$securePw = ConvertTo-SecureString $NewPassword -AsPlainText -Force

# --- Safety Confirmation ---
Write-Host "WARNING: This script will change passwords on ALL enabled accounts NOT matching the exclusion list!" -ForegroundColor Red
$confirm = Read-Host "Type 'CONFIRM' to proceed and begin the interactive password resets (or anything else to abort)"
if ($confirm -ne 'CONFIRM') {
    Write-Host "Aborted by user. No changes made." -ForegroundColor Green
    exit
}

# ------------------------------------
# --- 1. PROCESS SPECIFIC TARGETS ---
# ------------------------------------
Write-Host "`n--- Processing Specific Target Users ---" -ForegroundColor Cyan
foreach ($user in $targetSpecificUsers) {
    # Skip if the target user name matches the exclusion pattern (safety check)
    if ($user -match $exclusionRegex) {
        Write-Host "SKIP -> Target '$user' matches an exclusion pattern. Skipping for safety." -ForegroundColor Red
        continue
    }

    # Attempt to find the user locally first
    $u = $null
    try {
        $u = Get-LocalUser -Name $user -ErrorAction SilentlyContinue
        $environment = 'Local'
    } catch {}

    # If not found locally, attempt to find in Active Directory
    if (-not $u -and (Get-Module -ListAvailable -Name ActiveDirectory)) {
        try {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            $u = Get-ADUser -Identity $user -Properties SamAccountName, Enabled -ErrorAction SilentlyContinue
            $environment = 'Domain'
        } catch {}
    }
    
    if (-not $u) {
        Write-Host "NOTE -> Target '$user' was not found (normal if they aren't on this machine/domain)." -ForegroundColor Yellow
        
        $entry = [PSCustomObject]@{
            Environment = 'N/A'
            AccountName = $user
            Enabled = $false
            Whitelisted = $false
            Action = 'Skipped'
            Result = 'Not Found'
            ErrorMessage = 'User not found locally or in AD.'
        }
        $report += $entry
        continue
    }

    $isEnabled = $u.Enabled -eq $true
    
    $entry = [PSCustomObject]@{
        Environment = $environment
        AccountName = $user
        Enabled = $isEnabled
        Whitelisted = $false
        Action = ''
        Result = ''
        ErrorMessage = ''
    }

    if ($isEnabled) {
        # *** INTERACTIVE CONFIRMATION HERE ***
        $actionConfirm = Read-Host "TARGETED: Change password for $($user) ($($environment))? (y/n)"
        if ($actionConfirm -notmatch "^[yY]") {
            $entry.Action = 'Skipped'
            $entry.Result = 'No Action (User skipped)'
            Write-Host "SKIP (User declined) -> Target: $($user)" -ForegroundColor Gray
            $report += $entry
            continue
        }
        # *** END CONFIRMATION ***

        try {
            if ($environment -eq 'Local') {
                Set-LocalUser -Name $u.Name -Password $securePw -ErrorAction Stop
                $entry.Action = 'Password Changed'
                $entry.Result = 'Success'
            } else { # Domain
                Set-ADAccountPassword -Identity $u.SamAccountName -NewPassword $securePw -Reset -ErrorAction Stop
                Set-ADUser -Identity $u.SamAccountName -ChangePasswordAtLogon $true -PasswordNeverExpires $false -ErrorAction Stop
                $entry.Action = 'Password Changed + Force Next Logon + No Expires'
                $entry.Result = 'Success'
            }
            Write-Host "SUCCESS -> Target: $($user) ($($environment))" -ForegroundColor Green
        } catch {
            $entry.Action = 'Attempted Change'
            $entry.Result = 'Failed'
            $entry.ErrorMessage = $_.Exception.Message
            Write-Warning "FAILED -> Target: $($user) - $($_.Exception.Message)"
        }
    } else {
        $entry.Action = 'Skipped'
        $entry.Result = 'No Action'
        Write-Host "SKIP (Disabled) -> Target: $($user)" -ForegroundColor Gray
    }
    $report += $entry
}


# ------------------------------------
# --- 2. CATCH-ALL FOR REMAINING ---
# ------------------------------------
Write-Host "`n--- Processing Remaining Enabled Accounts (Catch-All) ---" -ForegroundColor Cyan

# Define an array to hold the names of accounts already processed to avoid duplication
$processedNames = $report | Select-Object -ExpandProperty AccountName | Where-Object { $_ -ne 'N/A' } # Exclude N/A entries

# --- Local Accounts Catch-All ---
try {
    $localUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true } -ErrorAction Stop
} catch {
    Write-Warning "Local user catch-all skipped."
    $localUsers = @()
}

foreach ($u in $localUsers) {
    if ($u.Name -match $exclusionRegex) {
        Write-Host "SKIP (Exclusion) -> Local: $($u.Name)" -ForegroundColor Red
        continue
    }
    if ($processedNames -contains $u.Name) {
        # Already processed in the target list
        continue
    }

    $entry = [PSCustomObject]@{
        Environment = 'Local'
        AccountName = $u.Name
        Enabled = $true
        Whitelisted = $false
        Action = ''
        Result = ''
        ErrorMessage = ''
    }
    
    # *** INTERACTIVE CONFIRMATION HERE ***
    $actionConfirm = Read-Host "CATCH-ALL: Change password for $($u.Name) (Local)? (y/n)"
    if ($actionConfirm -notmatch "^[yY]") {
        $entry.Action = 'Skipped'
        $entry.Result = 'No Action (User skipped)'
        Write-Host "SKIP (User declined) -> Local: $($u.Name)" -ForegroundColor Gray
        $report += $entry
        $processedNames += $u.Name # Add to processed list
        continue
    }
    # *** END CONFIRMATION ***

    # Change the password (similar logic as before)
    try {
        Set-LocalUser -Name $u.Name -Password $securePw -ErrorAction Stop
        $entry.Action = 'Password Changed (Catch-All)'
        $entry.Result = 'Success'
        Write-Host "SUCCESS -> Local: $($u.Name) (Catch-All)" -ForegroundColor Green
    } catch {
        $entry.Action = 'Attempted Change (Catch-All)'
        $entry.Result = 'Failed'
        $entry.ErrorMessage = $_.Exception.Message
        Write-Warning "FAILED -> Local: $($u.Name) - $($_.Exception.Message)"
    }
    $report += $entry
    $processedNames += $u.Name # Add to processed list
}

# --- Domain Accounts Catch-All ---
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    try {
        # Ensure AD module is imported for this section
        Import-Module ActiveDirectory -ErrorAction Stop
        
        $adUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties SamAccountName -ErrorAction Stop
        
        foreach ($u in $adUsers) {
            $sam = $u.SamAccountName
            
            if ($sam -match $exclusionRegex) {
                Write-Host "SKIP (Exclusion) -> Domain: $sam" -ForegroundColor Red
                continue
            }
            if ($processedNames -contains $sam) {
                # Already processed in the target list
                continue
            }
            
            $entry = [PSCustomObject]@{
                Environment = 'Domain'
                AccountName = $sam
                Enabled = $true
                Whitelisted = $false
                Action = ''
                Result = ''
                ErrorMessage = ''
            }

            # *** INTERACTIVE CONFIRMATION HERE ***
            $actionConfirm = Read-Host "CATCH-ALL: Change password for $sam (Domain)? (y/n)"
            if ($actionConfirm -notmatch "^[yY]") {
                $entry.Action = 'Skipped'
                $entry.Result = 'No Action (User skipped)'
                Write-Host "SKIP (User declined) -> Domain: $sam" -ForegroundColor Gray
                $report += $entry
                $processedNames += $sam # Add to processed list
                continue
            }
            # *** END CONFIRMATION ***

            # Change the password (similar logic as before)
            try {
                Set-ADAccountPassword -Identity $sam -NewPassword $securePw -Reset -ErrorAction Stop
                Set-ADUser -Identity $sam -ChangePasswordAtLogon $true -PasswordNeverExpires $false -ErrorAction Stop
                $entry.Action = 'Password Changed + Force Next Logon + No Expires (Catch-All)'
                $entry.Result = 'Success'
                Write-Host "SUCCESS -> Domain: $sam (Catch-All)" -ForegroundColor Green
            } catch {
                $entry.Action = 'Attempted Change (Catch-All)'
                $entry.Result = 'Failed'
                $entry.ErrorMessage = $_.Exception.Message
                Write-Warning "FAILED -> Domain: $sam - $($_.Exception.Message)"
            }
            $report += $entry
            $processedNames += $sam # Add to processed list
        }
    } catch {
        Write-Warning "ActiveDirectory catch-all failed: $($_.Exception.Message)"
    }
}


# ------------------------------------
# --- 3. SUMMARY & REPORT ---
# ------------------------------------
$report | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8

$successCount = ($report | Where-Object { $_.Result -eq 'Success' }).Count
$failCount = ($report | Where-Object { $_.Result -eq 'Failed' }).Count
$skipCount = ($report | Where-Object { $_.Result -match 'Skipped|Not Found'}).Count

Write-Host "`n--- Final Summary ---" -ForegroundColor Cyan
Write-Host "Success: $successCount | Failures: $failCount | Skipped/Not Found: $skipCount" -ForegroundColor White
Write-Host "Full report saved to: $outCsv" -ForegroundColor Green
Write-Host "Completed CCDC password reset. Good luck!" -ForegroundColor Yellow
