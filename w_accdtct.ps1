<#
.SYNOPSIS
    CCDC Account Whitelist Checker and Disabler
.DESCRIPTION
    Detects local and domain user accounts not in the predefined whitelist.
    Prompts for confirmation (y/n) before disabling unauthorized enabled accounts.
    Logs all actions to a timestamped TXT file.
    Run as Administrator. For domain checks, requires ActiveDirectory module (RSAT).
.NOTES
    Whitelist based on provided references:
    - Domain: fathertime, chronos, aion, kairos
    - Local: merlin, terminator, mrpeabody, jamescole, docbrown, professorparadox, drwho, martymcFly, arthurdent, sambeckett, loki, riphunter, theflash, tonystark, drstrange, barta, len
    Built-in accounts (Administrator, Guest, etc.) are automatically skipped.
#>

# Require Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run as Administrator!"
    Exit
}

# Detect which machine we're on
$hostname = $env:COMPUTERNAME
$logFile = "C:\CCDC_AccountCheck_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Whitelist (combined from references, case-insensitive)
$whitelist = @{
    "Domain" = @("fathertime", "chronos", "aion", "kairos", "datadog", "dd-dog", "whiteteam", "blackteam")
    "Local" = @("merlin", "terminator", "mrpeabody", "jamescole", "docbrown", "professorparadox", "drwho", "martymcFly", "arthurdent", "sambeckett", "loki", "riphunter", "theflash", "tonystark", "drstrange", "barta", "len", "datadog", "dd-dog", "whiteteam", "blackteam")
}
$allWhitelist = ($whitelist["Domain"] + $whitelist["Local"]) | ForEach-Object { $_.ToLower() }

# Built-in accounts to skip
$builtInAccounts = @("administrator", "guest", "defaultaccount", "wdagutilityaccount", "krbtgt")

function Log-Action {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    Write-Host $logEntry
    Add-Content -Path $logFile -Value $logEntry
}

Log-Action "STARTING CCDC ACCOUNT CHECK ON $hostname"

function Check-And-Disable-LocalUsers {
    Log-Action "CHECKING LOCAL USERS"
    
    # Get all enabled local users
    $allLocalUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    
    # Find unauthorized users
    $unauthorizedLocal = @()
    foreach ($user in $allLocalUsers) {
        $userNameLower = $user.Name.ToLower()
        if ($allWhitelist -notcontains $userNameLower -and $builtInAccounts -notcontains $userNameLower) {
            $unauthorizedLocal += $user
        }
    }
    
    if ($unauthorizedLocal.Count -gt 0) {
        Write-Host "`nUNAUTHORIZED LOCAL USERS DETECTED:" -ForegroundColor Red
        foreach ($user in $unauthorizedLocal) {
            Write-Host "- $($user.Name)" -ForegroundColor Red
        }
        Write-Host "`nWhitelist (Local + Domain):" -ForegroundColor Cyan
        $whitelist["Local"] | ForEach-Object { Write-Host "- $_" -ForegroundColor Green }
        $whitelist["Domain"] | ForEach-Object { Write-Host "- $_ (Domain)" -ForegroundColor Green }
        
        foreach ($user in $unauthorizedLocal) {
            Write-Host "`nLocal User: $($user.Name) (Enabled)" -ForegroundColor Yellow
            $choice = Read-Host "Disable this user? (y/n)"
            if ($choice -eq "y" -or $choice -eq "Y") {
                try {
                    Disable-LocalUser -Name $user.Name
                    Log-Action "DISABLED local user: $($user.Name)"
                    Write-Host "DISABLED: $($user.Name)" -ForegroundColor Green
                } catch {
                    Log-Action "FAILED to disable local user $($user.Name): $_"
                    Write-Host "FAILED to disable: $($user.Name)" -ForegroundColor Red
                }
            } else {
                Log-Action "SKIPPED disabling local user: $($user.Name) (user chose n)"
                Write-Host "SKIPPED: $($user.Name)" -ForegroundColor Yellow
            }
        }
    } else {
        Log-Action "No unauthorized local users detected"
        Write-Host "No unauthorized local users found!" -ForegroundColor Green
    }
}

function Check-And-Disable-DomainUsers {
    param($AuthorizedDomainUsers)
    
    Log-Action "CHECKING DOMAIN USERS"
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        
        # Get all enabled domain users (exclude service accounts)
        $allDomainUsers = Get-ADUser -Filter {Enabled -eq $true -and SamAccountName -notlike '*$'} | Select-Object -ExpandProperty SamAccountName
        
        # Find unauthorized users
        $unauthorizedDomain = @()
        foreach ($user in $allDomainUsers) {
            $userLower = $user.ToLower()
            if ($allWhitelist -notcontains $userLower -and $builtInAccounts -notcontains $userLower) {
                $unauthorizedDomain += $user
            }
        }
        
        if ($unauthorizedDomain.Count -gt 0) {
            Write-Host "`nUNAUTHORIZED DOMAIN USERS DETECTED:" -ForegroundColor Red
            foreach ($user in $unauthorizedDomain) {
                Write-Host "- $user" -ForegroundColor Red
            }
            Write-Host "`nWhitelist (Local + Domain):" -ForegroundColor Cyan
            $whitelist["Local"] | ForEach-Object { Write-Host "- $_" -ForegroundColor Green }
            $whitelist["Domain"] | ForEach-Object { Write-Host "- $_ (Domain)" -ForegroundColor Green }
            
            foreach ($user in $unauthorizedDomain) {
                Write-Host "`nDomain User: $user (Enabled)" -ForegroundColor Yellow
                $choice = Read-Host "Disable this user? (y/n)"
                if ($choice -eq "y" -or $choice -eq "Y") {
                    try {
                        Disable-ADAccount -Identity $user
                        Log-Action "DISABLED domain user: $user"
                        Write-Host "DISABLED: $user" -ForegroundColor Green
                    } catch {
                        Log-Action "FAILED to disable domain user $user : $_"
                        Write-Host "FAILED to disable: $user" -ForegroundColor Red
                    }
                } else {
                    Log-Action "SKIPPED disabling domain user: $user (user chose n)"
                    Write-Host "SKIPPED: $user" -ForegroundColor Yellow
                }
            }
        } else {
            Log-Action "No unauthorized domain users detected"
            Write-Host "No unauthorized domain users found!" -ForegroundColor Green
        }
    } catch {
        Log-Action "FAILED to check domain users: $_ (AD module may be missing)"
        Write-Host "Could not check domain users: $_" -ForegroundColor Red
    }
}

# Run local check always
Check-And-Disable-LocalUsers

# Check if Domain Controller
$isDC = Get-Service -Name "NTDS" -ErrorAction SilentlyContinue
if ($isDC -and $isDC.Status -eq "Running") {
    Write-Host "`nDOMAIN CONTROLLER DETECTED" -ForegroundColor Yellow
    $checkDomain = Read-Host "Check and disable domain users? (y/n)"
    if ($checkDomain -eq "y" -or $checkDomain -eq "Y") {
        Check-And-Disable-DomainUsers -AuthorizedDomainUsers $whitelist["Domain"]
    } else {
        Log-Action "Skipped domain user check per user choice"
    }
} else {
    # Even if not DC, try domain check if AD module available
    $haveAD = $false
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $haveAD = $true
    } catch {
        # Module not available
    }
    if ($haveAD) {
        $checkDomain = Read-Host "AD module available. Check and disable domain users? (y/n)"
        if ($checkDomain -eq "y" -or $checkDomain -eq "Y") {
            Check-And-Disable-DomainUsers -AuthorizedDomainUsers $whitelist["Domain"]
        } else {
            Log-Action "Skipped domain user check per user choice"
        }
    }
}

Log-Action "CCDC ACCOUNT CHECK COMPLETED!"
Log-Action "Log file saved to: $logFile"
Write-Host "`nLog file saved to: $logFile" -ForegroundColor Green
