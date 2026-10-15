# One-shot: rebuild the Mirage lab and run the full attack + e2e check.
# Run AFTER disabling VBS/Memory Integrity and rebooting (VirtualBox needs real AMD-V).
#   .\scripts\rebuild-and-verify.ps1
# Steps: guard VBS off -> vagrant up (provision) -> attach Kali to honeynet ->
#        setup-net -> lab-mode on -> attacker/run-all.sh -> lab-mode off -> e2e check.
param(
    [string]$KaliVm = "kali-linux-2025.4-virtualbox-amd64",
    [switch]$SkipVagrantUp
)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$vbox = Join-Path $env:ProgramFiles "Oracle\VirtualBox\VBoxManage.exe"
function Step($m){ Write-Host "`n=== $m ===" -ForegroundColor Cyan }

# 0. Guard: the hypervisor must be gone or VirtualBox falls back to slow NEM and the guest never boots.
Step "guard: VBS must be off"
$dg = Get-CimInstance Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
$vbs = $dg.VirtualizationBasedSecurityStatus
Write-Host "VBS status = $vbs (want 0)"
if ($vbs -ne 0) {
    throw "VBS still on ($vbs). Disable Memory Integrity + 'bcdedit /set hypervisorlaunchtype off' and REBOOT first."
}

# 1. Build + provision the honeypot VM.
if (-not $SkipVagrantUp) {
    Step "vagrant up (boot + ansible provision, ~10-15 min)"
    Push-Location $root
    try { & vagrant up; if ($LASTEXITCODE -ne 0) { throw "vagrant up failed ($LASTEXITCODE)" } }
    finally { Pop-Location }
}

# 2. Plug Kali into the isolated honeynet (Kali must be powered off for modifyvm).
Step "attach Kali to honeynet"
$state = (& $vbox showvminfo $KaliVm --machinereadable | Select-String '^VMState="(.+)"').Matches[0].Groups[1].Value
if ($state -eq "running") {
    throw "Shut down '$KaliVm' normally before running this script."
}
& "$PSScriptRoot\vbox-kali-attach.ps1" -KaliVm $KaliVm
if ($LASTEXITCODE -ne 0) { throw "Attaching Kali failed ($LASTEXITCODE)" }

# 3. Boot Kali headless and wait for guest additions to answer.
Step "start Kali (headless) and wait for guest control"
& $vbox startvm $KaliVm --type headless | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Starting Kali failed ($LASTEXITCODE)" }
$deadline = (Get-Date).AddMinutes(4)
do {
    Start-Sleep -Seconds 6
    & $vbox guestcontrol $KaliVm --username kali --password kali run --exe /bin/true --wait-stdout 2>$null
    $ready = ($LASTEXITCODE -eq 0)
} until ($ready -or (Get-Date) -gt $deadline)
if (-not $ready) { throw "Kali guest control not ready after 4 min" }

# 4. Configure the honeynet NIC inside Kali (static 10.66.0.50, no gateway).
Step "setup-net inside Kali"
& "$PSScriptRoot\kali-run.ps1" -Script "$root\attacker\setup-net.sh" -KaliVm $KaliVm -Sudo
if ($LASTEXITCODE -ne 0) { throw "Kali network setup failed ($LASTEXITCODE)" }

# 5. Cut Kali's NAT so the attack really originates from 10.66.0.50.
Step "lab-mode ON"
& "$PSScriptRoot\lab-mode.ps1" on -KaliVm $KaliVm

# 6. Run the full kill chain. nmap -sS needs root, so -Sudo.
Step "attacker/run-all.sh"
try {
    & "$PSScriptRoot\kali-run.ps1" -Script "$root\attacker\run-all.sh" -KaliVm $KaliVm -Sudo
    if ($LASTEXITCODE -ne 0) { throw "Attack scenario failed ($LASTEXITCODE)" }
} finally {
    # 7. Always restore Kali's uplink, even if the attack script errored.
    Step "lab-mode OFF"
    & "$PSScriptRoot\lab-mode.ps1" off -KaliVm $KaliVm
}

# 8. Verify the campaign on the VM (correlator API + Elasticsearch).
Step "e2e check (on mirage)"
Push-Location $root
try {
    & vagrant ssh -c "sudo python3 /vagrant/tests/e2e/check_campaign.py"
    if ($LASTEXITCODE -ne 0) { throw "Campaign verification failed ($LASTEXITCODE)" }
}
finally { Pop-Location }

Write-Host "`nDONE. If the line above says PASS, the lab is fully verified end-to-end." -ForegroundColor Green
