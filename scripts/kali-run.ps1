# Copies a script (and optional extra files) into Kali and runs it there via guest additions.
# Avoids passing shell code through PowerShell 5.1 argument quoting, which mangles it.
#   .\scripts\kali-run.ps1 attacker\stage2-smoke.sh -Extra attacker\wordlists -Sudo
param(
    [Parameter(Mandatory)][string]$Script,
    [string[]]$Extra = @(),
    [switch]$Sudo,
    [string]$KaliVm = "kali-linux-2025.4-virtualbox-amd64",
    [string]$User = "kali",
    [string]$Password = "kali",
    [string]$Dest = "/tmp/mirage"
)
$ErrorActionPreference = "Stop"
$vbox = Join-Path $env:ProgramFiles "Oracle\VirtualBox\VBoxManage.exe"
$auth = @("--username", $User, "--password", $Password)

& $vbox guestcontrol $KaliVm mkdir @auth --parents $Dest
foreach ($f in @($Script) + $Extra) {
    $item = Get-Item $f
    if ($item.PSIsContainer) {
        & $vbox guestcontrol $KaliVm copyto @auth --recursive --target-directory "$Dest/" $item.FullName
    } else {
        & $vbox guestcontrol $KaliVm copyto @auth --target-directory "$Dest/" $item.FullName
    }
}
$name = Split-Path $Script -Leaf
$cmd = if ($Sudo) { "echo $Password | sudo -S -p '' bash $Dest/$name" } else { "bash $Dest/$name" }
& $vbox guestcontrol $KaliVm run @auth --exe /bin/bash --wait-stdout --wait-stderr -- -c $cmd
exit $LASTEXITCODE
