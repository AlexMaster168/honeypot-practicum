# Lab mode: Kali loses its NAT uplink so it can only talk to the honeynet.
# Without it Kali reaches the management network through the Windows host
# (NAT -> host -> host-only), arriving as 192.168.56.1 and indistinguishable from the admin.
#
#   .\scripts\lab-mode.ps1 on    # attack from 10.66.0.50 only
#   .\scripts\lab-mode.ps1 off   # give Kali internet back (updates, tools)
param(
    [Parameter(Mandatory)][ValidateSet("on", "off", "status")][string]$Mode,
    [string]$KaliVm = "kali-linux-2025.4-virtualbox-amd64",
    [int]$NatNic = 1
)
$ErrorActionPreference = "Stop"
$vbox = Join-Path $env:ProgramFiles "Oracle\VirtualBox\VBoxManage.exe"

$info = & $vbox showvminfo $KaliVm --machinereadable
$running = ($info | Select-String '^VMState="running"') -ne $null

if ($Mode -ne "status") {
    $state = if ($Mode -eq "on") { "off" } else { "on" }
    if ($running) {
        & $vbox controlvm $KaliVm "setlinkstate$NatNic" $state
    } else {
        & $vbox modifyvm $KaliVm "--cableconnected$NatNic" $state
    }
    if ($LASTEXITCODE -ne 0) { throw "VBoxManage failed" }
    $info = & $vbox showvminfo $KaliVm --machinereadable
}

$cable = ($info | Select-String "^cableconnected$NatNic=""(.+)""").Matches[0].Groups[1].Value
$lab = if ($cable -eq "off") { "ON (Kali isolated to honeynet)" } else { "OFF (Kali has NAT uplink)" }
"lab mode: $lab"
