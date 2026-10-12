# Plugs Kali's spare NIC into the isolated "honeynet" internal network.
# Kali must be powered off. Inside Kali then run: sudo attacker/setup-net.sh
param(
    [string]$KaliVm = "kali-linux-2025.4-virtualbox-amd64",
    [int]$Nic = 2
)
$ErrorActionPreference = "Stop"
$vbox = Join-Path $env:ProgramFiles "Oracle\VirtualBox\VBoxManage.exe"

$info = & $vbox showvminfo $KaliVm --machinereadable
if ($LASTEXITCODE -ne 0) { throw "VM '$KaliVm' not found" }
$state = ($info | Select-String '^VMState="(.+)"').Matches[0].Groups[1].Value
if ($state -notin "poweroff", "aborted", "saved") { throw "Power off '$KaliVm' first (state: $state)" }

& $vbox modifyvm $KaliVm "--nic$Nic" intnet "--intnet$Nic" honeynet "--nicpromisc$Nic" deny "--cableconnected$Nic" on
if ($LASTEXITCODE -ne 0) { throw "modifyvm failed" }

& $vbox showvminfo $KaliVm --machinereadable | Select-String "^(nic$Nic|intnet$Nic)="
