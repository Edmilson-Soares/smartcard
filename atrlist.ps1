# Baixa a base de ATRs do pcsc-tools (Ludovic Rousseau, GPL-2.0) para data/.
# Use com scard.loadAtrList("data/smartcard_list.txt").
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force "$PSScriptRoot\data" | Out-Null
Invoke-WebRequest "https://pcsc-tools.apdu.fr/smartcard_list.txt" -OutFile "$PSScriptRoot\data\smartcard_list.txt"
Write-Host "data\smartcard_list.txt atualizado"
