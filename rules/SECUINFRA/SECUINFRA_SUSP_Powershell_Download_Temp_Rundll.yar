rule SECUINFRA_SUSP_Powershell_Download_Temp_Rundll : POWERSHELL DOWNLOAD
{
	meta:
		description = "Detect a Download to %temp% and execution with rundll32.exe"
		author = "SECUINFRA Falcon Team"
		id = "f7a9d2e6-bebf-598b-9e59-db0a3001b9f9"
		date = "2022-09-02"
		modified = "2022-02-19"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/PowerShell_Misc/download_variations.yar#L1-L14"
		license_url = "N/A"
		logic_hash = "7982438c032127349fb1c3477a23bab1c92eb68d9c3b26e2f5fb0a8c332dbc44"
		score = 65
		quality = 70
		tags = "POWERSHELL, DOWNLOAD"

	strings:
		$location = "$Env:temp" nocase
		$download = "downloadfile(" nocase
		$rundll = "rundll32.exe"

	condition:
		$location and $download and $rundll
}