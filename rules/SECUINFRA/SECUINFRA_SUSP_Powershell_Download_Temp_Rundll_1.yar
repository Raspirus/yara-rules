rule SECUINFRA_SUSP_Powershell_Download_Temp_Rundll_1 : POWERSHELL DOWNLOAD FILE
{
	meta:
		description = "Detect a Download to %temp% and execution with rundll32.exe"
		author = "SECUINFRA Falcon Team"
		id = "6b09a6f0-29c6-5baf-ae64-7aa49a37a9d3"
		date = "2022-09-02"
		modified = "2022-02-27"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Filetypes/powershell.yar#L1-L17"
		license_url = "N/A"
		logic_hash = "4d7860dc94614b10bc0eea0189ad9b964399d4ee6404ebeaef40720c716c592d"
		score = 65
		quality = 70
		tags = "POWERSHELL, DOWNLOAD, FILE"

	strings:
		$location = "$Env:temp" nocase
		$download = "downloadfile(" nocase
		$rundll = "rundll32.exe"

	condition:
		filesize <100KB and $location and $download and $rundll
}