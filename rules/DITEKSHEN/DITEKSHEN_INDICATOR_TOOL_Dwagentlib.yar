import "pe"


rule DITEKSHEN_INDICATOR_TOOL_Dwagentlib : FILE
{
	meta:
		description = "Detect DWAgent Remote Administration Tool library"
		author = "ditekSHen"
		id = "af0f9940-fbec-5775-9b74-bd73b55ec0ca"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1525-L1539"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "608dd9bc8cfcec5a671bee9456dccedace31d7ae37180387ac2408f79fd9f452"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "DWAgentLib" fullword wide
		$s2 = "PYTHONHOME" fullword wide
		$s3 = "isTaskRunning" fullword ascii
		$s4 = "isUserInAdminGroup" fullword ascii
		$s5 = "setFilePermissionEveryone" fullword ascii
		$s6 = "startProcessInActiveConsole" fullword ascii
		$s7 = "taskKill" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}