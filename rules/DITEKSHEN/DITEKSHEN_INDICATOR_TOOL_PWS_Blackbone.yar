import "pe"


rule DITEKSHEN_INDICATOR_TOOL_PWS_Blackbone : FILE
{
	meta:
		description = "detects Blackbone password dumping tool on Windows 7-10 operating system."
		author = "ditekSHen"
		id = "a6d9f9d1-75fb-51af-87ad-80b4e135e759"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L112-L129"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "e9dacd28accaef8a93ff8d3b5cf9437b3848791711a4a7118ab46d2bb6ca42d3"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "BlackBone: %s: " ascii
		$s2 = "\\BlackBoneDrv\\" ascii
		$s3 = "\\DosDevices\\BlackBone" fullword wide
		$s4 = "\\Temp\\BBImage.manifest" wide
		$s5 = "\\Device\\BlackBone" fullword wide
		$s6 = "BBExecuteInNewThread" fullword ascii
		$s7 = "BBHideVAD" fullword ascii
		$s8 = "BBInjectDll" fullword ascii
		$s9 = "ntoskrnl.exe" fullword ascii
		$s10 = "WDKTestCert Ton," ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}