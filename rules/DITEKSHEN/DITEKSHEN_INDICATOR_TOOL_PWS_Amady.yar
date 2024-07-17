rule DITEKSHEN_INDICATOR_TOOL_PWS_Amady : FILE
{
	meta:
		description = "Detects password stealer DLL. Dropped by Amadey"
		author = "ditekSHen"
		id = "6ee4e25b-bf38-5664-a08f-94e3fa92aa29"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L291-L306"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "409374bec5f58abeb7741b41f0fc7ea1c3fdc7bbc3f0c0628db0e3aac82836d1"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\AppData" fullword ascii
		$s2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" ascii
		$s3 = "\\Mikrotik\\Winbox\\Addresses.cdb" fullword ascii
		$s4 = "\\HostName" fullword ascii
		$s5 = "\\Password" fullword ascii
		$s6 = "SOFTWARE\\RealVNC\\" ascii
		$s7 = "SOFTWARE\\TightVNC\\" ascii
		$s8 = "cred.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 7 of them
}