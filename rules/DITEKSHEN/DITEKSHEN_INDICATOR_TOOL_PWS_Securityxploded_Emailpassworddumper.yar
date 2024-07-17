import "pe"


rule DITEKSHEN_INDICATOR_TOOL_PWS_Securityxploded_Emailpassworddumper : FILE
{
	meta:
		description = "Detects SecurityXploded Email Password Dumper tool"
		author = "ditekSHen"
		id = "25e140de-4a0a-5d4f-a93f-a414b9879f2b"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L752-L764"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "7f07611385d45bf45bfb8ee95e56febfb992fb7b416321c5b590878636a5c1b7"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "\\projects\\windows\\EmailPasswordDump\\Release\\FireMaster.pdb" ascii
		$s2 = "//Dump all the Email passwords to a file \"c:\\passlist.txt\"" ascii
		$s3 = "EmailPasswordDump" fullword wide
		$s4 = "//Dump all the Email passwords to console" ascii
		$s5 = "Email Password Dump" fullword wide

	condition:
		uint16(0)==0x5a4d and 3 of them
}