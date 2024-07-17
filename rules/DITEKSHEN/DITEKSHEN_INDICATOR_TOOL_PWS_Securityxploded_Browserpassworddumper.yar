rule DITEKSHEN_INDICATOR_TOOL_PWS_Securityxploded_Browserpassworddumper : FILE
{
	meta:
		description = "Detects SecurityXploded Browser Password Dumper tool"
		author = "ditekSHen"
		id = "ce90ef96-43c0-5d68-ba7d-21aafb3f754b"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L726-L737"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "b3c6e9b393c244c7bf6489f54ebd622a09da050a65d6dbde325d5bcd7d85f39a"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "\\projects\\windows\\BrowserPasswordDump\\Release\\FireMaster.pdb" ascii
		$s2 = "%s: Dumping passwords" fullword ascii
		$s3 = "%s - Found login data file...dumping the passwords from file %s" fullword ascii
		$s4 = "%s Dumping secrets from login json file %s" fullword ascii

	condition:
		uint16(0)==0x5a4d and 3 of them
}