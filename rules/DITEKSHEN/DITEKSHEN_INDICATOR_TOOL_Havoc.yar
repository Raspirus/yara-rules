rule DITEKSHEN_INDICATOR_TOOL_Havoc : FILE
{
	meta:
		description = "Detects Havoc Demon"
		author = "ditekSHen"
		id = "71ad145c-4017-597a-837e-5d11ba64d7c0"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1757-L1774"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "c5806deaa57590ebe1923608b9b085460e0edd024721e6e9d7073765a79bf22b"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$x1 = "X-Havoc:" wide
		$x2 = "X-Havoc-Agent:" wide
		$s1 = "\\Werfault.exe" wide
		$s2 = "/funny_cat.gif" wide

	condition:
		uint16(0)==0x5a4d and ( all of ($x*) or 3 of them or (pe.number_of_imports==0 and pe.number_of_exports==0 and 2 of them ))
}