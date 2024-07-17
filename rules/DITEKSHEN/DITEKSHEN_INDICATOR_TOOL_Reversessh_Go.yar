import "pe"


rule DITEKSHEN_INDICATOR_TOOL_Reversessh_Go : FILE
{
	meta:
		description = "Detects golang reverse ssh tool"
		author = "ditekShen"
		id = "4fb671aa-ad42-5f7e-bd5a-c19f018088c9"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1859-L1868"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "4f9899aacc09c7da05fb5d412cfe8e91ee0d8e922189a6f921410d73ae8b3a9c"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "/reverse_ssh/" ascii
		$s2 = "main.rsshService" ascii

	condition:
		uint16(0)==0x5a4d and all of them
}