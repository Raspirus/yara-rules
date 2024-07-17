import "pe"


rule DITEKSHEN_INDICATOR_TOOL_Scmaldevinj_Go : FILE
{
	meta:
		description = "Detects Go shell/malware dev injector"
		author = "ditekShen"
		id = "56ec114f-8e16-5ab6-ae3b-a182cb381b4a"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1847-L1857"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "48c3c759283c63a0c439cfba0194da89f402189e4c3cd831c22b5078ccae47b1"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "hooka/shellcode.go" ascii
		$s2 = "/maldev\x09v" ascii
		$s3 = "Binject/debug/pe." ascii

	condition:
		uint16(0)==0x5a4d and all of them
}