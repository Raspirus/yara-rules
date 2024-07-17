import "pe"


rule DITEKSHEN_INDICATOR_TOOL_SCN_Portscan : FILE
{
	meta:
		description = "Detects a port scanner tool observed as second or third stage post-compromise or dropped by malware."
		author = "ditekSHen"
		id = "f270e098-17a0-5d66-acd0-c946a29919f4"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L166-L180"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "ebe5eb045a250ca38a55ac43018548074e9db160d76737c36f8ae5ea268b7b10"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "HEAD / HTTP/1.0" fullword ascii
		$s2 = "Result.txt" fullword ascii
		$s3 = "Example: %s SYN " ascii
		$s4 = "Performing Time: %d/%d/%d %d:%d:%d -->" fullword ascii
		$s5 = "Bind On IP: %d.%d.%d.%d" fullword ascii
		$s6 = "SYN Scan: About To Scan %" ascii
		$s7 = "Normal Scan: About To Scan %" ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}