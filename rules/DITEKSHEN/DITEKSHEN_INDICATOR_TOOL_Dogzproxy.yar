import "pe"


rule DITEKSHEN_INDICATOR_TOOL_Dogzproxy : FILE
{
	meta:
		description = "Detects Dogz proxy tool"
		author = "ditekSHen"
		id = "de2a8d26-0e8e-5999-baca-1e43933af866"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1589-L1601"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "575cfed9cb7979216fd8fd2a05efe5dfece3a9120b4f185c015918337829ed63"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "LOGONSERVER=" fullword wide
		$s2 = "DOGZ_E_" ascii
		$s3 = "got handshake_id=%d" ascii
		$s4 = "responser send connect ack" ascii
		$s5 = "dogz " ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}