rule DITEKSHEN_INDICATOR_TOOL_Gogoprocdump : FILE
{
	meta:
		description = "Detects GoGo (lsass) process dump tool"
		author = "ditekSHen"
		id = "f92845c6-f8ae-50d0-97ea-cfa72051c2de"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1637-L1650"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "f410882e4c6c8b65e7d3c192cf94bf99d61cf54dc21d80cdf17193b34752c576"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "C:\\temp" ascii
		$s2 = "gogo" fullword ascii
		$s3 = "/DumpLsass-master/SilentProcessExit/" ascii
		$s4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zone" ascii
		$s5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe" ascii
		$s6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\lsass.exe" ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}