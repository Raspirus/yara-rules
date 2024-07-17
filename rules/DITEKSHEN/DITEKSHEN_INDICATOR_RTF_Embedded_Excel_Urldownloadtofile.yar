
rule DITEKSHEN_INDICATOR_RTF_Embedded_Excel_Urldownloadtofile : FILE
{
	meta:
		description = "Detects RTF documents that embed Excel documents for detection evation."
		author = "ditekSHen"
		id = "39b8723c-1755-5e2f-8fb2-cca5e9eef915"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_office.yar#L789-L815"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "9416664683c249a9dc2b3d506d9dea7067a638cc4ee5ef7138e5b33a8fcd2b96"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$clsid1 = "2008020000000000c000000000000046" ascii nocase
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii
		$ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
		$ole2 = "d0cf11e0a1b11ae1" ascii nocase
		$ole3 = "64306366313165306131623131616531" ascii
		$ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31"
		$ole5 = { 64 30 63 66 [0-2] 31 31 65 30 61 31 62 31 31 61 65 31 }
		$ole6 = "D0cf11E" ascii nocase
		$s1 = "55524c446f776e6c6f6164546f46696c6541" ascii nocase
		$s2 = "55524c4d4f4e" ascii nocase

	condition:
		uint32(0)==0x74725c7b and (1 of ($clsid*) and 1 of ($obj*) and 1 of ($ole*) and 1 of ($s*))
}