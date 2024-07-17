rule DITEKSHEN_INDICATOR_RTF_Embedded_Excel_Sheetmacroenabled : FILE
{
	meta:
		description = "Detects RTF documents embedding an Excel sheet with macros enabled. Observed in exploit followed by dropper behavior"
		author = "ditekSHen"
		id = "342d10b3-61d2-5fcb-8f4f-1fe45049257b"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_office.yar#L284-L308"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "cc3b52e549c2697c6e0a2fea365d193311d90d26854bd2fe321aa26c118975a0"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$ex1 = "457863656c2e53686565744d6163726f456e61626c65642e" ascii nocase
		$ex2 = "0002083200000000c000000000000046" ascii nocase
		$ex3 = "Excel.SheetMacroEnabled." ascii
		$ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
		$ole2 = "d0cf11e0a1b11ae1" ascii nocase
		$ole3 = "64306366313165306131623131616531" ascii
		$ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31"
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii
		$obj7 = "\\mmath" ascii

	condition:
		uint32(0)==0x74725c7b and (1 of ($ex*) and 1 of ($ole*) and 2 of ($obj*))
}