rule DITEKSHEN_INDICATOR_OLE_Excel4Macros_DL2 : FILE
{
	meta:
		description = "Detects OLE Excel 4 Macros documents acting as downloaders"
		author = "ditekSHen"
		id = "ea331976-6e5d-5377-a100-0f265e97177f"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_office.yar#L766-L787"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "48ab27a2f81934f6f2f034ebcd40fc083b0d90850d12a951f03dab3a4c396ec6"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$e1 = "Macros Excel 4.0" ascii
		$e2 = { 00 4d 61 63 72 6f 31 85 00 }
		$a1 = { 18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 00 }
		$a2 = { 18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 00 }
		$a3 = { 18 00 21 00 20 00 00 01 12 00 00 00 00 00 00 00 00 00 01 3a ff }
		$a4 = { 18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a 00 }
		$a5 = { 18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a 00 }
		$a6 = "auto_open" ascii nocase
		$a7 = "auto_close" ascii nocase
		$x1 = "* #,##0" ascii
		$x2 = "=EXEC(CHAR(" ascii
		$x3 = "-w 1 stARt`-s" ascii nocase
		$x4 = ")&CHAR(" ascii
		$x5 = "Reverse" fullword ascii

	condition:
		uint16(0)==0xcfd0 and (1 of ($e*) and 1 of ($a*) and (#x1>3 or 2 of ($x*)))
}