
rule DITEKSHEN_INDICATOR_OLE_Excel4Macros_DL3 : FILE
{
	meta:
		description = "Detects OLE Excel 4 Macros documents acting as downloaders"
		author = "ditekSHen"
		id = "794cac49-e917-5282-8cbd-8ecf91a2dc9e"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_office.yar#L817-L835"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "83eaf60b900119b9fcd458e9e9dda119fd71785821bf282e9385031368ff9891"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$a1 = { 18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 00 }
		$a2 = { 18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 00 }
		$a3 = { 18 00 21 00 20 00 00 01 12 00 00 00 00 00 00 00 00 00 01 3a ff }
		$a4 = { 18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a 00 }
		$a5 = { 18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a 00 }
		$a6 = "auto_open" ascii nocase
		$a7 = "auto_close" ascii nocase
		$s1 = "* #,##0" ascii
		$s2 = "URLMon" ascii
		$s3 = "DownloadToFileA" ascii
		$s4 = "DllRegisterServer" ascii

	condition:
		uint16(0)==0xcfd0 and 1 of ($a*) and all of ($s*) and #s1>3
}