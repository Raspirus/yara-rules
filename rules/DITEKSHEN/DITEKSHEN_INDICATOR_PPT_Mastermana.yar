
rule DITEKSHEN_INDICATOR_PPT_Mastermana : FILE
{
	meta:
		description = "Detects known malicious pattern (MasterMana) in PowerPoint documents."
		author = "ditekSHen"
		id = "8e9b8185-6211-54c6-946d-b16f2226312a"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_office.yar#L695-L715"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "f8169e63b22fbbd48de9a63ff228d9d9fb105e95d2ea8a37c0993493515e8b2e"
		score = 75
		quality = 71
		tags = "FILE"

	strings:
		$a1 = "auto_close" ascii nocase
		$a2 = "autoclose" ascii nocase
		$a3 = "auto_open" ascii nocase
		$a4 = "autoopen" ascii nocase
		$vb1 = "\\VBE7.DLL" ascii
		$vb2 = { 41 74 74 72 69 62 75 74 ?? 65 20 56 42 5f 4e 61 6d ?? 65 }
		$clsid = "000204EF-0000-0000-C000-000000000046" wide nocase
		$i1 = "@j.mp/" ascii wide
		$i2 = "j.mp/" ascii wide
		$i3 = "\\pm.j\\\\:" ascii wide
		$i4 = ".zz.ht/" ascii wide
		$i5 = "/pm.j@" ascii wide
		$i6 = "\\pm.j@" ascii wide

	condition:
		uint16(0)==0xcfd0 and 1 of ($i*) and $clsid and 1 of ($a*) and 1 of ($vb*)
}