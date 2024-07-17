
rule ELASTIC_Windows_Hacktool_Leigod_89397Ebf : FILE
{
	meta:
		description = "Detects Windows Hacktool Leigod (Windows.Hacktool.LeiGod)"
		author = "Elastic Security"
		id = "89397ebf-2fdb-4607-85a1-b9c378b4e256"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_LeiGod.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ae5cc99f3c61c86c7624b064fd188262e0160645c1676d231516bf4e716a22d3"
		logic_hash = "e887c34c624a182a3c57a55abe02784c4350d3956bcfd9f7918f08a464819e63"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "04709d703cd0a062029a05baee160eb9579fe0503984f3059ce49e1bcfa6e963"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\Device\\CtrlLeiGod" wide fullword

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}