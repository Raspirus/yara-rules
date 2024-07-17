
rule ELASTIC_Windows_Hacktool_Physmem_B3Fa382B : FILE
{
	meta:
		description = "Detects Windows Hacktool Physmem (Windows.Hacktool.PhysMem)"
		author = "Elastic Security"
		id = "b3fa382b-48a5-4004-92ad-bba0d42243ad"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_PhysMem.yar#L22-L40"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "88df37ede18bea511f1782c1a6c4915690b29591cf2c1bf5f52201fbbb4fa2b9"
		logic_hash = "36a60b78de15a52721ad4830b37daffc33d7689e8b180fe148876da00562273a"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "81285d1d8bdb575cb3ebf7f2df2555544e3f1342917e207def00c358a77cd620"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\Phymemx64.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}