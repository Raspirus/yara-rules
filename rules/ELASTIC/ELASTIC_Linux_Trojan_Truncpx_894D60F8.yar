
rule ELASTIC_Linux_Trojan_Truncpx_894D60F8 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Truncpx (Linux.Trojan.Truncpx)"
		author = "Elastic Security"
		id = "894d60f8-bea6-4b09-b8ab-526308575a01"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Truncpx.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2f09f2884fd5d3f5193bfc392656005bce6b935c12b3049ac8eb96862e4645ba"
		logic_hash = "9bc0a7fbddac532b53c72681f349bca0370b1fe6fb2d16f539560085b3ec4be3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "440ce5902642aeef56b6989df4462d01faadc479f1362c0ed90d1011e8737bc3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { B9 51 FE 88 63 A1 08 08 09 C5 1A FF D3 AB B2 28 }

	condition:
		all of them
}