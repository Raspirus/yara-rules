
rule ELASTIC_Linux_Hacktool_Flooder_7D5355Da : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "7d5355da-5fbd-46c0-8bd2-33a27cbcca63"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "03397525f90c8c2242058d2f6afc81ceab199c5abcab8fd460fabb6b083d8d20"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L500-L518"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "b4540f941ca1a36c460d056ef263ebd67c6388f3f6f373f50371f7cca2739bc4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "52882595f28e1778ee3b0e6bda94319f5c348523f16566833281f19912360270"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 E5 48 83 EC 60 64 48 8B 04 25 28 00 00 00 48 89 45 F8 31 C0 BF 0A 00 }

	condition:
		all of them
}