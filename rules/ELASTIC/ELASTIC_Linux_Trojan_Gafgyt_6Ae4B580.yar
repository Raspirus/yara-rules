rule ELASTIC_Linux_Trojan_Gafgyt_6Ae4B580 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "6ae4b580-f7cf-4318-b584-7ea15f10f5ea"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1247-L1265"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "eb0fe44df1c995c5d4e3a361c3e466f78cb70bffbc76d1b7b345ee651b313b9e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "279e344d6da518980631e70d7b1ded4ff1b034d24e4b4fe01b36ed62f5c1176c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 30 0B E5 3C 20 1B E5 6C 32 1B E5 03 00 52 E1 01 00 00 DA 6C }

	condition:
		all of them
}