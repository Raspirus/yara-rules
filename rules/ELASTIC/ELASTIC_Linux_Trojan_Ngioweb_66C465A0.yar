rule ELASTIC_Linux_Trojan_Ngioweb_66C465A0 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ngioweb (Linux.Trojan.Ngioweb)"
		author = "Elastic Security"
		id = "66c465a0-821d-43ea-82f5-fe787720bfbf"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ngioweb.yar#L81-L99"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7454ee074812d7fa49044de8190e17b5034b3f08625f547d1b04aae4054fd81a"
		logic_hash = "71f224e3ee1ff29787258a61f29a37a9ddc51e9cb5df0693ea52fd4b6f0b5ad8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e26071afff71506236b261a44e8f1903d348dd33b95597458649f377710492f4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 75 E6 B2 07 FE C0 EB DE 83 EC 10 6A 00 6A 00 6A 00 6A 00 FF 74 }

	condition:
		all of them
}