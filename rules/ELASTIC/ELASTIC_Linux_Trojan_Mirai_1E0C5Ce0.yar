rule ELASTIC_Linux_Trojan_Mirai_1E0C5Ce0 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "1e0c5ce0-3b76-4da4-8bed-2e5036b6ce79"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L120-L138"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5b1f95840caebf9721bf318126be27085ec08cf7881ec64a884211a934351c2d"
		logic_hash = "591cc3ef6932bf990f56c932866b34778e8eccd0e343f9bd6126eb8205a12ecc"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8e45538b59f9c9b8bc49661069044900c8199e487714c715c1b1f970fd528e3b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 4C 24 54 31 F6 41 B8 04 00 00 00 BA 03 00 00 00 C7 44 24 54 01 00 }

	condition:
		all of them
}