
rule ELASTIC_Linux_Trojan_Rbot_366F1599 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Rbot (Linux.Trojan.Rbot)"
		author = "Elastic Security"
		id = "366f1599-a287-44e6-bc2c-d835b2c2c024"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Rbot.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5553d154a0e02e7f97415299eeae78e5bb0ecfbf5454e3933d6fd9675d78b3eb"
		logic_hash = "3efe0f35efd855b415149513e8abb2210a26ef6f3b6c31275c8147fabb634fab"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "27166c9dab20d40c10a4f0ea5d0084be63fef48748395dd55c7a13ab6468e16d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C0 64 03 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B }

	condition:
		all of them
}