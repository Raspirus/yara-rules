
rule ELASTIC_Linux_Cryptominer_Malxmr_Da08E491 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Malxmr (Linux.Cryptominer.Malxmr)"
		author = "Elastic Security"
		id = "da08e491-c6fa-4228-8b6a-8adae2f0324a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Malxmr.yar#L300-L318"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4638d9ece32cd1385121146378772d487666548066aecd7e40c3ba5231f54cc0"
		logic_hash = "f98252c33f8d76981bbc51de87a11a7edca7292a864fc2a305d29cd21961729e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c4911fdeece4c3f97bbc9ef4da478c5f5363ab71a70b0767edec0f94b87fd939"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F9 48 31 CD 48 89 F9 48 F7 D1 4C 21 F9 48 21 DA 49 31 CA 48 }

	condition:
		all of them
}