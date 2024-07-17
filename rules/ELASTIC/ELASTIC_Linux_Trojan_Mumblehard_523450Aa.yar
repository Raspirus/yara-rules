rule ELASTIC_Linux_Trojan_Mumblehard_523450Aa : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mumblehard (Linux.Trojan.Mumblehard)"
		author = "Elastic Security"
		id = "523450aa-6bb4-4863-9656-81a6e6cb7d88"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mumblehard.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a637ea8f070e1edf2c9c81450e83934c177696171b24b4dff32dfb23cefa56d3"
		logic_hash = "60b4cc388975ce030e03c5c3a48adcfeec25299105206909163f20100fbf45d8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "783f07e4f4625c061309af2d89e9ece0ba4a8ce21a7d93ce19cd32bcd6ad38e9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 09 75 05 89 03 89 53 04 B8 02 00 00 00 50 80 F9 09 75 0B CD 80 }

	condition:
		all of them
}