
rule ELASTIC_Linux_Cryptominer_Xmrminer_D625Fcd2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrminer (Linux.Cryptominer.Xmrminer)"
		author = "Elastic Security"
		id = "d625fcd2-2951-4ecf-91cd-d58e16c33c65"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrminer.yar#L120-L137"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "b95b66392e1a07e0b6acd718a9501cede76e57561e69701e9e881bd3fbd3fe39"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "08c8d00e38fbf62cbf0aa329d6293fba302c3c76aee8c33341260329c14a58aa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 20 00 00 40 00 0C C0 5C 02 60 01 02 03 12 00 40 04 50 09 00 }

	condition:
		all of them
}