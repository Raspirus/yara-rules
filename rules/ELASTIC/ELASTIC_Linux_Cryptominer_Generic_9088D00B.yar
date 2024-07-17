
rule ELASTIC_Linux_Cryptominer_Generic_9088D00B : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "9088d00b-622a-4cbf-9600-6dfcf2fc0c2c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L181-L199"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8abb2b058ec475b0b6fd0c994685db72e98d87ee3eec58e29cf5c324672df04a"
		logic_hash = "3ebc8cb6d647138e72194528dafc644c90222440855d657ec50109f11ff936da"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "85cbe86b9f96fc1b6899b35cc4aa16b66a91dc1239ed5f5cf3609322cec30f30"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 2C 1C 77 16 48 8B 44 24 08 64 48 33 04 25 28 00 00 00 75 24 48 83 }

	condition:
		all of them
}