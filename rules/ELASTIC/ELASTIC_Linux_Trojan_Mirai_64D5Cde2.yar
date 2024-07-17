
rule ELASTIC_Linux_Trojan_Mirai_64D5Cde2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "64d5cde2-e4b1-425b-8af3-314a5bf519a9"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1164-L1182"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "caf2a8c199156db2f39dbb0a303db56040f615c4410e074ef56be2662752ca9d"
		logic_hash = "08f3635e5517185cae936b39f503bbeba5aed2e36abdd805170a259bc5e3644f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1a69f91b096816973ce0c2e775bcf2a54734fa8fbbe6ea1ffcf634ce2be41767"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 0F 35 7E B3 02 00 D0 02 00 00 07 01 00 00 0E 00 00 00 18 03 00 }

	condition:
		all of them
}