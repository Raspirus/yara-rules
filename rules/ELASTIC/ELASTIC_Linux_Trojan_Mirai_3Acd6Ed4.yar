rule ELASTIC_Linux_Trojan_Mirai_3Acd6Ed4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "3acd6ed4-6d62-47af-8d80-d5465abce38a"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1922-L1940"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2644447de8befa1b4fe39b2117d49754718a2f230d6d5f977166386aa88e7b84"
		logic_hash = "ab284d41af8e1920fa54ac8bfab84bac493adf816aebce60490ab22c0e502201"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e787989c37c26d4bb79c235150a08bbf3c4c963e2bc000f9a243a09bbf1f59cb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E5 7E 44 4C 89 E3 31 FF 48 C1 E3 05 48 03 5D 38 48 89 2B 44 88 }

	condition:
		all of them
}