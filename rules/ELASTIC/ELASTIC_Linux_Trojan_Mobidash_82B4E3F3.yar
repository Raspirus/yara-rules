
rule ELASTIC_Linux_Trojan_Mobidash_82B4E3F3 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mobidash (Linux.Trojan.Mobidash)"
		author = "Elastic Security"
		id = "82b4e3f3-a9ba-477c-8eef-6010767be52f"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mobidash.yar#L61-L78"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "8c91f85bc807605a3233d28a5eb8b6e1cf847fb288cbc4427e86226eed7a2055"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a01f5ba8b3e8e82ff46cb748fd90a103009318a25f8532fb014722c96f0392db"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 C6 74 2E 89 44 24 0C 8B 44 24 24 C7 44 24 08 01 00 00 00 89 7C }

	condition:
		all of them
}