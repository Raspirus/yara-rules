
rule ELASTIC_Windows_Generic_Threat_2507C37C : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "2507c37c-a0ef-47e0-a02a-3e28f4655715"
		date = "2023-12-18"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L62-L80"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "04296258f054a958f0fd013b3c6a3435280b28e9a27541463e6fc9afe30363cc"
		logic_hash = "8c5ea1290260993ea5140baa4645f3fd0ebb4d43fce0e9a25f8e8948e683aec1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b20b76f19d21730b6e32d1468f0e14ee9d6f9f07b9692fb6dec76605d9b967e2"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 8B 45 14 56 57 33 FF 3B C7 74 47 39 7D 08 75 1B E8 B2 2B 00 00 6A 16 5E 89 30 57 57 57 57 57 E8 3B 2B 00 00 83 C4 14 8B C6 EB 29 39 7D 10 74 E0 39 45 0C 73 0E E8 8D 2B 00 00 6A 22 59 }

	condition:
		all of them
}