
rule ELASTIC_Windows_Trojan_Matanbuchus_58A61Aaa : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Matanbuchus (Windows.Trojan.Matanbuchus)"
		author = "Elastic Security"
		id = "58a61aaa-51b2-47f2-ab32-2e639957b2d5"
		date = "2022-03-17"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Matanbuchus.yar#L44-L62"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4eb85a5532b98cbc4a6db1697cf46b9e2b7e28e89d6bbfc137b36c0736cd80e2"
		logic_hash = "7226e2f61bd6f1cca15c1f3f8d8697cb277d1e214f756295ffda5bc16304cc49"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "332794db0ed7488e939a91594d2100ee013a7f8f91afc085e15f06fc69098ad5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 83 EC 08 53 56 0F 57 C0 66 0F 13 45 F8 EB ?? 8B 45 F8 83 C0 01 8B 4D FC 83 D1 00 89 45 F8 89 4D FC 8B 55 FC 3B 55 }

	condition:
		all of them
}