
rule ELASTIC_Windows_Trojan_Wikiloader_C57F3F88 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Wikiloader (Windows.Trojan.WikiLoader)"
		author = "Elastic Security"
		id = "c57f3f88-0d2c-41a6-b2f9-839b1f1e1193"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_WikiLoader.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0f71b1805d7feb6830b856c5a5328d3a132af4c37fcd747d82beb0f61c77f6f5"
		logic_hash = "408c6d811232dbd0c87f75fd28508366151cf9f2f10f012919588db1919e406b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a3802da23431fcbc890a5164d6acdbf29ec29bf1a82d4b862495edd8ae642d52"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 48 81 EC 08 01 00 00 48 89 CB 48 31 C0 48 89 E9 48 29 E1 48 89 E7 F3 AA 48 89 D9 48 89 4D 80 48 89 95 78 FF FF FF 4C 89 45 C0 4C 89 4D 88 4D 89 D4 4D 89 DD 4C 89 65 C8 49 83 ED 10 4C 89 6D 98 }

	condition:
		all of them
}