
rule ELASTIC_Windows_Generic_Threat_23D33B48 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "23d33b48-00f6-487f-a3e5-f41603fc982e"
		date = "2024-06-05"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3485-L3503"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "acbc22df07888498ae6f52f5458e3fb8e0682e443a8c2bc97177a0320b4e2098"
		logic_hash = "c9fb93bb74e4d45197d0da5b641860738a42a583b15cc098e86ea79bb8690bf7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7a25301a1297337810240e8880febe525726c9b79a4a4bd81b1f856865097995"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 51 83 7A 14 10 8B C2 53 56 57 8B F1 72 02 8B 02 83 7E 14 10 72 02 8B 0E 8B 5A 10 8D 56 10 8B 3A 53 50 89 55 FC 8B D7 51 ?? ?? ?? ?? ?? 8B D0 83 C4 0C 83 FA FF 74 30 3B FA 72 33 8B C7 }

	condition:
		all of them
}