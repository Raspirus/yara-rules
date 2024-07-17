
rule ELASTIC_Windows_Ransomware_Doppelpaymer_6Ab188Da : BETA FILE MEMORY
{
	meta:
		description = "Identifies DOPPELPAYMER ransomware"
		author = "Elastic Security"
		id = "6ab188da-4e73-4669-816c-554b2f04ee65"
		date = "2020-06-28"
		modified = "2021-08-23"
		reference = "https://www.crowdstrike.com/blog/doppelpaymer-ransomware-and-dridex-2/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Doppelpaymer.yar#L23-L42"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "429c87d293b7f517a594e8be020cbe7f8302a8b6eb8337f090ca18973aafbde4"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "6c33e09e66b337064a1feae5c162f72dc5f6caecaa9829e4ad9fffb10ef3e576"
		threat_name = "Windows.Ransomware.Doppelpaymer"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$d1 = { 56 55 55 55 F7 EF B8 56 55 55 55 8B EA F7 E9 8B C2 8B D1 C1 FA 1F 2B C2 C1 FF 1F 2B EF 8D 14 40 B8 F3 1A CA 6B 2B CA 03 E9 F7 ED 8B CD C1 FA 05 C1 F9 1F 2B D1 6B CA B4 03 CD 74 1C 81 E1 03 00 00 80 7D 07 83 E9 01 83 C9 FC 41 8B C1 F7 D8 85 C9 8D 7C 05 04 0F 45 EF 8D 44 55 02 5D 5F C3 }

	condition:
		1 of ($d*)
}