rule ELASTIC_Windows_Generic_Threat_Aa30A738 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "aa30a738-616b-408c-960f-c0ea897145d0"
		date = "2024-01-21"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1931-L1949"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7726a691bd6c1ee51a9682e0087403a2c5a798ad172c1402acf2209c34092d18"
		logic_hash = "64967fbc0e74435452752731a8b9385345cc771d27ee33cd018cccdeb26bb75e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d2a4e1d4451d28afcef981f689de3212ff5d9c4ee8840864656082ef272f7501"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 8B 55 0C 85 D2 75 04 33 C0 5D C3 8B 45 08 53 56 8B 75 10 83 FE 08 57 F7 D0 B9 FF 00 00 00 0F 8C D1 00 00 00 8B FE C1 EF 03 8B DF F7 DB 8D 34 DE 89 75 10 0F B6 1A 8B F0 23 F1 33 F3 8B }

	condition:
		all of them
}