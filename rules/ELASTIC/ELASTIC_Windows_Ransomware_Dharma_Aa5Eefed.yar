
rule ELASTIC_Windows_Ransomware_Dharma_Aa5Eefed : BETA FILE MEMORY
{
	meta:
		description = "Identifies DHARMA ransomware"
		author = "Elastic Security"
		id = "aa5eefed-7212-42c9-b51d-2c58c65b53e5"
		date = "2020-06-25"
		modified = "2021-08-23"
		reference = "https://blog.malwarebytes.com/threat-analysis/2019/05/threat-spotlight-crysis-aka-dharma-ransomware-causing-a-crisis-for-businesses/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Dharma.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "bbafc2eac17562f315b09fa42eb601d0140152917d7962429df3a378abe67732"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "d3baf3474b450931b594322d190b243bdd813156ad80f04abcadde0db3bfe149"
		threat_name = "Windows.Ransomware.Dharma"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$c1 = { 4D F0 51 8B 55 E8 52 E8 CD 10 00 00 83 C4 08 89 45 E8 8A 45 F9 04 01 88 45 F9 0F B6 4D F9 8B 55 E4 8A 04 0A 88 45 FB 0F B6 4D FB 0F B6 55 FA 03 D1 88 55 FA 0F B6 45 FA 8B 4D E4 8A 14 01 88 55 EF 0F B6 45 F9 8B 4D E4 8A 55 EF 88 14 01 0F B6 45 FA 8B 4D E4 8A 55 FB 88 14 01 8B 45 0C 03 45 F4 0F B6 08 0F B6 55 FB 0F B6 45 EF 03 D0 0F B6 D2 8B 45 E4 0F B6 14 10 33 CA 8B 45 E8 03 45 F4 88 08 }
		$c2 = { 21 0C 7D 01 02 04 08 10 20 40 80 1B 36 6C D8 AB 4D 9A 2F 5E BC 63 C6 97 35 6A D4 B3 7D FA EF C5 91 00 00 A5 63 63 C6 84 7C 7C F8 99 77 77 EE 8D 7B 7B F6 0D F2 F2 FF BD 6B 6B D6 B1 6F 6F DE 54 C5 C5 91 50 30 30 60 03 01 01 02 A9 67 67 CE 7D 2B 2B 56 }

	condition:
		1 of ($c*)
}