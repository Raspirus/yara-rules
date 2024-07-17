
rule ELASTIC_Windows_Trojan_Solarmarker_08Bfc26B : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Solarmarker (Windows.Trojan.SolarMarker)"
		author = "Elastic Security"
		id = "08bfc26b-efda-49b4-b685-57edca8b9d18"
		date = "2024-05-29"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_SolarMarker.yar#L22-L42"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c1a6d2d78cc50f080f1fe4cadc6043027bf201d194f2b73625ce3664433a3966"
		logic_hash = "b31b9f8460b606426c1101eba39a41a75c7ecaafc62388a6a5ac0f24057561ed"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9c0c4a5bce63c9d99d53813f7250b3ccc395cb99eaebb8c016f8c040fbfa4ea7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 07 09 91 61 D2 9C 09 20 C8 00 00 00 5D 16 FE 01 16 FE 01 13 }
		$a2 = { 91 07 08 91 61 D2 9C 08 20 C8 00 00 00 5D 16 FE 01 16 FE 01 }
		$a3 = { 06 08 06 08 91 07 08 91 61 D2 9C 08 20 C8 00 00 00 5D 16 FE }

	condition:
		any of them
}