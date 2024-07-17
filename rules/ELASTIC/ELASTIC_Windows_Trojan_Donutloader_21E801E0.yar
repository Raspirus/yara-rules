rule ELASTIC_Windows_Trojan_Donutloader_21E801E0 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Donutloader (Windows.Trojan.Donutloader)"
		author = "Elastic Security"
		id = "21e801e0-b016-48b2-81f5-930e7d3dd318"
		date = "2024-01-21"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Donutloader.yar#L40-L58"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c3bda62725bb1047d203575bbe033f0f95d4dd6402c05f9d0c69d24bd3224ca6"
		logic_hash = "19ef7bc8c7117024ca72956376954254c36eeb673f9379aa00475f763084a169"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8b971734d471f281e7c48177096359e8f43578a12e42f6203f55d5e79d9ed09d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 48 89 45 F0 48 8B 45 F0 48 81 C4 D0 00 00 00 5D C3 55 48 81 EC 60 02 00 00 48 8D AC 24 80 00 00 00 48 89 8D F0 01 00 00 48 89 95 F8 01 00 00 4C 89 85 00 02 00 00 4C 89 8D 08 02 00 00 48 C7 85 }

	condition:
		all of them
}