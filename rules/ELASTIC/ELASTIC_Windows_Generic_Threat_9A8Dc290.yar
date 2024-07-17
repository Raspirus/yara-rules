rule ELASTIC_Windows_Generic_Threat_9A8Dc290 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "9a8dc290-d9ec-4d52-a4e8-db4ac6ceb164"
		date = "2024-01-21"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1951-L1969"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d951562a841f3706005d7696052d45397e3b4296d4cd96bf187920175fbb1676"
		logic_hash = "0097a13187b953ebe97809dda2be818cfcd94991c03e75f344e34a3d2c4fe902"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e9f42a0fdd778b8619633cce87c9d6a3d26243702cdd8a56e524bf48cf759094"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 6F 01 00 06 FE 0E 0B 00 FE 0C 0B 00 FE 0C 09 00 6F 78 01 00 06 FE 0C 0B 00 FE 0C 08 00 28 F2 00 00 06 6F 74 01 00 06 FE 0C 0B 00 FE 0C 07 00 28 F2 00 00 06 6F 76 01 00 06 FE 0C 0B 00 FE 09 00 }

	condition:
		all of them
}