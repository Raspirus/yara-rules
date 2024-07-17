rule ELASTIC_Windows_Generic_Threat_4578Ee8C : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "4578ee8c-9dfc-4fb2-b5dc-8f55b6ee26d0"
		date = "2024-02-14"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2578-L2596"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "699fecdb0bf27994d67492dc480f4ba1320acdd75e5881afbc5f73c982453fed"
		logic_hash = "1a519bb84aae29057536ea09e53ff97cfe34a70c84ac6fa7d1ec173de3754f03"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "3a40e6e8f35c5c114b1b0175723d9403c357bba7170c4350194d40d4a2c94c61"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 73 65 72 2D 41 67 65 6E 74 3A 4D 6F 7A 69 6C 6C 61 2F 34 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4D 53 49 45 20 25 64 2E 30 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 25 64 2E 31 3B 20 53 56 31 29 }

	condition:
		all of them
}