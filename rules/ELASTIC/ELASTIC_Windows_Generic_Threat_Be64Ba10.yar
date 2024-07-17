
rule ELASTIC_Windows_Generic_Threat_Be64Ba10 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "be64ba10-ea9d-45df-8c9b-2facc825b652"
		date = "2024-03-04"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3063-L3082"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "24bb4fc117aa57fd170e878263973a392d094c94d3a5f651fad7528d5d73b58a"
		logic_hash = "c6acce53610baf119a0e2d55fc698a976463bbd21b739d4ac39a75383fa5fed2"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "9496099988cf4f854bf7f70bae158c6e17025a7537245c5f1d92a90f6b9bca67"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 22 65 6E 63 72 79 70 74 65 64 5F 6B 65 79 22 3A 22 28 2E 2B 3F 29 22 }
		$a2 = { 2E 3F 41 56 3C 6C 61 6D 62 64 61 5F 37 65 66 38 63 66 32 36 39 61 32 32 38 62 36 30 34 64 36 35 34 33 32 65 37 65 63 33 37 30 31 34 3E 40 40 }

	condition:
		all of them
}