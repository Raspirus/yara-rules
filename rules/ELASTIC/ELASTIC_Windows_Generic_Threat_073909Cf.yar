
rule ELASTIC_Windows_Generic_Threat_073909Cf : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "073909cf-7e0d-48fa-a631-e1b641040570"
		date = "2024-01-10"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L914-L932"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "89a6dc518c119b39252889632bd18d9dfdae687f7621310fb14b684d2f85dad8"
		logic_hash = "5b42a74010549c884ff85a67b9add6b82a8109a953473cc1439581976f8f545e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "717da3b409c002ff6c6428690faf6e6018daedfaf9ec95b6fb9884cacc27dc20"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 C4 F0 53 56 89 55 FC 8B F0 8B 45 FC E8 CF E5 FF FF 33 C0 55 68 F2 39 40 00 64 FF 30 64 89 20 33 DB 68 04 3A 40 00 68 0C 3A 40 00 E8 70 FC FF FF 50 E8 82 FC FF FF 89 45 F8 68 18 3A }

	condition:
		all of them
}