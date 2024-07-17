
rule ELASTIC_Windows_Generic_Threat_1F2E969C : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "1f2e969c-5d90-4bab-a06a-9cccb1946251"
		date = "2024-06-05"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3525-L3543"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7def75df729ed66511fbe91eadf15bc69a03618e78c48e27c35497db2a6a97ae"
		logic_hash = "7d984a902f9bf40c9b49da89aba9249f80b41b24ca1cdb6189f541b40ef41742"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e7c872f2422fe54367900d69c9bb94d86db2bf001cbbe00ba6c801fb3d1e610e"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 51 53 8B 5A 10 56 8B F1 57 6A 78 89 75 FC C7 46 10 00 00 00 00 C7 46 14 0F 00 00 00 53 89 75 FC C6 06 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 33 C0 89 7D FC 85 DB 7E 39 0F 1F 40 00 }

	condition:
		all of them
}