rule ELASTIC_Windows_Generic_Threat_8D10790B : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "8d10790b-6f26-46bf-826e-1371565763f0"
		date = "2023-12-18"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L182-L200"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "911535923a5451c10239e20e7130d371e8ee37172e0f14fc8cf224d41f7f4c0f"
		logic_hash = "84c017abbce1c8702efbe8657e5a857ae222721b0db2260dc814652f4528df26"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7cc33c6684318373e45f5e7440f0a416dd5833a56bc31eb8198a3c36b15dd25e"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 81 EC 04 00 00 00 8B 5D 08 8B 1B 83 C3 04 89 5D FC 8B 45 0C 8B 5D FC 89 03 8B E5 5D C2 08 00 55 8B EC 81 EC 0C 00 00 00 C7 45 FC 00 00 00 00 68 00 00 00 00 BB C4 02 00 00 E8 0D 05 00 }

	condition:
		all of them
}