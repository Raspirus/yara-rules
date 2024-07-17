
rule ELASTIC_Windows_Generic_Threat_B509Dfc8 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "b509dfc8-6ec3-4315-a1ec-61e6b65793e7"
		date = "2024-01-29"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2252-L2270"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9b5124e5e1be30d3f2ad1020bbdb93e2ceeada4c4d36f71b2abbd728bd5292b8"
		logic_hash = "90b00caf612f56a898b24c28ae6febda3fd11f382ab1deba522bdd2e2ba254b4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "bb1e607fe0d84f25c9bd09d31614310e204dce17c4050be6ce7dc6ed9dfd8f92"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 28 00 00 0A 6F 29 00 00 0A 6F 2A 00 00 0A 13 04 11 04 28 22 00 00 0A 28 2B 00 00 0A 2D 0D 11 04 28 22 00 00 0A 28 2C 00 00 0A 26 06 28 2D 00 00 0A 2C 0F 06 73 28 00 00 0A 13 05 11 05 6F 2E 00 }

	condition:
		all of them
}