rule ELASTIC_Windows_Generic_Threat_1636C2Bf : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "1636c2bf-5506-4651-9c4c-cd6454386301"
		date = "2024-03-04"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2820-L2838"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6e43916db43d8217214bbe4eb32ed3d82d0ac423cffc91d053a317a3dbe6dafb"
		logic_hash = "c8b198cd5f9277ff3808ee2a313ab979d544b9e609d6623876d2e3c3c5668e38"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b0cd9f484d4191d42091300be33c72a29c073c297b4e46811555fc6d1ab0f482"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 28 00 00 0A 28 22 00 00 0A 80 19 00 00 04 28 3B 00 00 06 28 2D 00 00 0A 28 45 00 00 06 16 80 1D 00 00 04 7E 13 00 00 04 7E 15 00 00 04 16 7E 15 00 00 04 8E B7 16 14 FE 06 43 00 00 06 73 63 00 }

	condition:
		all of them
}