
rule ELASTIC_Windows_Generic_Threat_51A1D82B : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "51a1d82b-2ae0-45c9-b51d-9b54454dfcee"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1280-L1298"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1a7adde856991fa25fac79048461102fba58cda9492d4f5203b817d767a81018"
		logic_hash = "2d6b0560e1980deb6aad8e0902d065eeda406506b70bb8bb27c7fa58be9842f8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fddf98cdb00734e50908161d6715e807b1c4437789af524d6f0a17df55572261"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 EC 04 53 56 57 89 4D FC 8B 45 FC 50 FF 15 D0 63 41 00 5F 5E 5B C9 C3 CC CC CC CC CC 66 8B 01 56 66 8B 32 57 66 3B F0 72 44 75 0A 66 8B 79 02 66 39 7A 02 72 38 66 3B F0 75 14 66 8B }

	condition:
		all of them
}