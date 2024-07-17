rule ELASTIC_Windows_Generic_Threat_Dee3B4Bf : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "dee3b4bf-f09e-46a7-b177-6b1445db88ad"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1300-L1318"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c7f4b63fa5c7386d6444c0d0428a8fe328446efcef5fda93821f05e86efd2fba"
		logic_hash = "cfd7f9250ab44ffe12b62f84ae753032642d9aa2524d88a6d4d989a2afa043a3"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "6f6cf93e5ac640d1e71f9554752a846c3cc051d95c232e2f4d8fa383d5a3b5af"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 4A 75 73 74 20 63 6F 70 79 20 74 68 65 20 70 61 74 63 68 20 74 6F 20 74 68 65 20 70 72 6F 67 72 61 6D 20 64 69 72 65 63 74 6F 72 79 20 61 6E 64 20 61 70 70 6C 79 2E }

	condition:
		all of them
}