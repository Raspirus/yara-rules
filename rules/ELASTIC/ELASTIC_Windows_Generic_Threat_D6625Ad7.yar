rule ELASTIC_Windows_Generic_Threat_D6625Ad7 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "d6625ad7-7f2c-4445-a5f2-a9444425f3a4"
		date = "2024-01-29"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2192-L2210"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "878c9745320593573597d62c8f3adb3bef0b554cd51b18216f6d9f5d1a32a931"
		logic_hash = "e90aff7c35f60cc3446f9eeb2131edb7125bfa04eb8f90c5671d06e9ff269755"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "0e1bb99e22b53e6bb6350f95caaac592ddcad7695e72e298c7ab1d29d1dd4c1f"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 2E 3F 41 56 3C 6C 61 6D 62 64 61 5F 31 3E 40 3F 4C 40 3F 3F 6F 6E 5F 65 76 65 6E 74 5F 61 64 64 40 43 6F 6D 70 6F 6E 65 6E 74 5F 4B 65 79 6C 6F 67 65 72 40 40 45 41 45 58 49 40 5A 40 }

	condition:
		all of them
}