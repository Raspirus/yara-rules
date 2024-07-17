rule ELASTIC_Windows_Generic_Threat_0E8530F5 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "0e8530f5-32ce-48a2-9413-5a8f4596ba12"
		date = "2024-02-14"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2537-L2556"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9f44d9acf79ed4450195223a9da185c0b0e8a8ea661d365a3ddea38f2732e2b8"
		logic_hash = "f4a010366625c059151d3e704f6ece1808f367401729feaf6cc423cf4d5c5c60"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "33007c3793c74aaac45434cbd0b524973073a7223d68fae8da5cbd7296120739"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 63 6D 64 20 2F 63 20 73 74 61 72 74 20 22 22 20 22 25 53 25 53 22 20 25 53 }
		$a2 = { 76 68 61 50 20 71 20 65 71 30 75 61 }

	condition:
		all of them
}