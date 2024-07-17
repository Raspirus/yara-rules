rule ELASTIC_Windows_Rootkit_R77_Be403E3C : FILE MEMORY
{
	meta:
		description = "Detects Windows Rootkit R77 (Windows.Rootkit.R77)"
		author = "Elastic Security"
		id = "be403e3c-a70d-4126-b464-83060138c79b"
		date = "2023-05-18"
		modified = "2023-06-13"
		reference = "https://www.elastic.co/security-labs/elastic-security-labs-steps-through-the-r77-rootkit"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Rootkit_R77.yar#L66-L85"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "91c6e2621121a6871af091c52fafe41220ae12d6e47e52fd13a7b9edd8e31796"
		logic_hash = "efbf924c7a299f2543c639b6262007eb3bdbf6ff5e33dab7d6102814b9477811"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "46fd9d53771a0c6d14b364589a7cfa291a1c0405d74a97beac75db78faea7e0b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 33 C9 48 89 8C 24 C0 00 00 00 4C 8B CB 48 89 8C 24 B8 00 00 00 45 33 C0 48 89 8C 24 B0 00 00 00 48 89 8C 24 A8 00 00 00 89 8C 24 A0 00 00 00 }

	condition:
		$a
}