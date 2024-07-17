
rule ELASTIC_Windows_Generic_Threat_54B0Ec47 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "54b0ec47-79f3-4187-8253-805e7ad102ce"
		date = "2024-01-03"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L489-L508"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9c14203069ff6003e7f408bed71e75394de7a6c1451266c59c5639360bf5718c"
		logic_hash = "e3d74162a8874fe05042fec98d25b8db50e7f537566fd9f4e40f92bfe868259a"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "2c3890010aad3c2b54cba08a62b5af6a678849a6b823627bf9e26c8693a89c60"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 2D 2D 2D 2D 3D 5F 25 73 5F 25 2E 33 75 5F 25 2E 34 75 5F 25 2E 38 58 2E 25 2E 38 58 }
		$a2 = { 25 73 2C 20 25 75 20 25 73 20 25 75 20 25 2E 32 75 3A 25 2E 32 75 3A 25 2E 32 75 20 25 63 25 2E 32 75 25 2E 32 75 }

	condition:
		all of them
}