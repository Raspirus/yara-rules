
rule ELASTIC_Windows_Generic_Threat_5E718A0C : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "5e718a0c-3c46-46f7-adfd-b0c3c75b865f"
		date = "2024-01-03"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L530-L548"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "430b9369b779208bd3976bd2adc3e63d3f71e5edfea30490e6e93040c1b3bac6"
		logic_hash = "45068afeda7abae0fe922a21f8f768b6c74a6e0f8e9e8b1f68c3ddf92940bf9a"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "b6f9b85f4438c3097b430495dee6ceef1a88bd5cece823656d9dd325e8d9d4a1"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 44 3A 28 41 3B 3B 30 78 30 30 31 46 30 30 30 33 3B 3B 3B 42 41 29 28 41 3B 3B 30 78 30 30 31 30 30 30 30 33 3B 3B 3B 41 55 29 }

	condition:
		all of them
}