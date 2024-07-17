rule ELASTIC_Windows_Generic_Threat_C54Ed0Ed : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "c54ed0ed-9c63-437c-a016-d960bbb83c40"
		date = "2024-01-21"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1730-L1747"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "f0f4878cb003371522ed1419984f15fd5049f1adeb8e051b8b51b31b0d620e96"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1e08706e235d6cf23d9c772e1b67463b3e6261a5155d88762472d892079df0d4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 81 FA 00 10 00 00 72 1C 48 83 C2 27 4C 8B 41 F8 49 2B C8 48 8D 41 F8 48 83 F8 1F 0F 87 92 00 00 00 49 8B C8 ?? ?? ?? ?? ?? 48 83 63 10 00 33 C0 EB 58 4D 8B CC 4D 8B C7 49 8B D6 48 8B CE FF D0 }

	condition:
		all of them
}