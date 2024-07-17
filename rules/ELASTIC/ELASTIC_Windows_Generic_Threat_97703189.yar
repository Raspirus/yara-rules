rule ELASTIC_Windows_Generic_Threat_97703189 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "97703189-bcac-4b6c-b0d4-9167f5e8085d"
		date = "2024-01-04"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L589-L607"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "968ba3112c54f3437b9abb6137f633d919d75137d790af074df40a346891cfb5"
		logic_hash = "318bc82d49e9a3467ec0e0086aaf1092d2aa7c589b5f16ce6fbb3778eda7ef0b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9126c3aeaa4ed136424c20aa8e7a487131adc1ae22eb8ab4f514b4687855816f"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 5D E9 2A 1C 00 00 8B FF 55 8B EC 8B 45 08 56 8B F1 C6 46 0C 00 85 C0 75 63 E8 6F 29 00 00 89 46 08 8B 48 6C 89 0E 8B 48 68 89 4E 04 8B 0E 3B 0D 98 06 49 00 74 12 8B 0D B4 05 49 00 85 }

	condition:
		all of them
}