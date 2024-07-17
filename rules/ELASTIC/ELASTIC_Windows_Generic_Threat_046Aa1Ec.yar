rule ELASTIC_Windows_Generic_Threat_046Aa1Ec : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "046aa1ec-5134-4a03-85c2-048b5d363484"
		date = "2024-02-20"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2640-L2658"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c74cf499fb9298d43a6e64930addb1f8a8d8336c796b9bc02ffc260684ec60a2"
		logic_hash = "da6552da3db4851806f5a0ce3c324a79acf4ee4b2690cb02cc8d8c88a2ba28f8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "46591671500f83b6627a17368a0bbe43650da1dd58ba1a136a47818fe685bc68"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 C4 F4 D9 7D FE 66 8B 45 FE 80 CC 0C 66 89 45 FC D9 6D FC DF 7D F4 D9 6D FE 8B 45 F4 8B 55 F8 8B E5 5D C3 55 8B EC 51 33 D2 8D 5D 08 8B 03 83 C3 04 85 C0 74 03 03 50 04 49 75 F1 85 }

	condition:
		all of them
}