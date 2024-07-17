
rule ELASTIC_Windows_Generic_Threat_48Cbdc20 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "48cbdc20-386a-491e-8407-f7c4c348f2e9"
		date = "2024-03-04"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2881-L2900"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7a7704c64e64d3a1f76fc718d5b5a5e3d46beeeb62f0493f22e50865ddf66594"
		logic_hash = "687d0f3dc85a7e4b23019deec59ee77c211101d40ed6622a952e69ebc4151483"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "98db38ebd05e99171489828491e6acfc7c4322283b325ed99429f366b0ee01a6"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 5E 69 69 69 4E 42 42 42 3E 2E 2E 2E 25 }
		$a2 = { 24 2E 2E 2E 2F 41 41 41 3A 51 51 51 47 5D 5D 5D 54 69 69 69 62 }

	condition:
		all of them
}