rule ELASTIC_Windows_Ransomware_Darkside_Aceac5D9 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Darkside (Windows.Ransomware.Darkside)"
		author = "Elastic Security"
		id = "aceac5d9-fb38-4dca-ab1f-44ee40005d37"
		date = "2021-05-20"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Darkside.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bfb31c96f9e6285f5bb60433f2e45898b8a7183a2591157dc1d766be16c29893"
		logic_hash = "888ab06b55b07879ee6b9a45c04f1a09c570aeb4be55c698300566d57fd47252"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "521b0f574b27151ad03fc7693fd692e1a13e81a28e39d04d3f7ea149a0da59b9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 41 54 55 53 48 83 EC 28 48 8B 1F 4C 8B 66 08 48 8D 7C 24 10 4C }

	condition:
		any of them
}