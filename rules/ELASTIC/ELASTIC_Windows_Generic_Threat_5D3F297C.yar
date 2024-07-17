rule ELASTIC_Windows_Generic_Threat_5D3F297C : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "5d3f297c-b812-401a-8671-2e00369cd6f2"
		date = "2024-03-05"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3264-L3282"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "885c8cd8f7ad93f0fd43ba4fb7f14d94dfdee3d223715da34a6e2fbb4d25b9f4"
		logic_hash = "556d3bc9374a5ec23faa410900dfc94b5534434c9733165355d281976444a42b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ff90bfcb28bb3164fb11da5f35f289af679805f7e4047e48d97ae89e5b820dcd"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 EC 08 C7 45 F8 00 00 00 00 83 7D 08 00 74 4A 83 7D 0C 00 74 44 8B 45 0C 83 C0 01 50 6A 40 ?? ?? ?? ?? ?? ?? 89 45 F8 83 7D F8 00 74 2C C7 45 FC 00 00 00 00 EB 09 8B 4D FC 83 C1 01 }

	condition:
		all of them
}