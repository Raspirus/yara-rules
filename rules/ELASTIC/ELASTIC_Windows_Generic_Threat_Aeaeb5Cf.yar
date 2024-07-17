rule ELASTIC_Windows_Generic_Threat_Aeaeb5Cf : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "aeaeb5cf-2683-4a88-b736-4b8873d92fc5"
		date = "2024-05-22"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3404-L3422"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f57d955d485904f0c729acff9db1de9cb42f32af993393d58538f07fa273b431"
		logic_hash = "640966296bad70234e0fe7b6f87b92fcf4fc111189d307d44f32e926785f76cb"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f6d32006747b083632f551c8ca182b6b4d67a8f130a118e61b0dd2f35d7d8477"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 8B 4D 08 33 C0 66 39 01 74 0B 8D 49 00 40 66 83 3C 41 00 75 F8 8D 04 45 02 00 00 00 50 FF 75 0C 51 ?? ?? ?? ?? ?? 83 C4 0C 5D C3 CC CC 55 8B EC 6A 00 FF 75 08 }

	condition:
		all of them
}