rule ELASTIC_Windows_Generic_Threat_D8F834A9 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "d8f834a9-41b7-4fc9-8100-87b9b07c0bc7"
		date = "2024-01-29"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2335-L2353"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c118c2064a5839ebd57a67a7be731fffe89669a8f17c1fe678432d4ff85e7929"
		logic_hash = "9fa1a65f3290867e4c59f14242f7261741e792b8be48c053ac320a315f2c1beb"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fcf7fc680c762ffd9293a84c9ac2ba34b18dc928417ebdabd6dfa998f96ed1f6"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 C4 F4 53 56 57 8B F9 8B F2 8B D8 33 D2 8A 55 08 0F AF 53 30 D1 FA 79 03 83 D2 00 03 53 30 8B 43 34 E8 62 48 04 00 89 45 FC 68 20 00 CC 00 8B 45 20 50 57 56 8B 45 FC 8B 10 FF 52 20 }

	condition:
		all of them
}