
rule ELASTIC_Windows_Trojan_Icedid_A2Ca5F80 : FILE MEMORY
{
	meta:
		description = "IcedID Injector Variant Core"
		author = "Elastic Security"
		id = "a2ca5f80-85b1-4502-8794-b8b4ea1be482"
		date = "2023-01-16"
		modified = "2023-04-23"
		reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_IcedID.yar#L296-L323"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "e36266cd66b9542f2eb9d38f9a01f7b480f2bcdbe61fe20944dca33e22bd3281"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dfbacf63b91315e5acf168b57bf18283ba30f681f5b3d3835418d0d32d238854"
		threat_name = "Windows.Trojan.Icedid"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "EMPTY"
		$a2 = "CLEAR"
		$a3 = { 66 C7 06 6D 3D 83 C6 02 0F B6 05 [4] 50 68 34 73 00 10 56 FF D7 03 F0 66 C7 06 26 6A C6 46 ?? 3D 83 C6 03 }
		$a4 = { 8B 46 ?? 6A 00 FF 76 ?? F7 D8 FF 76 ?? 1B C0 FF 76 ?? 50 FF 76 ?? 53 FF 15 }
		$a5 = { 8D 44 24 ?? 89 7C 24 ?? 89 44 24 ?? 33 F6 B8 BB 01 00 00 46 55 66 89 44 24 ?? 89 74 24 ?? E8 [4] 89 44 24 ?? 85 C0 74 ?? 8B AC 24 }
		$a6 = { 8A 01 88 45 ?? 45 41 83 EE 01 75 ?? 8B B4 24 [4] 8B 7E }
		$a7 = { 53 E8 [4] 8B D8 30 1C 2F 45 59 3B EE 72 }
		$a8 = { 8B 1D [4] 33 D9 6A 00 53 52 E8 [4] 83 C4 0C 89 44 24 ?? 85 C0 0F 84 }
		$a9 = { C1 C9 0D 0F BE C0 03 C8 46 8A 06 }

	condition:
		4 of them
}