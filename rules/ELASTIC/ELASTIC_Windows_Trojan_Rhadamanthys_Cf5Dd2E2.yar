
rule ELASTIC_Windows_Trojan_Rhadamanthys_Cf5Dd2E2 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Rhadamanthys (Windows.Trojan.Rhadamanthys)"
		author = "Elastic Security"
		id = "cf5dd2e2-a505-4927-8653-3c9addd3ac90"
		date = "2024-04-03"
		modified = "2024-05-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Rhadamanthys.yar#L76-L97"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "39ccc224c2c6d89d0bce3d9e2c677465cbc7524f2d2aa903f79ad26b340dec3d"
		logic_hash = "039d6de0d072be6717ba3eb90735d7b4898d3bbac83db4feb75efcdbca8fd98b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3b2bdfd45a11649deb3430044c7b707aebcf74a3745398e3db09a7465fa62a6c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 33 D2 49 8B C4 49 83 C4 57 48 F7 F7 41 8A C2 46 0F B6 04 1A 33 D2 42 8D 4C 05 00 C1 E9 03 F6 E9 8A C8 49 8B C0 41 C0 E8 05 }
		$a2 = { 8A 04 19 32 03 88 04 1A 48 83 C3 01 48 83 EF 01 }
		$a3 = { 4C 01 27 48 8B 0F 48 8B 47 10 C6 04 01 00 48 83 07 01 48 8B 0F 48 8B 47 10 }
		$a4 = { 69 F6 93 01 00 01 0F B6 C0 48 83 C1 01 33 F0 8A 01 84 C0 }

	condition:
		2 of them
}