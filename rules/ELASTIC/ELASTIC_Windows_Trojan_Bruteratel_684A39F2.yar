rule ELASTIC_Windows_Trojan_Bruteratel_684A39F2 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Bruteratel (Windows.Trojan.BruteRatel)"
		author = "Elastic Security"
		id = "684a39f2-a110-4553-8d29-9f742e0ca3dc"
		date = "2023-01-24"
		modified = "2023-02-01"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_BruteRatel.yar#L59-L84"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5f4782a34368bb661f413f33e2d1fb9f237b7f9637f2c0c21dc752316b02350c"
		logic_hash = "7cb74176e1dbdd248295649568d29c9d88841fcd0c16479b6b7efc71c4a1d706"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fef288db141810b01f248a476368946c478a395b1709a982e2f740dd011c6328"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$seq1 = { 39 DA 0F 82 61 02 00 00 45 8D 48 14 44 39 CA 0F 82 54 02 00 00 41 8D 40 07 46 0F B6 0C 09 44 0F B6 1C 01 42 0F B6 04 11 41 C1 E3 08 41 09 C3 }
		$seq2 = { 45 8A 44 13 F0 44 32 04 01 48 FF C0 45 88 04 13 48 FF C2 48 83 F8 04 75 E7 49 83 C2 04 48 83 C6 04 49 81 FA B0 00 00 00 75 AA 48 83 C4 38 5B 5E C3 }
		$seq3 = { 48 83 EC 18 8A 01 88 04 24 8A 41 05 88 44 24 01 8A 41 0A 88 44 24 02 8A 41 0F 88 44 24 03 8A 41 04 88 44 24 04 8A 41 09 88 44 24 05 8A 41 0E 88 44 24 06 8A 41 03 88 44 24 07 }
		$seq4 = { 42 8A 0C 22 8D 42 ?? 80 F9 ?? 75 ?? 48 98 4C 89 E9 48 29 C1 42 8A 14 20 80 FA ?? 74 ?? 88 14 01 48 FF C0 EB ?? }
		$cfg1 = { 22 00 2C 00 22 00 61 00 72 00 63 00 68 00 22 00 3A 00 22 00 78 00 36 00 34 00 22 00 2C 00 22 00 62 00 6C 00 64 00 22 00 3A 00 22 00 }
		$cfg2 = { 22 00 2C 00 22 00 77 00 76 00 65 00 72 00 22 00 3A 00 22 00 }
		$cfg3 = { 22 00 2C 00 22 00 70 00 69 00 64 00 22 00 3A 00 22 00 }
		$cfg4 = { 22 00 7D 00 2C 00 22 00 6D 00 74 00 64 00 74 00 22 00 3A 00 7B 00 22 00 68 00 5F 00 6E 00 61 00 6D 00 65 00 22 00 3A 00 22 00 }

	condition:
		any of ($seq*) and all of ($cfg*)
}