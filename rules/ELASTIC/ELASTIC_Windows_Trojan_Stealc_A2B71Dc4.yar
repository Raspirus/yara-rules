rule ELASTIC_Windows_Trojan_Stealc_A2B71Dc4 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Stealc (Windows.Trojan.Stealc)"
		author = "Elastic Security"
		id = "a2b71dc4-4041-4c1f-b546-a2b6947702d1"
		date = "2024-03-13"
		modified = "2024-03-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Stealc.yar#L29-L50"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0d1c07c84c54348db1637e21260dbed09bd6b7e675ef58e003d0fe8f017fd2c8"
		logic_hash = "b79ac3e65cd7d2819d6a49f59ec661241c97174f66a7c4ada91932f10fc43583"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9eeb13fededae39b8a531fa5d07eaf839b56a1c828ecd11322c604962e8b1aec"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$seq_1 = { 8B C6 C1 E8 02 33 C6 D1 E8 33 C6 C1 E8 02 33 C6 83 E0 01 A3 D4 35 61 00 C1 E0 0F 66 D1 E9 66 0B C8 }
		$seq_2 = { FF D3 8B 4D ?? E8 [4] 6A ?? 33 D2 5F 8B C8 F7 F7 85 D2 74 ?? }
		$seq_3 = { 33 D2 8B F8 59 F7 F1 8B C7 3B D3 76 04 2B C2 03 C1 }
		$seq_4 = { 6A 7C 58 66 89 45 FC 8D 45 F0 50 8D 45 FC 50 FF 75 08 C7 45 F8 01 }

	condition:
		2 of ($seq*)
}