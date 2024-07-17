
rule ELASTIC_Windows_Trojan_Pikabot_5B220E9C : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Pikabot (Windows.Trojan.PikaBot)"
		author = "Elastic Security"
		id = "5b220e9c-3232-4a86-82b7-31f96c95242c"
		date = "2024-02-06"
		modified = "2024-02-08"
		reference = "https://www.elastic.co/security-labs/pikabot-i-choose-you"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_PikaBot.yar#L27-L52"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d836b06b0118e6d258e318b1cfdc509cacc0859c6a6b3d7c5f4d2525e00d97b2"
		logic_hash = "1d2158716b7c32734f12f8528352a3872e21fea2f9b21a36d6ac44fcd50a9f3c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3a7ba8156f9ad017cdb8630770bf900c198215306a125f6f7dcd845f2c683948"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$byte_seq0 = { 03 44 95 ?? 42 83 FA ?? 7C ?? EB ?? }
		$byte_seq1 = { 3B C1 73 ?? 80 3C 18 ?? 75 ?? C6 04 18 ?? 40 EB ?? }
		$byte_seq2 = { 03 C7 03 C8 0F B6 F9 8A 84 3D 34 FD FF FF 88 84 35 34 FD FF FF }
		$byte_seq3 = { 55 8B EC 83 EC 0C 33 C0 C7 45 F4 05 00 00 00 C7 45 F8 32 00 00 00 8B D0 C7 45 FC C9 FF FF FF }
		$byte_seq4 = { 55 8B EC 51 51 53 56 89 55 F8 89 4D FC 8B 75 FC 8B 45 F8 33 C9 0F A2 89 06 89 5E 04 89 4E 08 89 }
		$byte_seq5 = { 8D 5D E8 59 33 D2 C7 45 F8 04 00 00 00 8A 03 8D 0C 16 43 88 04 39 83 6D F8 01 8D 52 04 75 EE 46 }
		$byte_seq6 = { 55 8B EC 51 51 53 56 89 55 F8 89 4D FC 8B 75 FC 8B 45 F8 33 C9 0F A2 89 06 89 5E 04 89 4E 08 89 }

	condition:
		2 of them
}