
rule ELASTIC_Windows_Trojan_Pikabot_5441F511 : FILE MEMORY
{
	meta:
		description = "Related to Pikabot core"
		author = "Elastic Security"
		id = "5441f511-82f2-4971-b9ff-7fe739041357"
		date = "2024-02-15"
		modified = "2024-02-21"
		reference = "https://www.elastic.co/security-labs/pikabot-i-choose-you"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_PikaBot.yar#L54-L78"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "fa44408874c6a007212dfc206cbecbac7a3e50df94da4ce02de2e04e9119c79f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7a90c7e21ebffd6276bd53e37d4a09df29d3d1167024b96a39504518f0a38dfe"
		threat_name = "Windows.Trojan.PikaBot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$handler_table = { 72 26 [6] 6F 24 [6] CB 0A [6] 6C 03 [6] 92 07 }
		$api_hashing = { 3C 60 76 ?? 83 E8 20 8B 0D ?? ?? ?? ?? 6B FF 21 }
		$debug_check = { A1 ?? ?? ?? ?? FF 50 ?? 50 50 80 7E ?? 01 74 ?? 83 7D ?? 00 75 ?? }
		$checksum = { 55 89 E5 8B 55 08 69 02 E1 10 00 00 05 38 15 00 00 89 02 5D C3 }
		$load_sycall = { 8F 05 ?? ?? ?? ?? 83 C0 04 50 8F 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 A3 ?? ?? ?? ?? 31 C0 64 8B 0D C0 00 00 00 85 C9 }
		$read_xbyte_config = { 8B 43 04 8B 55 F4 B9 FC FF FF FF 83 C0 04 29 D1 01 4B 0C 8D 0C 10 89 4B 04 85 F6 ?? ?? 89 16 89 C3 }

	condition:
		2 of them
}