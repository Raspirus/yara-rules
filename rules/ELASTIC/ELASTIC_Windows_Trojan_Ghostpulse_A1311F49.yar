rule ELASTIC_Windows_Trojan_Ghostpulse_A1311F49 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Ghostpulse (Windows.Trojan.GhostPulse)"
		author = "Elastic Security"
		id = "a1311f49-65a7-4136-a5ab-28cf4de4d40f"
		date = "2023-10-06"
		modified = "2023-10-26"
		reference = "https://www.elastic.co/security-labs/ghostpulse-haunts-victims-using-defense-evasion-bag-o-tricks"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_GhostPulse.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0175448655e593aa299278d5f11b81f2af76638859e104975bdb5d30af5c0c11"
		logic_hash = "21838f230ac1a77f09d01d30f4ea3b66313618660e63ab7012b030e0b819547e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e07a8152ab75624aa8dd0a8301d690a6a4bdd3b0e069699632541fb6a32e419b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 0F BE 00 48 0F BE C0 85 C0 74 0D B8 01 00 00 00 03 45 00 89 45 00 EB E1 8B 45 00 48 8D 65 10 5D C3 }
		$a2 = { 88 4C 24 08 48 83 EC 18 0F B6 44 24 20 88 04 24 0F BE 44 24 20 83 F8 41 7C 13 0F BE 04 24 83 F8 5A 7F 0A 0F BE 04 24 83 C0 20 88 04 24 }

	condition:
		any of them
}