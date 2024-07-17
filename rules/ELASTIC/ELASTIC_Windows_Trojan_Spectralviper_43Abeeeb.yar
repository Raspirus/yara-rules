rule ELASTIC_Windows_Trojan_Spectralviper_43Abeeeb : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Spectralviper (Windows.Trojan.SpectralViper)"
		author = "Elastic Security"
		id = "43abeeeb-d81a-475e-9b9e-6b6337bf2ce0"
		date = "2023-04-13"
		modified = "2023-05-26"
		reference = "https://www.elastic.co/security-labs/elastic-charms-spectralviper"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_SpectralViper.yar#L1-L27"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7e35ba39c2c77775b0394712f89679308d1a4577b6e5d0387835ac6c06e556cb"
		logic_hash = "976e5b5b4ba73f1b392c2f6b32a86b09b5fd9e5a3510c60b77a39f1e0d705822"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0e19e57e936d08f68c5580d21c2d69d451cfc11d413c6125dbdaab863b73d5c7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 13 00 8D 58 FF 0F AF D8 F6 C3 01 0F 94 44 24 26 83 FD 0A 0F 9C 44 24 27 4D 89 CE 4C 89 C7 48 89 D3 48 89 CE B8 }
		$a2 = { 15 00 8D 58 FF 0F AF D8 F6 C3 01 0F 94 44 24 2E 83 FD 0A 0F 9C 44 24 2F 4D 89 CE 4C 89 C7 48 89 D3 48 89 CE B8 }
		$a3 = { 00 8D 68 FF 0F AF E8 40 F6 C5 01 0F 94 44 24 2E 83 FA 0A 0F 9C 44 24 2F 4C 89 CE 4C 89 C7 48 89 CB B8 }
		$a4 = { 00 48 89 C6 0F 29 30 0F 29 70 10 0F 29 70 20 0F 29 70 30 0F 29 70 40 0F 29 70 50 48 C7 40 60 00 00 00 00 48 89 C1 E8 }
		$a5 = { 41 0F 45 C0 45 84 C9 41 0F 45 C0 EB BA 48 89 4C 24 08 89 D0 EB B1 48 8B 44 24 08 48 83 C4 10 C3 56 57 53 48 83 EC 30 8B 05 }
		$a6 = { 00 8D 70 FF 0F AF F0 40 F6 C6 01 0F 94 44 24 25 83 FF 0A 0F 9C 44 24 26 89 D3 48 89 CF 48 }
		$a7 = { 48 89 CE 48 89 11 4C 89 41 08 41 0F 10 01 41 0F 10 49 10 41 0F 10 51 20 0F 11 41 10 0F 11 49 20 0F 11 51 30 }
		$a8 = { 00 8D 58 FF 0F AF D8 F6 C3 01 0F 94 44 24 22 83 FD 0A 0F 9C 44 24 23 48 89 D6 48 89 CF 4C 8D }

	condition:
		5 of them
}