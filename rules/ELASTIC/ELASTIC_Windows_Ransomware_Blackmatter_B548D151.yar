
rule ELASTIC_Windows_Ransomware_Blackmatter_B548D151 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Blackmatter (Windows.Ransomware.Blackmatter)"
		author = "Elastic Security"
		id = "b548d151-5dde-459b-9d4a-b4a48c1b5545"
		date = "2021-08-03"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Blackmatter.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "072158f5588440e6c94cb419ae06a27cf584afe3b0cb09c28eff0b4662c15486"
		logic_hash = "cf76a311de9d292a2ea09b3937b8eb7fd761b7c33a464a31acf6b9a5bf121959"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "351658f8fe3f9c956634e3cf7a03b272c55359f069c5200e948d817c6b554c87"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 93 F0 DA 07 E7 F0 DA 07 E0 5B 99 65 47 38 96 6C 75 91 65 46 5A D0 B0 25 DA 90 42 CE F1 73 10 B1 14 BD 3C EC FD 7C AF 9B 8D 86 89 A5 FF C0 3F 78 57 8E E2 AD 2E 3A 2F 74 79 B1 FE 27 69 6B 9F 97 CE C8 67 88 1A 0B 01 F1 B7 76 35 18 E8 FF E1 D7 66 8C 41 03 EB F8 64 E5 7E F1 06 73 AB BF 6B 1D 6A B9 B6 BA 41 A2 91 49 5E 85 51 A0 83 23 46 D6 E0 E5 0F C2 53 89 2A 35 94 AF FC 87 A0 D8 08 E7 B8 DB 08 E7 78 22 E5 7E AE BB EF 16 87 08 3C 47 F0 49 1E 0D 2D 9A 1B 55 54 05 14 69 A3 1B 9C 7A 97 7B CF 85 2B 09 F9 DC 2C EB A6 55 F1 A0 07 B4 AA 80 EA ED 26 87 C0 }

	condition:
		any of them
}