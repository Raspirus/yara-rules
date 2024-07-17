
rule ELASTIC_Linux_Trojan_Xzbackdoor_74E87A9D : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xzbackdoor (Linux.Trojan.XZBackdoor)"
		author = "Elastic Security"
		id = "74e87a9d-11c1-4e86-bb3c-63a3c51c50df"
		date = "2024-03-30"
		modified = "2024-04-03"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_XZBackdoor.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5448850cdc3a7ae41ff53b433c2adbd0ff492515012412ee63a40d2685db3049"
		logic_hash = "c777171c36d9369ade7bf44c7cc4e5aee16bb4c803431bc480cc0f8ebb2819c0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6ec0ee53f66167f7f2bbe5420aa474681701ed8f889aaad99e3990ecc4fb6716"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "yolAbejyiejuvnup=Evjtgvsh5okmkAvj"
		$a2 = { 0A 31 FD 3B 2F 1F C6 92 92 68 32 52 C8 C1 AC 28 34 D1 F2 C9 75 C4 76 5E B1 F6 88 58 88 93 3E 48 10 0C B0 6C 3A BE 14 EE 89 55 D2 45 00 C7 7F 6E 20 D3 2C 60 2B 2C 6D 31 00 }
		$b1 = { 48 8D 7C 24 08 F3 AB 48 8D 44 24 08 48 89 D1 4C 89 C7 48 89 C2 E8 ?? ?? ?? ?? 89 C2 }
		$b2 = { 31 C0 49 89 FF B9 16 00 00 00 4D 89 C5 48 8D 7C 24 48 4D 89 CE F3 AB 48 8D 44 24 48 }
		$b3 = { 4D 8B 6C 24 08 45 8B 3C 24 4C 8B 63 10 89 85 78 F1 FF FF 31 C0 83 BD 78 F1 FF FF 00 F3 AB 79 07 }

	condition:
		1 of ($a*) or all of ($b*)
}