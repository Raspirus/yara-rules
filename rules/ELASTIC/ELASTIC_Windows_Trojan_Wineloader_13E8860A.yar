
rule ELASTIC_Windows_Trojan_Wineloader_13E8860A : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Wineloader (Windows.Trojan.WineLoader)"
		author = "Elastic Security"
		id = "13e8860a-9d83-4ae6-b07e-20bb4037010c"
		date = "2024-03-24"
		modified = "2024-05-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_WineLoader.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f5cb3234eff0dbbd653d5cdce1d4b1026fa9574ebeaf16aaae3d4e921b6a7f9d"
		logic_hash = "c072abb73377ed59c0dd9fab25a4c84575ab9badbddfda1ed51e576e4e12fa82"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d21c6d97360deea724b94b8f65116f00c11625c5deb1bac0790a23ede6eaaac6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 48 8B 1E 48 89 F1 E8 ?? ?? 00 00 48 8B 56 08 48 89 F9 49 89 D8 E8 ?? ?? FF FF 48 89 F1 E8 ?? 5C 00 00 90 48 81 C4 ?? 00 00 00 5B 5D 5F 5E 41 5C 41 5E 41 5F C3 C3 41 57 41 56 41 55 41 54 56 57 }
		$a2 = { 85 C0 0F 84 ?? 03 00 00 4C 8D A4 24 BC 00 00 00 41 C7 04 24 04 00 00 00 B8 0F 00 00 00 48 8D 7C 24 70 48 89 47 F8 48 B8 }
		$a3 = { 48 85 DB 0F 84 B3 00 00 00 83 BC 24 80 01 00 00 00 0F 84 5A 01 00 00 4C 8D 74 24 50 49 C7 46 F8 0D 00 00 00 48 B8 }

	condition:
		any of them
}