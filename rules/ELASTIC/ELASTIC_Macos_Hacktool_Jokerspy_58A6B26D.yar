rule ELASTIC_Macos_Hacktool_Jokerspy_58A6B26D : FILE MEMORY
{
	meta:
		description = "Detects Macos Hacktool Jokerspy (Macos.Hacktool.JokerSpy)"
		author = "Elastic Security"
		id = "58a6b26d-13dd-485a-bac3-77a1053c3a02"
		date = "2023-06-19"
		modified = "2023-06-19"
		reference = "https://www.elastic.co/security-labs/inital-research-of-jokerspy"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Macos_Hacktool_JokerSpy.yar#L1-L25"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d895075057e491b34b0f8c0392b44e43ade425d19eaaacea6ef8c5c9bd3487d8"
		logic_hash = "e9e1333c7172d5a0f06093a902edefd7f128963dbaadf77e829f032ccb04ce56"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "71423d5c4c917917281b7e0f644142a0570df7a5a7ea568506753cb6eabef1c0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$str1 = "ScreenRecording: NO" fullword
		$str2 = "Accessibility: NO" fullword
		$str3 = "Accessibility: YES" fullword
		$str4 = "eck13XProtectCheck"
		$str5 = "Accessibility: NO" fullword
		$str6 = "kMDItemDisplayName = *TCC.db" fullword

	condition:
		5 of them
}