
rule ELASTIC_Windows_Trojan_Ghostengine_8Ea2Aa65 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Ghostengine (Windows.Trojan.GhostEngine)"
		author = "Elastic Security"
		id = "8ea2aa65-d7e2-4c58-9f95-3194cd8b6990"
		date = "2024-05-07"
		modified = "2024-05-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_GhostEngine.yar#L1-L26"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2fe78941d74d35f721556697491a438bf3573094d7ac091b42e4f59ecbd25753"
		logic_hash = "3bddd2ac79d92d34df5d2df4a11cf96cc44ca39c3baece1b5c67b75a682778ff"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "17c4c2fa2d412b79ee197de1e6bd6a4c882ad894be54a780e540627a570756e5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str0 = "\\\\.\\IOBitUnlockerDevice"
		$str1 = "C:\\Windows\\Fonts\\taskhostw.exe"
		$str2 = "C:\\Windows\\Fonts\\config.json"
		$str3 = "/drives/kill.png"
		$str4 = "C:\\Windows\\Fonts\\WinRing0x64.sys"
		$str5 = "C:\\Windows\\Fonts\\smartsscreen.exe"
		$binary0 = { 89 C2 C1 E8 1F C1 E0 1F 85 C0 0F 84 74 01 00 00 D1 E2 89 CB C1 E9 1F 09 D1 D1 E3 C1 EB 1F 89 CA D1 E1 09 D9 89 CB 81 C1 80 7F B1 D7 C1 EA 1F 81 C3 80 7F B1 D7 83 D2 0D 81 C1 00 09 6E 88 89 4C 24 20 83 D2 F1 89 54 24 24 }
		$binary1 = { 83 F9 06 0F ?? ?? ?? ?? ?? 8B 10 81 FA 78 38 36 5F 0F 85 ?? ?? ?? ?? 0F B7 50 04 66 81 FA 36 34 74 ?? E9 ?? ?? 00 00 C7 04 24 00 E4 0B 54 C7 44 24 04 02 00 00 00 }

	condition:
		3 of ($str*) or 1 of ($binary*)
}