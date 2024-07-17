rule ELASTIC_Windows_Trojan_Suddenicon_99487621 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Suddenicon (Windows.Trojan.SuddenIcon)"
		author = "Elastic Security"
		id = "99487621-88c4-40f6-918a-f1276cc2d2a7"
		date = "2023-03-29"
		modified = "2023-03-30"
		reference = "https://www.elastic.co/security-labs/elastic-users-protected-from-suddenicon-supply-chain-attack"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_SuddenIcon.yar#L1-L26"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "aa4e398b3bd8645016d8090ffc77d15f926a8e69258642191deb4e68688ff973"
		logic_hash = "9a441c47e8b95d8aaec6f495d6ddfec2ed6b0762637ea48e64c9ea01b0945019"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b16f7de530ed27c42bffec4bcfc1232bad34cdaf4e7a9803fce0564e12701ef1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "https://raw.githubusercontent.com/IconStorages/images/main/icon%d.ico" wide fullword
		$str2 = "__tutma" ascii fullword
		$str3 = "__tutmc" ascii fullword
		$str4 = "%s: %s" ascii fullword
		$str5 = "%s=%s" ascii fullword
		$seq_obf = { C1 E1 ?? 33 C1 45 8B CA 8B C8 C1 E9 ?? 33 C1 81 C2 ?? ?? ?? ?? 8B C8 C1 E1 ?? 33 C1 41 8B C8 }
		$seq_virtualprotect = { FF 15 ?? ?? ?? ?? 85 C0 74 ?? FF D5 48 85 C0 74 ?? 81 7B ?? CA 7D 0F 00 75 ?? 48 8D 54 24 ?? 48 8D 4C 24 ?? FF D0 8B F8 44 8B 44 24 ?? 4C 8D 4C 24 ?? BA 00 10 00 00 48 8B CD FF 15 ?? ?? ?? ?? }

	condition:
		5 of ($str*) or 2 of ($seq*)
}