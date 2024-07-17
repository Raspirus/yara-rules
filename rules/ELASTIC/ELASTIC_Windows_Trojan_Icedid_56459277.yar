
rule ELASTIC_Windows_Trojan_Icedid_56459277 : FILE MEMORY
{
	meta:
		description = "IcedID Gzip Variant Core"
		author = "Elastic Security"
		id = "56459277-432c-437c-9350-f5efaa60ffca"
		date = "2022-08-21"
		modified = "2023-03-02"
		reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_IcedID.yar#L207-L237"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "21b1a635db2723266af4b46539f67253171399830102167c607c6dbf83d6d41c"
		logic_hash = "a18557217c69a3bb8c3da7725d2e0ed849741f8e36341a4ea80eea09d47a5b45"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "503bfa6800e0f4ff1a0b56eb8a145e67fa0f387c84aee7bd2eca3cf7074be709"
		threat_name = "Windows.Trojan.IcedID"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "cookie.tar" ascii fullword
		$str2 = "passff.tar" ascii fullword
		$str3 = "\\sqlite64.dll" ascii fullword
		$str4 = "Cookie: session=" ascii fullword
		$str5 = "{0ccac395-7d1d-4641-913a-7558812ddea2}" ascii fullword
		$str6 = "mail_vault" wide fullword
		$seq_decrypt_payload = { 42 0F B6 04 32 48 FF C2 03 C8 C1 C1 ?? 48 3B D7 72 ?? 44 33 F9 45 33 C9 44 89 3C 3B 48 85 FF 74 ?? 41 0F B6 D1 44 8D 42 01 83 E2 03 41 83 E0 03 }
		$seq_compute_hash = { 0F B6 4C 14 ?? 48 FF C2 8B C1 83 E1 ?? 48 C1 E8 ?? 41 0F B7 04 41 66 89 03 48 8D 5B ?? 41 0F B7 0C 49 66 89 4B ?? 48 83 FA ?? 72 ?? 66 44 89 03 B8 }
		$seq_format_string = { C1 E8 ?? 44 0B D8 41 0F B6 D0 8B C1 C1 E2 ?? C1 E1 ?? 25 [4] 0B C1 41 C1 E8 ?? 41 0F B6 CA 41 0B D0 44 8B 44 24 ?? C1 E0 ?? C1 E1 ?? 41 C1 EB ?? 44 0B D8 41 C1 EA ?? 0F B7 44 24 ?? 41 0B CA }
		$seq_custom_ror = { 41 8A C0 41 8A D0 02 C0 0F B6 C8 8A C1 44 8B C1 34 ?? 84 D2 0F B6 C8 44 0F 48 C1 49 83 EB }
		$seq_string_decrypt = { 0F B7 44 24 ?? 0F B7 4C 24 ?? 3B C1 7D ?? 8B 4C 24 ?? E8 [4] 89 44 24 ?? 0F B7 44 24 ?? 48 8B 4C 24 ?? 0F B6 04 01 0F B6 4C 24 ?? 33 C1 0F B7 4C 24 ?? 48 8B 54 24 ?? 88 04 0A EB }

	condition:
		5 of ($str*) or 2 of ($seq_*)
}