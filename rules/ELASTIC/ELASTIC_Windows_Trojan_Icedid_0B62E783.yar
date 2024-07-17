rule ELASTIC_Windows_Trojan_Icedid_0B62E783 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Icedid (Windows.Trojan.IcedID)"
		author = "Elastic Security"
		id = "0b62e783-5c1a-4377-8338-1c53194b8d01"
		date = "2022-04-06"
		modified = "2022-06-09"
		reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_IcedID.yar#L123-L142"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
		logic_hash = "aca126529dfa8047ed7dfdc60d970759ab5307448d7d764f88e402cd8d2a016f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2f473fbe6338d9663808f1a3615cf8f0f6f9780fbce8f4a3c24f0ddc5f43dd4a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 89 44 95 E0 83 E0 07 8A C8 42 8B 44 85 E0 D3 C8 FF C0 42 89 44 }

	condition:
		all of them
}