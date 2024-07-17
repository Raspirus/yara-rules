rule ELASTIC_Windows_Ransomware_Rook_Ee21Fa67 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Rook (Windows.Ransomware.Rook)"
		author = "Elastic Security"
		id = "ee21fa67-bd82-40fb-9c6d-bab5abfe14b3"
		date = "2022-01-14"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Rook.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c2d46d256b8f9490c9599eea11ecef19fde7d4fdd2dea93604cee3cea8e172ac"
		logic_hash = "6fe19cfc572a3dceba5e26615d111a3c0fa1036e275a5640a5c5a8f8cdaf6dc1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8ef731590e73f79a13d04db39e58b03d0a29fd8e46a0584b0fcaf57ac0efe473"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 01 75 09 8B C3 FF C3 48 89 74 C5 F0 48 FF C7 48 83 FF 1A 7C DB }

	condition:
		all of them
}