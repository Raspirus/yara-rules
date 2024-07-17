rule ELASTIC_Windows_Ransomware_Crytox_29859242 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Crytox (Windows.Ransomware.Crytox)"
		author = "Elastic Security"
		id = "29859242-adf4-4d17-afdf-dbc02f5b787b"
		date = "2024-01-18"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Crytox.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "55a27cb6280f31c077987d338151b13e9dc0cc1c14d47a32e64de6d6c1a6a742"
		logic_hash = "47ca96e14b2b56bc6ef1ed22b42adac7aa557170632c2dc085fae3baf6198f40"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "999713c1815d61904f13f7f9cbaf34b116f53af223b2aac20bf0d88af107dbae"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 48 83 C7 20 D7 C1 C8 08 D7 C1 C8 08 D7 C1 C8 08 D7 C1 C8 10 33 C2 33 47 E0 D0 E2 }

	condition:
		all of them
}