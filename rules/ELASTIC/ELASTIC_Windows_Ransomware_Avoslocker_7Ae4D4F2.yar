
rule ELASTIC_Windows_Ransomware_Avoslocker_7Ae4D4F2 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Avoslocker (Windows.Ransomware.Avoslocker)"
		author = "Elastic Security"
		id = "7ae4d4f2-be5f-4aad-baaa-4182ff9cf996"
		date = "2021-07-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Avoslocker.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "43b7a60c0ef8b4af001f45a0c57410b7374b1d75a6811e0dfc86e4d60f503856"
		logic_hash = "c87faf6f128fd6a8cabd68ec8de72fb10e6be42bdbe23ece374dd8f3cf0c1b15"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0e5ff268ed2b62f9d31df41192135145094849a4e6891407568c3ea27ebf66bb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "drive %s took %f seconds" ascii fullword
		$a2 = "client_rsa_priv: %s" ascii fullword
		$a3 = "drive: %s" ascii fullword
		$a4 = "Map: %s" ascii fullword
		$a5 = "encrypting %ls failed" wide fullword

	condition:
		all of them
}