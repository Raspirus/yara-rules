
rule ELASTIC_Windows_Ransomware_Akira_C8C298Ba : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Akira (Windows.Ransomware.Akira)"
		author = "Elastic Security"
		id = "c8c298ba-2760-4880-a54a-3d916049d0ab"
		date = "2024-05-02"
		modified = "2024-05-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Akira.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a2df5477cf924bd41241a3326060cc2f913aff2379858b148ddec455e4da67bc"
		logic_hash = "9058c83693e93f6daee8894453e56e0d9a4867d551ec3a6b66d7a517f65d8b07"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "81c6dfa172ce7f4254e3cc74fcb71786336d39438d6e9379f7611495f54227c9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "akira_readme.txt" ascii fullword
		$a2 = "Number of threads to encrypt = " ascii fullword
		$a3 = "write_encrypt_info error:" ascii fullword
		$a4 = "Log-%d-%m-%Y-%H-%M-%S" ascii fullword
		$a5 = "--encryption_path" wide fullword
		$a6 = "--encryption_percent" wide fullword

	condition:
		3 of them
}