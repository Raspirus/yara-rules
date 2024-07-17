rule ELASTIC_Linux_Generic_Threat_80Aea077 : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "80aea077-c94f-4c95-83a5-967cc16df2a8"
		date = "2024-01-17"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L42-L60"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "002827c41bc93772cd2832bc08dfc413302b1a29008adbb6822343861b9818f0"
		logic_hash = "cab860ad5f0c49555adb845504acb4dbeabb94dbc287202be35020e055e6f27b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "702953af345afb999691906807066d58b9ec055d814fc6fe351e59ac5193e31f"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 38 49 89 FE 0F B6 0E 48 C1 E1 18 0F B6 6E 01 48 C1 E5 10 48 09 E9 0F B6 6E 03 48 09 E9 0F B6 6E 02 48 C1 E5 08 48 09 CD 0F B6 56 04 48 C1 E2 18 44 0F B6 7E 05 49 C1 E7 10 4C 09 FA 44 }

	condition:
		all of them
}