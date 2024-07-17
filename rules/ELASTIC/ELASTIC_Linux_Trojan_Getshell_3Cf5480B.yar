
rule ELASTIC_Linux_Trojan_Getshell_3Cf5480B : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Getshell (Linux.Trojan.Getshell)"
		author = "Elastic Security"
		id = "3cf5480b-bb21-4a6e-a078-4b145d22c79f"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "0e41c0d6286fb7cd3288892286548eaebf67c16f1a50a69924f39127eb73ff38"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Getshell.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "87b0db74e81d4f236b11f51a72fba2e4263c988402292b2182d19293858c6126"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3ef0817445c54994d5a6792ec0e6c93f8a51689030b368eb482f5ffab4761dd2"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { B2 24 B0 03 CD 80 85 C0 78 02 FF E1 B8 01 00 00 00 BB 01 00 }

	condition:
		all of them
}