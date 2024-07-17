rule ELASTIC_Macos_Trojan_Getshell_F339D74C : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Getshell (MacOS.Trojan.Getshell)"
		author = "Elastic Security"
		id = "f339d74c-36f1-46e5-bf7d-22f49a0948a5"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Getshell.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b2199c15500728a522c04320aee000938f7eb69d751a55d7e51a2806d8cd0fe7"
		logic_hash = "77a409f1a0ab5f87a77a6b2ffa2d4ff7bd6d86c0f685c524e2083585bb3fb764"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fad5ca4f345c2c01a3d222f59bac8d5dacf818d4e018c8d411d86266a481a1a1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 00 00 FF E0 E8 00 00 00 00 58 8B 80 4B 22 00 00 FF E0 55 89 E5 53 83 EC 04 E8 }

	condition:
		all of them
}