rule ELASTIC_Linux_Trojan_Kinsing_2C1Ffe78 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Kinsing (Linux.Trojan.Kinsing)"
		author = "Elastic Security"
		id = "2c1ffe78-a965-4a70-8a9c-2cad705f8be7"
		date = "2021-12-13"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Kinsing.yar#L40-L58"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b3527e3d03a30fcf1fdaa73a1b3743866da6db088fbfa5f51964f519e22d05e6"
		logic_hash = "9561511710eef5877c5afa49890b77fbad31a6e312b5cd33fc01f91ff2a73583"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "6701b007ee14a022525301d53af0f4254bc26fdfbe27d3d5cebc2d40e8536ed6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 73 74 73 20 22 24 42 49 4E 5F 46 55 4C 4C 5F 50 41 54 48 22 20 22 }

	condition:
		all of them
}